package com.deeppacket.engine;

import com.deeppacket.dpi.DNSExtractor;
import com.deeppacket.dpi.HTTPHostExtractor;
import com.deeppacket.dpi.QUICSNIExtractor;
import com.deeppacket.dpi.SNIExtractor;
import com.deeppacket.dpi.TLSFingerprint;
import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.ConnectionState;
import com.deeppacket.model.NetUtil;
import com.deeppacket.model.PacketAction;
import com.deeppacket.model.PacketJob;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

public class FastPathProcessor {
    public record FPStats(long packetsProcessed, long packetsForwarded, long packetsDropped,
                          long connectionsTracked, long sniExtractions, long classificationHits) {}

    private static final int MAX_TLS_RECORD_BYTES = 16 * 1024 + 5;
    /** Initial datagrams examined per flow; clients normally send two or three before the server answers. */
    private static final int MAX_QUIC_ATTEMPTS = 6;

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final DnsCache dnsCache;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;
    private final boolean verbose;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    private final AtomicLong processed = new AtomicLong();
    private final AtomicLong forwarded = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();

    public FastPathProcessor(int fpId, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback,
                             boolean verbose, DnsCache dnsCache) {
        this.fpId = fpId;
        this.dnsCache = dnsCache;
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
        this.verbose = verbose;
        this.connTracker = new ConnectionTracker(fpId, 100_000);
    }

    public void start() {
        if (running.getAndSet(true)) return;
        thread = new Thread(this::run, "fp-" + fpId);
        thread.start();
    }

    public void stop() {
        if (!running.getAndSet(false)) return;
        inputQueue.shutdown();
        if (thread != null) {
            try { thread.join(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public FPStats getStats() {
        return new FPStats(processed.get(), forwarded.get(), dropped.get(), connTracker.getActiveCount(),
            sniExtractions.get(), classificationHits.get());
    }

    private void run() {
        while (running.get() || !inputQueue.empty()) {
            PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) {
                connTracker.cleanupStale(300_000_000_000L);
                continue;
            }
            processed.incrementAndGet();
            PacketAction action = processPacket(job);
            outputCallback.accept(job, action);
            if (action == PacketAction.DROP) dropped.incrementAndGet();
            else forwarded.incrementAndGet();
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn.state == ConnectionState.CLOSED && isInitialSyn(job)) {
            // The 5-tuple is being reused for a new TCP connection: keep the old flow for reporting.
            connTracker.retire(conn);
            conn = connTracker.getOrCreateConnection(job.tuple);
        }
        connTracker.updateConnection(conn, job.data.length, conn.isOutbound(job.tuple));
        if (job.tuple.protocol == 6) updateTcpState(conn, job.tcpFlags);
        if (conn.state == ConnectionState.BLOCKED) return PacketAction.DROP;
        // DNS answers are learned from every response, even when the flow was already classified by its query.
        if (job.tuple.protocol == 17 && job.tuple.srcPort == 53 && job.payloadLength > 0) observeDnsAnswer(job);
        if (job.payloadLength > 0 && shouldInspectFurther(conn)) inspectPayload(job, conn);
        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength <= 0 || job.payloadOffset >= job.data.length) return;
        byte[] payload = new byte[job.payloadLength];
        System.arraycopy(job.data, job.payloadOffset, payload, 0, job.payloadLength);

        if (tryExtractSni(job, conn, payload)) return;
        if (tryExtractQuic(job, conn, payload)) return;
        if (tryExtractHttpHost(job, conn, payload)) return;
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            DNSExtractor.extractQuery(payload, payload.length).ifPresent(domain ->
                connTracker.classifyConnection(conn, AppType.DNS, domain, "DNS query"));
            return;
        }
        // Keep port-based classification provisional so later packets can still
        // upgrade to concrete app classification from SNI/Host.
        if (job.tuple.dstPort == 80 && conn.appType == AppType.UNKNOWN) {
            conn.appType = AppType.HTTP;
            conn.classifiedBy = "port";
        } else if (job.tuple.dstPort == 443 && conn.appType == AppType.UNKNOWN) {
            conn.appType = AppType.HTTPS;
            conn.classifiedBy = "port";
        }
    }

    private boolean tryExtractSni(PacketJob job, Connection conn, byte[] payload) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) return false;
        var sni = extractSni(job, conn, payload);
        if (sni.isEmpty()) return false;
        sniExtractions.incrementAndGet();
        AppType app = AppType.fromSni(sni.get());
        connTracker.classifyConnection(conn, app, sni.get(), "TLS SNI");
        if (app != AppType.UNKNOWN && app != AppType.HTTPS) classificationHits.incrementAndGet();
        return true;
    }

    /**
     * Extracts the SNI from a single segment, or - for the client's first TLS record on a TCP flow -
     * from a ClientHello that is split across several in-order segments (common with large
     * post-quantum key shares). Out-of-order and retransmitted segments are ignored.
     */
    private Optional<String> extractSni(PacketJob job, Connection conn, byte[] payload) {
        // Fingerprint the hello even when it carries no SNI, so such flows can still be identified and blocked.
        if (conn.ja3.isEmpty() && SNIExtractor.isTlsClientHello(payload, payload.length)) {
            fingerprint(conn, payload, payload.length);
        }
        var direct = SNIExtractor.extract(payload, payload.length);
        if (direct.isPresent() || job.tuple.protocol != 6 || !conn.isOutbound(job.tuple)) return direct;

        if (conn.tlsBuffer == null) {
            if (payload.length < 5 || (payload[0] & 0xFF) != 0x16 || (payload[1] & 0xFF) != 0x03) {
                return Optional.empty();
            }
            int recordLength = ((payload[3] & 0xFF) << 8) | (payload[4] & 0xFF);
            int needed = 5 + recordLength;
            if (needed <= payload.length || needed > MAX_TLS_RECORD_BYTES) return Optional.empty();
            if (!connTracker.tryReserveReassembly(needed)) return Optional.empty();
            conn.tlsBuffer = new byte[needed];
            conn.tlsFilled = 0;
            conn.tlsNextSeq = job.seq;
        }
        if (job.seq != conn.tlsNextSeq) return Optional.empty();

        int n = Math.min(payload.length, conn.tlsBuffer.length - conn.tlsFilled);
        System.arraycopy(payload, 0, conn.tlsBuffer, conn.tlsFilled, n);
        conn.tlsFilled += n;
        conn.tlsNextSeq = (job.seq + payload.length) & 0xFFFFFFFFL;
        if (conn.tlsFilled < conn.tlsBuffer.length) return Optional.empty();

        var sni = SNIExtractor.extract(conn.tlsBuffer, conn.tlsFilled);
        if (conn.ja3.isEmpty()) fingerprint(conn, conn.tlsBuffer, conn.tlsFilled);
        connTracker.releaseReassemblyBuffer(conn);
        return sni;
    }

    private static void fingerprint(Connection conn, byte[] record, int length) {
        TLSFingerprint.fromClientHello(record, length).ifPresent(result -> {
            conn.ja3 = result.ja3();
            conn.tlsVersion = result.tlsVersion();
        });
    }

    /**
     * Reads the SNI from QUIC Initial packets (v1 and v2). A ClientHello that is split over several Initial
     * datagrams is reassembled from the CRYPTO fragments, within the same per-worker memory budget as TLS.
     */
    private boolean tryExtractQuic(PacketJob job, Connection conn, byte[] payload) {
        if (job.tuple.protocol != 17 || conn.quicAttempts >= MAX_QUIC_ATTEMPTS) return false;
        if (!QUICSNIExtractor.isQuicInitial(payload, payload.length)) return false;
        conn.quicAttempts++;
        var decrypted = QUICSNIExtractor.decrypt(payload, payload.length);
        if (decrypted.isEmpty()) return false;

        Optional<String> sni = Optional.empty();
        for (var fragment : decrypted.get()) {
            byte[] data = fragment.data();
            if (conn.quicCrypto == null) {
                if (fragment.offset() != 0) continue; // cannot size the message until its start arrives
                int announced = QUICSNIExtractor.announcedLength(data, data.length);
                if (announced < 0 || announced > QUICSNIExtractor.MAX_CLIENT_HELLO) continue;
                if (data.length >= announced) { // the whole ClientHello is in this one packet
                    sni = QUICSNIExtractor.sniFromHandshake(data, announced);
                    if (sni.isPresent()) break;
                    continue;
                }
                if (!connTracker.tryReserveReassembly(announced)) continue;
                conn.quicCrypto = new com.deeppacket.model.ReassemblyBuffer(announced);
            }
            conn.quicCrypto.add(fragment.offset(), data, 0, data.length);
        }
        if (sni.isEmpty() && conn.quicCrypto != null) {
            int have = conn.quicCrypto.contiguousLength();
            sni = QUICSNIExtractor.sniFromHandshake(conn.quicCrypto.contiguousBytes(), have);
            if (sni.isPresent() || have >= conn.quicCrypto.capacity()) connTracker.releaseReassemblyBuffer(conn);
        } else if (conn.quicCrypto != null) {
            connTracker.releaseReassemblyBuffer(conn);
        }
        if (sni.isEmpty()) return false;

        AppType app = AppType.fromSni(sni.get());
        if (app == AppType.HTTPS) app = AppType.QUIC; // QUIC to a service we have no signature for
        connTracker.classifyConnection(conn, app, sni.get(), "QUIC Initial");
        if (app != AppType.UNKNOWN && app != AppType.QUIC) classificationHits.incrementAndGet();
        return true;
    }

    private void observeDnsAnswer(PacketJob job) {
        if (job.payloadOffset + job.payloadLength > job.data.length) return;
        byte[] payload = new byte[job.payloadLength];
        System.arraycopy(job.data, job.payloadOffset, payload, 0, job.payloadLength);
        DNSExtractor.extractAnswer(payload, payload.length).ifPresent(answer -> {
            long timestamp = Integer.toUnsignedLong(job.tsSec) * 1_000_000L + Integer.toUnsignedLong(job.tsUsec);
            for (int address : answer.addresses()) {
                // Answers are in network order; flows (and the cache keys used to look them up) use NetUtil's encoding.
                dnsCache.observe(NetUtil.fromNetworkOrder(address), answer.name(), timestamp);
            }
        });
    }

    private static boolean isInitialSyn(PacketJob job) {
        return job.tuple.protocol == 6 && (job.tcpFlags & 0x12) == 0x02;
    }

    private boolean tryExtractHttpHost(PacketJob job, Connection conn, byte[] payload) {
        if (job.tuple.dstPort != 80) return false;
        var host = HTTPHostExtractor.extract(payload, payload.length);
        if (host.isEmpty()) return false;
        AppType app = AppType.fromSni(host.get());
        // Plain HTTP to a host we have no signature for is still HTTP, not HTTPS.
        if (app == AppType.HTTPS) app = AppType.HTTP;
        connTracker.classifyConnection(conn, app, host.get(), "HTTP Host");
        if (app != AppType.UNKNOWN && app != AppType.HTTP) classificationHits.incrementAndGet();
        return true;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        var reason = ruleManager.shouldBlock(job.tuple.srcIp, job.tuple.dstIp, job.tuple.dstPort, conn.appType, conn.sni, conn.ja3);
        if (reason.isPresent()) {
            if (verbose) {
                var why = reason.get();
                String detail = switch (why.type) {
                    case IP -> "IP " + why.detail;
                    case APP -> "App " + why.detail;
                    case DOMAIN -> "Domain " + why.detail;
                    case PORT -> "Port " + why.detail;
                    case JA3 -> "JA3 " + why.detail;
                };
                System.out.println("[FP" + fpId + "] BLOCKED packet: " + detail);
            }
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }
        return PacketAction.FORWARD;
    }

    private static void updateTcpState(Connection conn, int flags) {
        if ((flags & 0x02) != 0) {
            if ((flags & 0x10) != 0) conn.synAckSeen = true;
            else conn.synSeen = true;
        }
        if (conn.synSeen && conn.synAckSeen && (flags & 0x10) != 0 && conn.state == ConnectionState.NEW) {
            conn.state = ConnectionState.ESTABLISHED;
        }
        if ((flags & 0x01) != 0) conn.finSeen = true;
        if ((flags & 0x04) != 0 || (conn.finSeen && (flags & 0x10) != 0)) conn.state = ConnectionState.CLOSED;
    }

    private static boolean shouldInspectFurther(Connection conn) {
        if (conn.sni == null || conn.sni.isEmpty()) {
            return conn.appType == AppType.UNKNOWN ||
                   conn.appType == AppType.HTTPS ||
                   conn.appType == AppType.HTTP;
        }
        return conn.appType == AppType.UNKNOWN ||
               conn.appType == AppType.HTTPS ||
               conn.appType == AppType.HTTP;
    }
}
