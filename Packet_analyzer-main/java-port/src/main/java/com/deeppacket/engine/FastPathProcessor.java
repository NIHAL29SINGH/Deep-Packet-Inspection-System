package com.deeppacket.engine;

import com.deeppacket.dpi.DNSExtractor;
import com.deeppacket.dpi.HTTPHostExtractor;
import com.deeppacket.dpi.SNIExtractor;
import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.ConnectionState;
import com.deeppacket.model.PacketAction;
import com.deeppacket.model.PacketJob;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

public class FastPathProcessor {
    public record FPStats(long packetsProcessed, long packetsForwarded, long packetsDropped,
                          long connectionsTracked, long sniExtractions, long classificationHits) {}

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
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
                             boolean verbose) {
        this.fpId = fpId;
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
        connTracker.updateConnection(conn, job.data.length, true);
        if (job.tuple.protocol == 6) updateTcpState(conn, job.tcpFlags);
        if (conn.state == ConnectionState.BLOCKED) return PacketAction.DROP;
        if (job.payloadLength > 0 && shouldInspectFurther(conn)) inspectPayload(job, conn);
        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength <= 0 || job.payloadOffset >= job.data.length) return;
        byte[] payload = new byte[job.payloadLength];
        System.arraycopy(job.data, job.payloadOffset, payload, 0, job.payloadLength);

        if (tryExtractSni(job, conn, payload)) return;
        if (tryExtractHttpHost(job, conn, payload)) return;
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            DNSExtractor.extractQuery(payload, payload.length).ifPresent(domain ->
                connTracker.classifyConnection(conn, AppType.DNS, domain));
            return;
        }
        // Keep port-based classification provisional so later packets can still
        // upgrade to concrete app classification from SNI/Host.
        if (job.tuple.dstPort == 80 && conn.appType == AppType.UNKNOWN) {
            conn.appType = AppType.HTTP;
        } else if (job.tuple.dstPort == 443 && conn.appType == AppType.UNKNOWN) {
            conn.appType = AppType.HTTPS;
        }
    }

    private boolean tryExtractSni(PacketJob job, Connection conn, byte[] payload) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) return false;
        var sni = SNIExtractor.extract(payload, payload.length);
        if (sni.isEmpty()) return false;
        sniExtractions.incrementAndGet();
        AppType app = AppType.fromSni(sni.get());
        connTracker.classifyConnection(conn, app, sni.get());
        if (app != AppType.UNKNOWN && app != AppType.HTTPS) classificationHits.incrementAndGet();
        return true;
    }

    private boolean tryExtractHttpHost(PacketJob job, Connection conn, byte[] payload) {
        if (job.tuple.dstPort != 80) return false;
        var host = HTTPHostExtractor.extract(payload, payload.length);
        if (host.isEmpty()) return false;
        AppType app = AppType.fromSni(host.get());
        connTracker.classifyConnection(conn, app, host.get());
        if (app != AppType.UNKNOWN && app != AppType.HTTP) classificationHits.incrementAndGet();
        return true;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        var reason = ruleManager.shouldBlock(job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);
        if (reason.isPresent()) {
            if (verbose) {
                var why = reason.get();
                String detail = switch (why.type) {
                    case IP -> "IP " + why.detail;
                    case APP -> "App " + why.detail;
                    case DOMAIN -> "Domain " + why.detail;
                    case PORT -> "Port " + why.detail;
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
