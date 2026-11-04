package com.deeppacket.engine;

import com.deeppacket.dpi.DnsHeuristics;
import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.DPIStats;
import com.deeppacket.model.FiveTuple;
import com.deeppacket.model.NetUtil;
import com.deeppacket.model.PacketAction;
import com.deeppacket.model.PacketJob;
import com.deeppacket.parser.PacketParser;
import com.deeppacket.parser.ParsedPacket;
import com.deeppacket.pcap.PcapPacketHeader;
import com.deeppacket.pcap.PcapReader;
import com.deeppacket.pcap.PcapWriter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Orchestrates one offline run: reader thread -> load balancers -> fast-path workers -> output writer.
 *
 * <p>Report generation, console output, Prometheus publishing and performance measurement live in their
 * own classes ({@link ReportExporter}, {@link ConsoleReport}, {@link PrometheusPublisher},
 * {@link PerformanceMonitor}); this class only owns the pipeline lifecycle and the rule API.
 */
public class DPIEngine {
    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public String rulesFile = "";
        public String riskRulesFile = "";
        public boolean verbose = false;
    }

    private static final long DRAIN_TIMEOUT_NANOS = 30_000_000_000L;

    private final Config config;
    private final DPIStats stats = new DPIStats();
    private final ThreadSafeQueue<PacketJob> outputQueue = new ThreadSafeQueue<>(10_000);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong writeErrors = new AtomicLong();
    private final PerformanceMonitor perf = new PerformanceMonitor();

    private RuleManager ruleManager;
    private RiskRules riskRules;
    private FPManager fpManager;
    private LBManager lbManager;
    private GlobalConnectionTable globalTable;
    private final DnsCache dnsCache = new DnsCache();
    private PcapWriter writer;
    private Thread outputThread;

    public DPIEngine(Config config) {
        this.config = config;
        System.out.println();
        System.out.println("==============================================================");
        System.out.println(" DPI ENGINE v2.0 (Multi-threaded)");
        System.out.println("--------------------------------------------------------------");
        System.out.printf(" Load Balancers: %2d | FPs per LB: %2d | Total FPs: %2d%n",
            config.numLoadBalancers, config.fpsPerLb, config.numLoadBalancers * config.fpsPerLb);
        System.out.println("==============================================================");
    }

    public boolean initialize() {
        ruleManager = new RuleManager();
        try {
            riskRules = RiskRules.load(config.riskRulesFile);
        } catch (IOException | IllegalArgumentException e) {
            System.err.println("[Risk] Failed to load risk rules: " + e.getMessage());
            return false;
        }
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }
        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        fpManager = new FPManager(totalFps, ruleManager, this::handleOutput, config.verbose, dnsCache);
        lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getQueues());
        globalTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }
        return true;
    }

    public boolean processFile(String inputFile, String outputFile) {
        if (ruleManager == null && !initialize()) return false;

        writeErrors.set(0);
        perf.start();
        try (PcapReader reader = new PcapReader()) {
            reader.open(inputFile);
            writer = new PcapWriter();
            writer.open(outputFile, reader.getGlobalHeader());

            start();
            System.out.println();
            System.out.println("[Reader] Processing packets...");
            int packetId = 0;
            while (true) {
                var opt = reader.readNextPacket();
                if (opt.isEmpty()) break;
                var raw = opt.get();
                ParsedPacket parsed = PacketParser.parse(raw);
                if (!isInspectable(parsed)) {
                    countSkipped(parsed);
                    continue;
                }
                PacketJob job = createPacketJob(raw.data, parsed, (int) raw.header.tsSec, (int) raw.header.tsUsec, packetId++);
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
                else stats.udpPackets.incrementAndGet();
                lbManager.getLBForPacket(job.tuple).getInputQueue().push(job);
            }

            System.out.println("[Reader] Done reading " + packetId + " packets");
            waitForPipelineDrain();
            stop();
            writer.close();
            perf.end();
            enrichAfterRun();
            PrometheusPublisher.publish(stats, summary(), lbManager, fpManager, globalTable);
            if (writeErrors.get() > 0) {
                System.err.println("[DPIEngine] " + writeErrors.get() + " packet(s) could not be written; output is incomplete");
                return false;
            }
            return true;
        } catch (Exception e) {
            System.err.println("[DPIEngine] Failed to process file: " + e.getMessage());
            stop();
            perf.end();
            PrometheusPublisher.publish(stats, summary(), lbManager, fpManager, globalTable);
            return false;
        }
    }

    /**
     * Single-threaded pass after the workers have stopped: ties flows that have no visible SNI to the name a DNS
     * answer gave for their server address, and flags clients that queried many distinct names under one domain.
     */
    private void enrichAfterRun() {
        if (globalTable == null) return;
        List<Connection> flows = globalTable.snapshotConnections();
        for (Connection c : flows) {
            if (!c.sni.isEmpty() || c.appType == AppType.DNS) continue;
            dnsCache.lookup(c.tuple.dstIp).ifPresent(name -> {
                c.dnsHint = name;
                AppType inferred = AppType.fromSni(name);
                boolean generic = c.appType == AppType.UNKNOWN || c.appType == AppType.HTTPS
                    || c.appType == AppType.HTTP || c.appType == AppType.QUIC;
                if (generic && inferred != AppType.HTTPS) {
                    c.appType = inferred;
                    c.classifiedBy = "DNS answer";
                }
            });
        }
        Map<String, Set<String>> namesPerDomain = new HashMap<>();
        for (Connection c : flows) {
            if (c.appType == AppType.DNS && !c.sni.isEmpty()) {
                namesPerDomain.computeIfAbsent(tunnelKey(c), k -> new HashSet<>()).add(c.sni.toLowerCase(java.util.Locale.ROOT));
            }
        }
        for (Connection c : flows) {
            if (c.appType != AppType.DNS || c.sni.isEmpty()) continue;
            int distinct = namesPerDomain.getOrDefault(tunnelKey(c), Set.of()).size();
            if (distinct >= riskRules.dnsTunnelMinQueries) {
                c.tunnelNote = distinct + " distinct names under " + DnsHeuristics.registeredDomain(c.sni)
                    + " were queried by " + NetUtil.intToIpv4(c.tuple.srcIp) + " (possible DNS tunnelling)";
            }
        }
    }

    private static String tunnelKey(Connection c) {
        return c.tuple.srcIp + "|" + DnsHeuristics.registeredDomain(c.sni);
    }

    // ----------------------------------------------------------- rules API

    public void blockIP(String ip) { if (ruleManager != null) ruleManager.blockIP(ip); }
    public void blockApp(String app) { if (ruleManager != null) ruleManager.blockApp(AppType.fromDisplayName(app)); }
    public void blockDomain(String domain) { if (ruleManager != null) ruleManager.blockDomain(domain); }
    public void blockPort(int port) { if (ruleManager != null) ruleManager.blockPort(port); }
    public void blockJa3(String ja3) { if (ruleManager != null) ruleManager.blockJa3(ja3); }
    public boolean loadRules(String file) { return ruleManager != null && ruleManager.loadRules(file); }
    public boolean saveRules(String file) { return ruleManager != null && ruleManager.saveRules(file); }

    // ------------------------------------------------------------- reports

    public boolean exportConnectionCsv(String file) {
        return export("CSV", file, (exporter, path) -> exporter.writeCsv(path));
    }

    public boolean exportReportJson(String file) {
        return export("JSON", file, (exporter, path) -> exporter.writeJson(path));
    }

    public boolean exportReportHtml(String file) {
        return export("HTML", file, (exporter, path) -> exporter.writeHtml(path));
    }

    public String generateReport() {
        return ConsoleReport.render(stats, summary(), lbManager, fpManager, globalTable);
    }

    public DPIStats getStats() { return stats; }

    /** Snapshot of all tracked flows, active and retired (used by reports and tests). */
    public List<Connection> getConnections() {
        return globalTable == null ? List.of() : globalTable.snapshotConnections();
    }

    @FunctionalInterface
    private interface ExportAction {
        void run(ReportExporter exporter, Path path) throws IOException;
    }

    private boolean export(String label, String file, ExportAction action) {
        if (globalTable == null) return false;
        try {
            var exporter = new ReportExporter(stats, globalTable.getGlobalStats(), globalTable.snapshotConnections(),
                riskRules, summary());
            action.run(exporter, Path.of(file));
            return true;
        } catch (IOException e) {
            System.err.println("Failed to export " + label + ": " + e.getMessage());
            return false;
        }
    }

    private PerformanceMonitor.Summary summary() {
        return perf.summary(stats.totalPackets.get(), stats.totalBytes.get());
    }

    // ------------------------------------------------------------ lifecycle

    private void start() {
        if (running.getAndSet(true)) return;
        outputThread = new Thread(this::outputThreadFunc, "output-writer");
        outputThread.start();
        fpManager.startAll();
        lbManager.startAll();
    }

    private void stop() {
        if (!running.getAndSet(false)) return;
        if (lbManager != null) lbManager.stopAll();
        if (fpManager != null) fpManager.stopAll();
        outputQueue.shutdown();
        if (outputThread != null) {
            try { outputThread.join(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    private void waitForPipelineDrain() throws InterruptedException {
        long deadline = System.nanoTime() + DRAIN_TIMEOUT_NANOS;
        while (System.nanoTime() < deadline) {
            var lb = lbManager.getAggregatedStats();
            var fp = fpManager.getAggregatedStats();
            long expected = stats.totalPackets.get();
            if (lb.totalReceived() >= expected && fp.totalProcessed() >= expected && outputQueue.empty()) {
                return;
            }
            Thread.sleep(10);
        }
        throw new IllegalStateException("Timed out waiting for packet-processing pipeline to drain");
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.empty()) {
            PacketJob job = outputQueue.popWithTimeout(100);
            if (job == null) continue;
            try {
                PcapPacketHeader hdr = new PcapPacketHeader();
                hdr.tsSec = Integer.toUnsignedLong(job.tsSec);
                hdr.tsUsec = Integer.toUnsignedLong(job.tsUsec);
                hdr.inclLen = Integer.toUnsignedLong(job.data.length);
                hdr.origLen = hdr.inclLen;
                writer.writePacket(hdr, job.data);
            } catch (IOException e) {
                if (writeErrors.getAndIncrement() == 0) {
                    System.err.println("[Output] Failed to write filtered packet: " + e.getMessage());
                }
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        perf.recordLatency(System.nanoTime() - job.enqueueNanos);
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
    }

    // -------------------------------------------------------------- helpers

    private static boolean isInspectable(ParsedPacket parsed) {
        return parsed != null && parsed.hasIp && parsed.ipVersion == 4 && !parsed.fragment
            && (parsed.hasTcp || parsed.hasUdp);
    }

    private void countSkipped(ParsedPacket parsed) {
        if (parsed == null) stats.malformedPackets.incrementAndGet();
        else if (parsed.fragment) stats.fragmentPackets.incrementAndGet();
        else stats.otherPackets.incrementAndGet();
    }

    private static PacketJob createPacketJob(byte[] data, ParsedPacket parsed, int tsSec, int tsUsec, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = tsSec;
        job.tsUsec = tsUsec;
        job.enqueueNanos = System.nanoTime();
        job.data = data;
        job.ethOffset = 0;
        job.ipOffset = 14;
        job.payloadOffset = parsed.payloadOffset;
        job.payloadLength = parsed.payloadLength;
        job.tcpFlags = parsed.tcpFlags;
        job.seq = parsed.seqNumber;
        job.tuple = new FiveTuple(
            NetUtil.parseIpv4ToInt(parsed.srcIp),
            NetUtil.parseIpv4ToInt(parsed.destIp),
            parsed.srcPort,
            parsed.destPort,
            parsed.protocol);
        return job;
    }
}
