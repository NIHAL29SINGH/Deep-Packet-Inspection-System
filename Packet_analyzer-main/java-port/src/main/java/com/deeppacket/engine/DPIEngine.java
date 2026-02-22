package com.deeppacket.engine;

import com.sun.management.OperatingSystemMXBean;
import com.deeppacket.model.AppType;
import com.deeppacket.model.DPIStats;
import com.deeppacket.model.FiveTuple;
import com.deeppacket.model.PacketAction;
import com.deeppacket.model.PacketJob;
import com.deeppacket.model.NetUtil;
import com.deeppacket.monitoring.PrometheusMetrics;
import com.deeppacket.parser.PacketParser;
import com.deeppacket.parser.ParsedPacket;
import com.deeppacket.pcap.PcapPacketHeader;
import com.deeppacket.pcap.PcapReader;
import com.deeppacket.pcap.PcapWriter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class DPIEngine {
    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    private final Config config;
    private final DPIStats stats = new DPIStats();
    private final ThreadSafeQueue<PacketJob> outputQueue = new ThreadSafeQueue<>(10_000);
    private final AtomicBoolean running = new AtomicBoolean(false);

    private RuleManager ruleManager;
    private FPManager fpManager;
    private LBManager lbManager;
    private GlobalConnectionTable globalTable;
    private PcapWriter writer;
    private Thread outputThread;
    private final LatencyTracker latencyTracker = new LatencyTracker();
    private final PerfSnapshot perf = new PerfSnapshot();
    private final Runtime runtime = Runtime.getRuntime();
    private final int availableProcessors = runtime.availableProcessors();
    private final OperatingSystemMXBean osBean = resolveOsBean();

    private static final class PerfSnapshot {
        long startNanos;
        long endNanos;
        long startCpuNanos;
        long endCpuNanos;
        double endSystemCpuLoad = -1.0;
        long usedMemBefore;
        long usedMemAfter;
        long peakMemBytes;
    }

    private static final class LatencyTracker {
        private final AtomicLong count = new AtomicLong();
        private final AtomicLong totalNanos = new AtomicLong();
        private final AtomicLong minNanos = new AtomicLong(Long.MAX_VALUE);
        private final AtomicLong maxNanos = new AtomicLong();
        private long[] samples = new long[2048];
        private int size = 0;

        void record(long nanos) {
            if (nanos < 0) return;
            count.incrementAndGet();
            totalNanos.addAndGet(nanos);
            minNanos.accumulateAndGet(nanos, Math::min);
            maxNanos.accumulateAndGet(nanos, Math::max);
            synchronized (this) {
                if (size == samples.length) {
                    samples = Arrays.copyOf(samples, samples.length * 2);
                }
                samples[size++] = nanos;
            }
        }

        long count() { return count.get(); }
        long totalNanos() { return totalNanos.get(); }
        long minNanos() { return count.get() == 0 ? 0 : minNanos.get(); }
        long maxNanos() { return maxNanos.get(); }

        long percentileNanos(double percentile) {
            if (count.get() == 0) return 0;
            long[] copy;
            synchronized (this) {
                copy = Arrays.copyOf(samples, size);
            }
            Arrays.sort(copy);
            int index = (int) Math.ceil((percentile / 100.0) * copy.length) - 1;
            if (index < 0) index = 0;
            if (index >= copy.length) index = copy.length - 1;
            return copy[index];
        }
    }

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
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }
        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        fpManager = new FPManager(totalFps, ruleManager, this::handleOutput, config.verbose);
        lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getQueues());
        globalTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }
        return true;
    }

    public boolean processFile(String inputFile, String outputFile) {
        if (ruleManager == null && !initialize()) return false;

        startPerfCapture();
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
                if (parsed == null || !parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

                PacketJob job = createPacketJob(raw.data, parsed, (int) raw.header.tsSec, (int) raw.header.tsUsec, packetId++);
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
                else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

                lbManager.getLBForPacket(job.tuple).getInputQueue().push(job);
            }

            System.out.println("[Reader] Done reading " + packetId + " packets");
            Thread.sleep(700);
            stop();
            writer.close();
            endPerfCapture();
            publishPrometheusMetrics();
            return true;
        } catch (Exception e) {
            System.err.println("[DPIEngine] Failed to process file: " + e.getMessage());
            stop();
            endPerfCapture();
            publishPrometheusMetrics();
            return false;
        }
    }

    public void blockIP(String ip) { if (ruleManager != null) ruleManager.blockIP(ip); }
    public void blockApp(String app) { if (ruleManager != null) ruleManager.blockApp(AppType.fromDisplayName(app)); }
    public void blockDomain(String domain) { if (ruleManager != null) ruleManager.blockDomain(domain); }
    public boolean loadRules(String file) { return ruleManager != null && ruleManager.loadRules(file); }
    public boolean saveRules(String file) { return ruleManager != null && ruleManager.saveRules(file); }
    public boolean exportConnectionCsv(String file) {
        if (globalTable == null) return false;
        List<com.deeppacket.model.Connection> rows = globalTable.snapshotConnections();
        rows.sort(Comparator.comparingLong(c -> c.firstSeenNanos));

        Path out = Paths.get(file);
        try {
            Path parent = out.getParent();
            if (parent != null) Files.createDirectories(parent);

            try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
                writer.write("src_ip,dst_ip,src_port,dst_port,protocol,app,state,action,sni,packets_in,packets_out,bytes_in,bytes_out,first_seen_ns,last_seen_ns");
                writer.newLine();
                for (var c : rows) {
                    writer.write(String.join(",",
                        csv(NetUtil.intToIpv4(c.tuple.srcIp)),
                        csv(NetUtil.intToIpv4(c.tuple.dstIp)),
                        Integer.toString(c.tuple.srcPort),
                        Integer.toString(c.tuple.dstPort),
                        csv(protocolName(c.tuple.protocol)),
                        csv(c.appType.displayName()),
                        csv(c.state.name()),
                        csv(c.action.name()),
                        csv(c.sni == null ? "" : c.sni),
                        Long.toString(c.packetsIn),
                        Long.toString(c.packetsOut),
                        Long.toString(c.bytesIn),
                        Long.toString(c.bytesOut),
                        Long.toString(c.firstSeenNanos),
                        Long.toString(c.lastSeenNanos)
                    ));
                    writer.newLine();
                }
            }
            return true;
        } catch (IOException | UncheckedIOException e) {
            System.err.println("Failed to export CSV: " + e.getMessage());
            return false;
        }
    }
    public boolean exportReportJson(String file) {
        if (globalTable == null) return false;
        Path out = Paths.get(file);
        try {
            Path parent = out.getParent();
            if (parent != null) Files.createDirectories(parent);

            var g = globalTable.getGlobalStats();
            List<com.deeppacket.model.Connection> topConnections = globalTable.snapshotConnections();
            topConnections.sort(Comparator
                .comparingLong((com.deeppacket.model.Connection c) -> c.bytesIn + c.bytesOut)
                .reversed());
            if (topConnections.size() > 20) topConnections = topConnections.subList(0, 20);

            StringBuilder sb = new StringBuilder();
            long durationNanos = Math.max(1, perf.endNanos - perf.startNanos);
            double durationSec = durationNanos / 1_000_000_000.0;
            double pps = stats.totalPackets.get() / durationSec;
            double throughputBps = (stats.totalBytes.get() * 8.0) / durationSec;
            long latencyCount = latencyTracker.count();
            double avgLatencyNs = latencyCount == 0 ? 0.0 : (latencyTracker.totalNanos() / (double) latencyCount);
            double avgCpuUsage = 0.0;
            if (availableProcessors > 0 && perf.endCpuNanos >= perf.startCpuNanos) {
                avgCpuUsage = 100.0 * (perf.endCpuNanos - perf.startCpuNanos) / (durationNanos * availableProcessors);
            }

            sb.append("{\n");
            sb.append("  \"stats\": {\n");
            sb.append("    \"total_packets\": ").append(stats.totalPackets.get()).append(",\n");
            sb.append("    \"total_bytes\": ").append(stats.totalBytes.get()).append(",\n");
            sb.append("    \"tcp_packets\": ").append(stats.tcpPackets.get()).append(",\n");
            sb.append("    \"udp_packets\": ").append(stats.udpPackets.get()).append(",\n");
            sb.append("    \"forwarded_packets\": ").append(stats.forwardedPackets.get()).append(",\n");
            sb.append("    \"dropped_packets\": ").append(stats.droppedPackets.get()).append(",\n");
            sb.append("    \"active_connections\": ").append(g.totalActiveConnections()).append(",\n");
            sb.append("    \"connections_seen\": ").append(g.totalConnectionsSeen()).append("\n");
            sb.append("  },\n");
            sb.append("  \"performance\": {\n");
            sb.append("    \"processing_time_sec\": ").append(String.format(java.util.Locale.US, "%.6f", durationSec)).append(",\n");
            sb.append("    \"packets_per_second\": ").append(String.format(java.util.Locale.US, "%.2f", pps)).append(",\n");
            sb.append("    \"throughput_bps\": ").append(String.format(java.util.Locale.US, "%.2f", throughputBps)).append(",\n");
            sb.append("    \"avg_latency_us\": ").append(String.format(java.util.Locale.US, "%.3f", avgLatencyNs / 1_000.0)).append(",\n");
            sb.append("    \"min_latency_us\": ").append(String.format(java.util.Locale.US, "%.3f", latencyTracker.minNanos() / 1_000.0)).append(",\n");
            sb.append("    \"max_latency_us\": ").append(String.format(java.util.Locale.US, "%.3f", latencyTracker.maxNanos() / 1_000.0)).append(",\n");
            sb.append("    \"p95_latency_us\": ").append(String.format(java.util.Locale.US, "%.3f", latencyTracker.percentileNanos(95.0) / 1_000.0)).append(",\n");
            sb.append("    \"cpu_cores\": ").append(availableProcessors).append(",\n");
            sb.append("    \"avg_cpu_usage_percent\": ").append(String.format(java.util.Locale.US, "%.2f", Math.max(0.0, avgCpuUsage))).append(",\n");
            sb.append("    \"system_cpu_load_end_percent\": ").append(perf.endSystemCpuLoad >= 0.0 ? String.format(java.util.Locale.US, "%.2f", perf.endSystemCpuLoad * 100.0) : "null").append(",\n");
            sb.append("    \"memory_before_mb\": ").append(String.format(java.util.Locale.US, "%.2f", perf.usedMemBefore / (1024.0 * 1024.0))).append(",\n");
            sb.append("    \"memory_after_mb\": ").append(String.format(java.util.Locale.US, "%.2f", perf.usedMemAfter / (1024.0 * 1024.0))).append(",\n");
            sb.append("    \"peak_memory_mb\": ").append(String.format(java.util.Locale.US, "%.2f", perf.peakMemBytes / (1024.0 * 1024.0))).append("\n");
            sb.append("  },\n");

            sb.append("  \"app_distribution\": [\n");
            List<Map.Entry<com.deeppacket.model.AppType, Long>> apps = new ArrayList<>(g.appDistribution().entrySet());
            apps.sort(Comparator.comparingLong((Map.Entry<com.deeppacket.model.AppType, Long> e) -> e.getValue()).reversed());
            for (int i = 0; i < apps.size(); i++) {
                var e = apps.get(i);
                sb.append("    {\"app\": \"").append(json(e.getKey().displayName())).append("\", \"count\": ").append(e.getValue()).append("}");
                if (i + 1 < apps.size()) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ],\n");

            sb.append("  \"top_domains\": [\n");
            var topDomains = g.topDomains();
            for (int i = 0; i < topDomains.size(); i++) {
                var e = topDomains.get(i);
                sb.append("    {\"domain\": \"").append(json(e.getKey())).append("\", \"count\": ").append(e.getValue()).append("}");
                if (i + 1 < topDomains.size()) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ],\n");

            sb.append("  \"top_connections_by_bytes\": [\n");
            for (int i = 0; i < topConnections.size(); i++) {
                var c = topConnections.get(i);
                long totalBytes = c.bytesIn + c.bytesOut;
                sb.append("    {");
                sb.append("\"src_ip\": \"").append(json(NetUtil.intToIpv4(c.tuple.srcIp))).append("\", ");
                sb.append("\"dst_ip\": \"").append(json(NetUtil.intToIpv4(c.tuple.dstIp))).append("\", ");
                sb.append("\"src_port\": ").append(c.tuple.srcPort).append(", ");
                sb.append("\"dst_port\": ").append(c.tuple.dstPort).append(", ");
                sb.append("\"protocol\": \"").append(json(protocolName(c.tuple.protocol))).append("\", ");
                sb.append("\"app\": \"").append(json(c.appType.displayName())).append("\", ");
                sb.append("\"sni\": \"").append(json(c.sni == null ? "" : c.sni)).append("\", ");
                sb.append("\"bytes_total\": ").append(totalBytes).append(", ");
                sb.append("\"packets_in\": ").append(c.packetsIn).append(", ");
                sb.append("\"packets_out\": ").append(c.packetsOut);
                sb.append("}");
                if (i + 1 < topConnections.size()) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ]\n");
            sb.append("}\n");

            Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
            return true;
        } catch (IOException e) {
            System.err.println("Failed to export JSON: " + e.getMessage());
            return false;
        }
    }

    public DPIStats getStats() { return stats; }

    public String generateReport() {
        StringBuilder sb = new StringBuilder("\n");
        sb.append("==============================================================\n");
        sb.append(" PROCESSING REPORT\n");
        sb.append("--------------------------------------------------------------\n");
        sb.append(String.format(" Total Packets   : %d%n", stats.totalPackets.get()));
        sb.append(String.format(" Total Bytes     : %d%n", stats.totalBytes.get()));
        sb.append(String.format(" TCP Packets     : %d%n", stats.tcpPackets.get()));
        sb.append(String.format(" UDP Packets     : %d%n", stats.udpPackets.get()));
        sb.append("--------------------------------------------------------------\n");
        sb.append(String.format(" Forwarded       : %d%n", stats.forwardedPackets.get()));
        sb.append(String.format(" Dropped         : %d%n", stats.droppedPackets.get()));

        if (lbManager != null && fpManager != null) {
            sb.append("--------------------------------------------------------------\n");
            sb.append(" THREAD STATISTICS\n");
            for (int i = 0; i < lbManager.getNumLBs(); i++) {
                var lbStats = lbManager.getLB(i).getStats();
                sb.append(String.format("  LB%d dispatched: %d%n", i, lbStats.packetsDispatched()));
            }
            for (int i = 0; i < fpManager.getNumFPs(); i++) {
                var fpStats = fpManager.getFP(i).getStats();
                sb.append(String.format("  FP%d processed : %d%n", i, fpStats.packetsProcessed()));
            }
        }

        if (globalTable != null) {
            var g = globalTable.getGlobalStats();
            long total = g.appDistribution().values().stream().mapToLong(Long::longValue).sum();
            List<Map.Entry<com.deeppacket.model.AppType, Long>> apps = new ArrayList<>(g.appDistribution().entrySet());
            apps.sort(Comparator.comparingLong((Map.Entry<com.deeppacket.model.AppType, Long> e) -> e.getValue()).reversed());

            sb.append("--------------------------------------------------------------\n");
            sb.append(" APPLICATION BREAKDOWN\n");
            for (var e : apps) {
                double pct = total == 0 ? 0.0 : (100.0 * e.getValue() / total);
                int barLen = Math.max(1, (int) (pct / 5.0));
                String bar = "#".repeat(Math.min(barLen, 20));
                sb.append(String.format("  %-16s %6d  %5.1f%%  %s%n",
                    e.getKey().displayName(), e.getValue(), pct, bar));
            }

            if (!g.topDomains().isEmpty()) {
                sb.append("\n Detected Domains/SNIs\n");
                for (var d : g.topDomains()) {
                    var app = com.deeppacket.model.AppType.fromSni(d.getKey()).displayName();
                    sb.append("  - ").append(d.getKey()).append(" -> ").append(app).append('\n');
                }
            }
        }

        appendPerformanceReport(sb);
        sb.append("==============================================================\n");
        return sb.toString();
    }

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
            } catch (IOException ignored) {
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        latencyTracker.record(System.nanoTime() - job.enqueueNanos);
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
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
        job.tuple = new FiveTuple(
            NetUtil.parseIpv4ToInt(parsed.srcIp),
            NetUtil.parseIpv4ToInt(parsed.destIp),
            parsed.srcPort,
            parsed.destPort,
            parsed.protocol
        );
        return job;
    }

    private static OperatingSystemMXBean resolveOsBean() {
        var bean = ManagementFactory.getOperatingSystemMXBean();
        if (bean instanceof OperatingSystemMXBean os) return os;
        return null;
    }

    private void startPerfCapture() {
        perf.startNanos = System.nanoTime();
        perf.startCpuNanos = osBean != null ? osBean.getProcessCpuTime() : 0;
        perf.usedMemBefore = usedMemoryBytes();
        perf.usedMemAfter = perf.usedMemBefore;
        perf.endCpuNanos = perf.startCpuNanos;
        perf.endNanos = perf.startNanos;
        perf.endSystemCpuLoad = -1.0;
        resetPeakMemoryMeters();
    }

    private void endPerfCapture() {
        perf.endNanos = System.nanoTime();
        perf.endCpuNanos = osBean != null ? osBean.getProcessCpuTime() : perf.startCpuNanos;
        perf.endSystemCpuLoad = osBean != null ? osBean.getSystemCpuLoad() : -1.0;
        perf.usedMemAfter = usedMemoryBytes();
        perf.peakMemBytes = peakMemoryBytes();
    }

    private void appendPerformanceReport(StringBuilder sb) {
        long packets = stats.totalPackets.get();
        long totalBytes = stats.totalBytes.get();
        long durationNanos = Math.max(1, perf.endNanos - perf.startNanos);
        double durationSec = durationNanos / 1_000_000_000.0;
        double pps = packets / durationSec;
        double throughputBps = (totalBytes * 8.0) / durationSec;

        long latencyCount = latencyTracker.count();
        double avgLatencyNs = latencyCount == 0 ? 0.0 : (latencyTracker.totalNanos() / (double) latencyCount);
        double minLatencyNs = latencyTracker.minNanos();
        double maxLatencyNs = latencyTracker.maxNanos();
        double p95LatencyNs = latencyTracker.percentileNanos(95.0);

        double avgCpuUsage = 0.0;
        if (availableProcessors > 0 && perf.endCpuNanos >= perf.startCpuNanos) {
            avgCpuUsage = 100.0 * (perf.endCpuNanos - perf.startCpuNanos) / (durationNanos * availableProcessors);
        }

        sb.append("==============================================================\n");
        sb.append(" PERFORMANCE REPORT\n");
        sb.append("--------------------------------------------------------------\n");
        sb.append(String.format(" Packets Processed : %d%n", packets));
        sb.append(String.format(" Total Bytes       : %d (%.2f MB)%n", totalBytes, totalBytes / (1024.0 * 1024.0)));
        sb.append(String.format(" Processing Time   : %.3f sec%n", durationSec));
        sb.append(String.format(" Packets Per Second: %,.0f pps%n", pps));
        sb.append(String.format(" Throughput        : %s%n", formatBitrate(throughputBps)));
        sb.append(String.format(" Avg Latency       : %.2f us%n", avgLatencyNs / 1_000.0));
        sb.append(String.format(" Min Latency       : %.2f us%n", minLatencyNs / 1_000.0));
        sb.append(String.format(" Max Latency       : %.2f us%n", maxLatencyNs / 1_000.0));
        sb.append(String.format(" P95 Latency       : %.2f us%n", p95LatencyNs / 1_000.0));
        sb.append(String.format(" CPU Cores         : %d%n", availableProcessors));
        sb.append(String.format(" Avg CPU Usage     : %.1f%%%n", Math.max(0.0, avgCpuUsage)));
        if (perf.endSystemCpuLoad >= 0.0) {
            sb.append(String.format(" System CPU (end)  : %.1f%%%n", perf.endSystemCpuLoad * 100.0));
        } else {
            sb.append(" System CPU (end)  : n/a\n");
        }
        sb.append(String.format(" Memory Before     : %.2f MB%n", perf.usedMemBefore / (1024.0 * 1024.0)));
        sb.append(String.format(" Memory After      : %.2f MB%n", perf.usedMemAfter / (1024.0 * 1024.0)));
        sb.append(String.format(" Peak Memory       : %.2f MB%n", perf.peakMemBytes / (1024.0 * 1024.0)));
    }

    private void publishPrometheusMetrics() {
        PrometheusMetrics pm = PrometheusMetrics.getInstance();

        long packets = stats.totalPackets.get();
        long totalBytes = stats.totalBytes.get();
        long durationNanos = Math.max(1, perf.endNanos - perf.startNanos);
        double durationSec = durationNanos / 1_000_000_000.0;
        double pps = packets / durationSec;
        double throughputBps = (totalBytes * 8.0) / durationSec;

        long latencyCount = latencyTracker.count();
        double avgLatencyNs = latencyCount == 0 ? 0.0 : (latencyTracker.totalNanos() / (double) latencyCount);
        double avgCpuUsage = 0.0;
        if (availableProcessors > 0 && perf.endCpuNanos >= perf.startCpuNanos) {
            avgCpuUsage = 100.0 * (perf.endCpuNanos - perf.startCpuNanos) / (durationNanos * availableProcessors);
        }

        pm.setGauge("dpi_processing_total_packets", packets);
        pm.setGauge("dpi_processing_total_bytes", totalBytes);
        pm.setGauge("dpi_processing_tcp_packets", stats.tcpPackets.get());
        pm.setGauge("dpi_processing_udp_packets", stats.udpPackets.get());
        pm.setGauge("dpi_processing_forwarded_packets", stats.forwardedPackets.get());
        pm.setGauge("dpi_processing_dropped_packets", stats.droppedPackets.get());

        pm.setGauge("dpi_performance_processing_seconds", durationSec);
        pm.setGauge("dpi_performance_packets_per_second", pps);
        pm.setGauge("dpi_performance_throughput_bps", throughputBps);
        pm.setGauge("dpi_performance_latency_avg_us", avgLatencyNs / 1_000.0);
        pm.setGauge("dpi_performance_latency_min_us", latencyTracker.minNanos() / 1_000.0);
        pm.setGauge("dpi_performance_latency_max_us", latencyTracker.maxNanos() / 1_000.0);
        pm.setGauge("dpi_performance_latency_p95_us", latencyTracker.percentileNanos(95.0) / 1_000.0);
        pm.setGauge("dpi_performance_cpu_cores", availableProcessors);
        pm.setGauge("dpi_performance_cpu_avg_percent", Math.max(0.0, avgCpuUsage));
        if (perf.endSystemCpuLoad >= 0.0) {
            pm.setGauge("dpi_performance_cpu_system_end_percent", perf.endSystemCpuLoad * 100.0);
        } else {
            pm.clearGauge("dpi_performance_cpu_system_end_percent");
        }
        pm.setGauge("dpi_performance_memory_before_mb", perf.usedMemBefore / (1024.0 * 1024.0));
        pm.setGauge("dpi_performance_memory_after_mb", perf.usedMemAfter / (1024.0 * 1024.0));
        pm.setGauge("dpi_performance_memory_peak_mb", perf.peakMemBytes / (1024.0 * 1024.0));

        pm.clearLabeledMetric("dpi_thread_lb_dispatched");
        if (lbManager != null) {
            for (int i = 0; i < lbManager.getNumLBs(); i++) {
                Map<String, String> labels = new HashMap<>();
                labels.put("lb", Integer.toString(i));
                pm.setLabeledGauge("dpi_thread_lb_dispatched", labels, lbManager.getLB(i).getStats().packetsDispatched());
            }
        }

        pm.clearLabeledMetric("dpi_thread_fp_processed");
        if (fpManager != null) {
            for (int i = 0; i < fpManager.getNumFPs(); i++) {
                Map<String, String> labels = new HashMap<>();
                labels.put("fp", Integer.toString(i));
                pm.setLabeledGauge("dpi_thread_fp_processed", labels, fpManager.getFP(i).getStats().packetsProcessed());
            }
        }

        pm.clearLabeledMetric("dpi_application_count");
        pm.clearLabeledMetric("dpi_domain_count");
        if (globalTable != null) {
            var g = globalTable.getGlobalStats();
            pm.setGauge("dpi_connections_active", g.totalActiveConnections());
            pm.setGauge("dpi_connections_seen", g.totalConnectionsSeen());

            for (Map.Entry<AppType, Long> e : g.appDistribution().entrySet()) {
                Map<String, String> labels = new HashMap<>();
                labels.put("app", e.getKey().displayName());
                pm.setLabeledGauge("dpi_application_count", labels, e.getValue());
            }

            for (Map.Entry<String, Long> e : g.topDomains()) {
                Map<String, String> labels = new HashMap<>();
                labels.put("domain", e.getKey());
                labels.put("app", AppType.fromSni(e.getKey()).displayName());
                pm.setLabeledGauge("dpi_domain_count", labels, e.getValue());
            }
        }
    }

    private long usedMemoryBytes() {
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private static void resetPeakMemoryMeters() {
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            try {
                pool.resetPeakUsage();
            } catch (Exception ignored) {
            }
        }
    }

    private static long peakMemoryBytes() {
        long peak = 0;
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            try {
                var usage = pool.getPeakUsage();
                if (usage != null && usage.getUsed() > 0) {
                    peak += usage.getUsed();
                }
            } catch (Exception ignored) {
            }
        }
        return peak;
    }

    private static String formatBitrate(double bps) {
        if (bps >= 1_000_000_000.0) return String.format("%.2f Gbps", bps / 1_000_000_000.0);
        if (bps >= 1_000_000.0) return String.format("%.2f Mbps", bps / 1_000_000.0);
        if (bps >= 1_000.0) return String.format("%.2f Kbps", bps / 1_000.0);
        return String.format("%.0f bps", bps);
    }

    private static String protocolName(int protocol) {
        return switch (protocol) {
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> Integer.toString(protocol);
        };
    }

    private static String csv(String value) {
        if (value == null) return "";
        boolean needsQuotes = value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r");
        if (!needsQuotes) return value;
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static String json(String value) {
        if (value == null) return "";
        return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("\t", "\\t");
    }
}

