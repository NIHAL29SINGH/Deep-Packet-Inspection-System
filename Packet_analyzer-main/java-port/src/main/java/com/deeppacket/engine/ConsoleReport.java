package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.DPIStats;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** Plain-text summary printed at the end of a CLI run. */
final class ConsoleReport {
    private static final String RULE = "==============================================================\n";
    private static final String THIN = "--------------------------------------------------------------\n";

    private ConsoleReport() {}

    static String render(DPIStats stats, PerformanceMonitor.Summary perf, LBManager lbManager,
                         FPManager fpManager, GlobalConnectionTable globalTable) {
        StringBuilder sb = new StringBuilder("\n");
        sb.append(RULE).append(" PROCESSING REPORT\n").append(THIN);
        sb.append(String.format(" Total Packets   : %d%n", stats.totalPackets.get()));
        sb.append(String.format(" Total Bytes     : %d%n", stats.totalBytes.get()));
        sb.append(String.format(" TCP Packets     : %d%n", stats.tcpPackets.get()));
        sb.append(String.format(" UDP Packets     : %d%n", stats.udpPackets.get()));
        sb.append(String.format(" Not inspected   : %d (other protocols/IPv6: %d, fragments: %d, malformed: %d)%n",
            stats.otherPackets.get() + stats.fragmentPackets.get() + stats.malformedPackets.get(),
            stats.otherPackets.get(), stats.fragmentPackets.get(), stats.malformedPackets.get()));
        sb.append(THIN);
        sb.append(String.format(" Forwarded       : %d%n", stats.forwardedPackets.get()));
        sb.append(String.format(" Dropped         : %d%n", stats.droppedPackets.get()));

        if (lbManager != null && fpManager != null) {
            sb.append(THIN).append(" THREAD STATISTICS\n");
            for (int i = 0; i < lbManager.getNumLBs(); i++) {
                sb.append(String.format("  LB%d dispatched: %d%n", i, lbManager.getLB(i).getStats().packetsDispatched()));
            }
            for (int i = 0; i < fpManager.getNumFPs(); i++) {
                sb.append(String.format("  FP%d processed : %d%n", i, fpManager.getFP(i).getStats().packetsProcessed()));
            }
        }

        if (globalTable != null) {
            var g = globalTable.getGlobalStats();
            long total = g.appDistribution().values().stream().mapToLong(Long::longValue).sum();
            List<Map.Entry<AppType, Long>> apps = new ArrayList<>(g.appDistribution().entrySet());
            apps.sort(Comparator.comparingLong((Map.Entry<AppType, Long> e) -> e.getValue()).reversed());

            sb.append(THIN).append(" APPLICATION BREAKDOWN\n");
            for (var e : apps) {
                double pct = total == 0 ? 0.0 : (100.0 * e.getValue() / total);
                String bar = "#".repeat(Math.min(Math.max(1, (int) (pct / 5.0)), 20));
                sb.append(String.format("  %-16s %6d  %5.1f%%  %s%n", e.getKey().displayName(), e.getValue(), pct, bar));
            }
            if (!g.topDomains().isEmpty()) {
                sb.append("\n Detected Domains/SNIs\n");
                for (var d : g.topDomains()) {
                    sb.append("  - ").append(d.getKey()).append(" -> ")
                      .append(AppType.fromSni(d.getKey()).displayName()).append('\n');
                }
            }
        }

        appendPerformance(sb, stats, perf);
        sb.append(RULE);
        return sb.toString();
    }

    private static void appendPerformance(StringBuilder sb, DPIStats stats, PerformanceMonitor.Summary p) {
        long totalBytes = stats.totalBytes.get();
        sb.append(RULE).append(" PERFORMANCE REPORT\n").append(THIN);
        sb.append(String.format(" Packets Processed : %d%n", stats.totalPackets.get()));
        sb.append(String.format(" Total Bytes       : %d (%.2f MB)%n", totalBytes, totalBytes / (1024.0 * 1024.0)));
        sb.append(String.format(" Processing Time   : %.3f sec%n", p.durationSec()));
        sb.append(String.format(" Packets Per Second: %,.0f pps%n", p.packetsPerSecond()));
        sb.append(String.format(" Throughput        : %s%n", formatBitrate(p.throughputBps())));
        sb.append(String.format(" Avg Latency       : %.2f us%n", p.avgLatencyUs()));
        sb.append(String.format(" Min Latency       : %.2f us%n", p.minLatencyUs()));
        sb.append(String.format(" Max Latency       : %.2f us%n", p.maxLatencyUs()));
        sb.append(String.format(" P95 Latency       : %.2f us (histogram, ~6%% resolution)%n", p.p95LatencyUs()));
        sb.append(String.format(" CPU Cores         : %d%n", p.cpuCores()));
        sb.append(String.format(" Avg CPU Usage     : %.1f%%%n", p.avgCpuPercent()));
        if (p.systemCpuEndPercent() >= 0.0) {
            sb.append(String.format(" System CPU (end)  : %.1f%%%n", p.systemCpuEndPercent()));
        } else {
            sb.append(" System CPU (end)  : n/a\n");
        }
        sb.append(String.format(" Memory Before     : %.2f MB%n", p.memoryBeforeMb()));
        sb.append(String.format(" Memory After      : %.2f MB%n", p.memoryAfterMb()));
        sb.append(String.format(" Peak Memory       : %.2f MB%n", p.peakMemoryMb()));
    }

    static String formatBitrate(double bps) {
        if (bps >= 1_000_000_000.0) return String.format("%.2f Gbps", bps / 1_000_000_000.0);
        if (bps >= 1_000_000.0) return String.format("%.2f Mbps", bps / 1_000_000.0);
        if (bps >= 1_000.0) return String.format("%.2f Kbps", bps / 1_000.0);
        return String.format("%.0f bps", bps);
    }
}
