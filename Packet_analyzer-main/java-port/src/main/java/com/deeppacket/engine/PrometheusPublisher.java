package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.DPIStats;
import com.deeppacket.monitoring.PrometheusMetrics;

import java.util.HashMap;
import java.util.Map;

/** Publishes the results of a run to the in-process Prometheus registry. */
final class PrometheusPublisher {
    private PrometheusPublisher() {}

    static void publish(DPIStats stats, PerformanceMonitor.Summary perf, LBManager lbManager,
                        FPManager fpManager, GlobalConnectionTable globalTable) {
        PrometheusMetrics pm = PrometheusMetrics.getInstance();

        pm.setGauge("dpi_processing_total_packets", stats.totalPackets.get());
        pm.setGauge("dpi_processing_total_bytes", stats.totalBytes.get());
        pm.setGauge("dpi_processing_tcp_packets", stats.tcpPackets.get());
        pm.setGauge("dpi_processing_udp_packets", stats.udpPackets.get());
        pm.setGauge("dpi_processing_forwarded_packets", stats.forwardedPackets.get());
        pm.setGauge("dpi_processing_dropped_packets", stats.droppedPackets.get());
        pm.setGauge("dpi_processing_other_packets", stats.otherPackets.get());
        pm.setGauge("dpi_processing_fragment_packets", stats.fragmentPackets.get());
        pm.setGauge("dpi_processing_malformed_packets", stats.malformedPackets.get());

        pm.setGauge("dpi_performance_processing_seconds", perf.durationSec());
        pm.setGauge("dpi_performance_packets_per_second", perf.packetsPerSecond());
        pm.setGauge("dpi_performance_throughput_bps", perf.throughputBps());
        pm.setGauge("dpi_performance_latency_avg_us", perf.avgLatencyUs());
        pm.setGauge("dpi_performance_latency_min_us", perf.minLatencyUs());
        pm.setGauge("dpi_performance_latency_max_us", perf.maxLatencyUs());
        pm.setGauge("dpi_performance_latency_p95_us", perf.p95LatencyUs());
        pm.setGauge("dpi_performance_cpu_cores", perf.cpuCores());
        pm.setGauge("dpi_performance_cpu_avg_percent", perf.avgCpuPercent());
        if (perf.systemCpuEndPercent() >= 0.0) {
            pm.setGauge("dpi_performance_cpu_system_end_percent", perf.systemCpuEndPercent());
        } else {
            pm.clearGauge("dpi_performance_cpu_system_end_percent");
        }
        pm.setGauge("dpi_performance_memory_before_mb", perf.memoryBeforeMb());
        pm.setGauge("dpi_performance_memory_after_mb", perf.memoryAfterMb());
        pm.setGauge("dpi_performance_memory_peak_mb", perf.peakMemoryMb());

        pm.clearLabeledMetric("dpi_thread_lb_dispatched");
        if (lbManager != null) {
            for (int i = 0; i < lbManager.getNumLBs(); i++) {
                pm.setLabeledGauge("dpi_thread_lb_dispatched", Map.of("lb", Integer.toString(i)),
                    lbManager.getLB(i).getStats().packetsDispatched());
            }
        }

        pm.clearLabeledMetric("dpi_thread_fp_processed");
        if (fpManager != null) {
            for (int i = 0; i < fpManager.getNumFPs(); i++) {
                pm.setLabeledGauge("dpi_thread_fp_processed", Map.of("fp", Integer.toString(i)),
                    fpManager.getFP(i).getStats().packetsProcessed());
            }
        }

        pm.clearLabeledMetric("dpi_application_count");
        pm.clearLabeledMetric("dpi_domain_count");
        if (globalTable != null) {
            var g = globalTable.getGlobalStats();
            pm.setGauge("dpi_connections_active", g.totalActiveConnections());
            pm.setGauge("dpi_connections_retired", g.retiredConnections());
            pm.setGauge("dpi_connections_seen", g.totalConnectionsSeen());
            for (Map.Entry<AppType, Long> e : g.appDistribution().entrySet()) {
                pm.setLabeledGauge("dpi_application_count", Map.of("app", e.getKey().displayName()), e.getValue());
            }
            for (Map.Entry<String, Long> e : g.topDomains()) {
                Map<String, String> labels = new HashMap<>();
                labels.put("domain", e.getKey());
                labels.put("app", AppType.fromSni(e.getKey()).displayName());
                pm.setLabeledGauge("dpi_domain_count", labels, e.getValue());
            }
        }
    }
}
