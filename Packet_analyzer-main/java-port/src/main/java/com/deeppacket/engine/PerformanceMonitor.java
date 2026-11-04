package com.deeppacket.engine;

import com.sun.management.OperatingSystemMXBean;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;

/** Collects wall-clock, CPU, memory and latency measurements for one processing run. */
final class PerformanceMonitor {
    /** Derived, ready-to-print numbers for a finished run. */
    record Summary(double durationSec, double packetsPerSecond, double throughputBps,
                   double avgLatencyUs, double minLatencyUs, double maxLatencyUs, double p95LatencyUs,
                   int cpuCores, double avgCpuPercent, double systemCpuEndPercent,
                   double memoryBeforeMb, double memoryAfterMb, double peakMemoryMb) {}

    private static final double MB = 1024.0 * 1024.0;

    private final Runtime runtime = Runtime.getRuntime();
    private final int cpuCores = runtime.availableProcessors();
    private final OperatingSystemMXBean osBean = resolveOsBean();
    private final LatencyHistogram latency = new LatencyHistogram();

    private long startNanos;
    private long endNanos;
    private long startCpuNanos;
    private long endCpuNanos;
    private double endSystemCpuLoad = -1.0;
    private long usedMemBefore;
    private long usedMemAfter;
    private long peakMemBytes;

    void recordLatency(long nanos) {
        latency.record(nanos);
    }

    void start() {
        startNanos = System.nanoTime();
        startCpuNanos = osBean != null ? osBean.getProcessCpuTime() : 0;
        usedMemBefore = usedMemoryBytes();
        usedMemAfter = usedMemBefore;
        endCpuNanos = startCpuNanos;
        endNanos = startNanos;
        endSystemCpuLoad = -1.0;
        resetPeakMemoryMeters();
    }

    void end() {
        endNanos = System.nanoTime();
        endCpuNanos = osBean != null ? osBean.getProcessCpuTime() : startCpuNanos;
        endSystemCpuLoad = osBean != null ? osBean.getCpuLoad() : -1.0;
        usedMemAfter = usedMemoryBytes();
        peakMemBytes = peakMemoryBytes();
    }

    Summary summary(long packets, long totalBytes) {
        long durationNanos = Math.max(1, endNanos - startNanos);
        double durationSec = durationNanos / 1_000_000_000.0;
        long samples = latency.count();
        double avgLatencyNs = samples == 0 ? 0.0 : latency.totalNanos() / (double) samples;
        double cpu = 0.0;
        if (cpuCores > 0 && endCpuNanos >= startCpuNanos) {
            cpu = 100.0 * (endCpuNanos - startCpuNanos) / ((double) durationNanos * cpuCores);
        }
        return new Summary(durationSec, packets / durationSec, (totalBytes * 8.0) / durationSec,
            avgLatencyNs / 1_000.0, latency.minNanos() / 1_000.0, latency.maxNanos() / 1_000.0,
            latency.percentileNanos(95.0) / 1_000.0, cpuCores, Math.max(0.0, cpu),
            endSystemCpuLoad >= 0.0 ? endSystemCpuLoad * 100.0 : -1.0,
            usedMemBefore / MB, usedMemAfter / MB, peakMemBytes / MB);
    }

    private long usedMemoryBytes() {
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private static OperatingSystemMXBean resolveOsBean() {
        var bean = ManagementFactory.getOperatingSystemMXBean();
        return bean instanceof OperatingSystemMXBean os ? os : null;
    }

    private static void resetPeakMemoryMeters() {
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            try {
                pool.resetPeakUsage();
            } catch (RuntimeException ignored) {
                // Some pools do not support resetting; the peak is then cumulative.
            }
        }
    }

    private static long peakMemoryBytes() {
        long peak = 0;
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            try {
                var usage = pool.getPeakUsage();
                if (usage != null && usage.getUsed() > 0) peak += usage.getUsed();
            } catch (RuntimeException ignored) {
                // Ignore pools that cannot report usage.
            }
        }
        return peak;
    }
}
