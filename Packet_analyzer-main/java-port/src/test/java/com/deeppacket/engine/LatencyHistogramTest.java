package com.deeppacket.engine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LatencyHistogramTest {
    @Test
    void emptyHistogramReportsZeros() {
        LatencyHistogram h = new LatencyHistogram();
        assertEquals(0, h.count());
        assertEquals(0, h.minNanos());
        assertEquals(0, h.maxNanos());
        assertEquals(0, h.percentileNanos(95));
    }

    @Test
    void tracksCountMinMaxAndAverageExactly() {
        LatencyHistogram h = new LatencyHistogram();
        for (long v : new long[]{100, 200, 300, 400}) h.record(v);
        assertEquals(4, h.count());
        assertEquals(100, h.minNanos());
        assertEquals(400, h.maxNanos());
        assertEquals(1000, h.totalNanos());
    }

    @Test
    void percentilesAreWithinBucketResolution() {
        LatencyHistogram h = new LatencyHistogram();
        for (long v = 1; v <= 10_000; v++) h.record(v * 1_000); // 1us .. 10ms
        long p50 = h.percentileNanos(50);
        long p95 = h.percentileNanos(95);
        long p99 = h.percentileNanos(99);
        assertTrue(Math.abs(p50 - 5_000_000) < 5_000_000 * 0.15, "p50=" + p50);
        assertTrue(Math.abs(p95 - 9_500_000) < 9_500_000 * 0.15, "p95=" + p95);
        assertTrue(p50 <= p95 && p95 <= p99 && p99 <= h.maxNanos());
    }

    @Test
    void ignoresNegativeValuesAndHandlesHugeOnes() {
        LatencyHistogram h = new LatencyHistogram();
        h.record(-5);
        h.record(Long.MAX_VALUE);
        assertEquals(1, h.count());
        assertEquals(Long.MAX_VALUE, h.maxNanos());
    }

    @Test
    void bucketsAreMonotonic() {
        int previous = -1;
        for (long v = 0; v < 5_000_000; v += 997) {
            int bucket = LatencyHistogram.bucketOf(v);
            assertTrue(bucket >= previous, "bucket regressed at " + v);
            assertTrue(LatencyHistogram.upperBound(bucket) >= v, "upper bound below value " + v);
            previous = bucket;
        }
    }

    @Test
    void recordingFromManyThreadsLosesNothing() throws Exception {
        LatencyHistogram h = new LatencyHistogram();
        Thread[] threads = new Thread[4];
        for (int t = 0; t < threads.length; t++) {
            threads[t] = new Thread(() -> { for (int i = 1; i <= 25_000; i++) h.record(i); });
            threads[t].start();
        }
        for (Thread t : threads) t.join();
        assertEquals(100_000, h.count());
    }
}
