package com.deeppacket.engine;

import java.util.concurrent.atomic.AtomicLongArray;
import java.util.concurrent.atomic.LongAccumulator;
import java.util.concurrent.atomic.LongAdder;

/**
 * Lock-free latency recorder with bounded memory.
 *
 * <p>Values are bucketed on a log2 scale with 8 linear sub-buckets per octave (about 6% worst-case
 * error on percentiles). Worker threads record without taking a lock, and memory stays constant no
 * matter how many packets are processed.
 */
final class LatencyHistogram {
    private static final int SUB_BITS = 3;
    private static final int SUB_BUCKETS = 1 << SUB_BITS;
    private static final int BUCKETS = 64 * SUB_BUCKETS;

    private final AtomicLongArray counts = new AtomicLongArray(BUCKETS);
    private final LongAdder count = new LongAdder();
    private final LongAdder total = new LongAdder();
    private final LongAccumulator min = new LongAccumulator(Math::min, Long.MAX_VALUE);
    private final LongAccumulator max = new LongAccumulator(Math::max, 0);

    void record(long nanos) {
        if (nanos < 0) return;
        counts.incrementAndGet(bucketOf(nanos));
        count.increment();
        total.add(nanos);
        min.accumulate(nanos);
        max.accumulate(nanos);
    }

    long count() { return count.sum(); }
    long totalNanos() { return total.sum(); }
    long minNanos() { return count.sum() == 0 ? 0 : min.get(); }
    long maxNanos() { return max.get(); }

    /** Upper bound of the bucket containing the requested percentile. */
    long percentileNanos(double percentile) {
        long n = count.sum();
        if (n == 0) return 0;
        long rank = Math.max(1, (long) Math.ceil(percentile / 100.0 * n));
        long seen = 0;
        for (int i = 0; i < BUCKETS; i++) {
            seen += counts.get(i);
            if (seen >= rank) return Math.min(upperBound(i), max.get());
        }
        return max.get();
    }

    static int bucketOf(long nanos) {
        if (nanos < SUB_BUCKETS) return (int) nanos;
        int exp = 63 - Long.numberOfLeadingZeros(nanos);
        int sub = (int) ((nanos >>> (exp - SUB_BITS)) & (SUB_BUCKETS - 1));
        return Math.min(BUCKETS - 1, ((exp - SUB_BITS + 1) << SUB_BITS) + sub);
    }

    static long upperBound(int bucket) {
        if (bucket < SUB_BUCKETS) return bucket;
        int exp = (bucket >> SUB_BITS) + SUB_BITS - 1;
        long sub = bucket & (SUB_BUCKETS - 1);
        return ((SUB_BUCKETS + sub + 1L) << (exp - SUB_BITS)) - 1;
    }
}
