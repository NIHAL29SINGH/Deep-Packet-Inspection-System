package com.deeppacket.engine;

import com.deeppacket.model.PacketJob;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer {
    public record LBStats(long packetsReceived, long packetsDispatched, long[] perFpPackets) {}

    private final int lbId;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    private final long[] perFpCounts;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        this.lbId = lbId;
        this.fpQueues = fpQueues;
        this.perFpCounts = new long[fpQueues.size()];
    }

    public void start() {
        if (running.getAndSet(true)) return;
        thread = new Thread(this::run, "lb-" + lbId);
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

    public LBStats getStats() {
        return new LBStats(packetsReceived.get(), packetsDispatched.get(), perFpCounts.clone());
    }

    private void run() {
        while (running.get() || !inputQueue.empty()) {
            PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) continue;
            packetsReceived.incrementAndGet();
            int fpIdx = Math.floorMod(job.tuple.hashCode(), fpQueues.size());
            fpQueues.get(fpIdx).push(job);
            perFpCounts[fpIdx]++;
            packetsDispatched.incrementAndGet();
        }
    }
}
