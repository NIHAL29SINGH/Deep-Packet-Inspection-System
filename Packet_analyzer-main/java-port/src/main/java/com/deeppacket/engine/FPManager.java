package com.deeppacket.engine;

import com.deeppacket.model.PacketAction;
import com.deeppacket.model.PacketJob;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

public class FPManager {
    public record AggregatedStats(long totalProcessed, long totalForwarded, long totalDropped, long totalConnections) {}

    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback,
                     boolean verbose) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback, verbose));
        }
    }

    public void startAll() { fps.forEach(FastPathProcessor::start); }
    public void stopAll() { fps.forEach(FastPathProcessor::stop); }
    public FastPathProcessor getFP(int id) { return fps.get(id); }
    public int getNumFPs() { return fps.size(); }

    public List<ThreadSafeQueue<PacketJob>> getQueues() {
        List<ThreadSafeQueue<PacketJob>> out = new ArrayList<>(fps.size());
        for (FastPathProcessor fp : fps) out.add(fp.getInputQueue());
        return out;
    }

    public AggregatedStats getAggregatedStats() {
        long processed = 0, forwarded = 0, dropped = 0, conns = 0;
        for (FastPathProcessor fp : fps) {
            var s = fp.getStats();
            processed += s.packetsProcessed();
            forwarded += s.packetsForwarded();
            dropped += s.packetsDropped();
            conns += s.connectionsTracked();
        }
        return new AggregatedStats(processed, forwarded, dropped, conns);
    }
}
