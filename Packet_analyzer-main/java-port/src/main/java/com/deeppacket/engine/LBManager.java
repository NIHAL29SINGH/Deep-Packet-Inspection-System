package com.deeppacket.engine;

import com.deeppacket.model.FiveTuple;
import com.deeppacket.model.PacketJob;

import java.util.ArrayList;
import java.util.List;

public class LBManager {
    public record AggregatedStats(long totalReceived, long totalDispatched) {}

    private final List<LoadBalancer> lbs = new ArrayList<>();

    public LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        for (int lbId = 0; lbId < numLbs; lbId++) {
            int start = lbId * fpsPerLb;
            List<ThreadSafeQueue<PacketJob>> sub = new ArrayList<>();
            for (int i = 0; i < fpsPerLb; i++) sub.add(fpQueues.get(start + i));
            lbs.add(new LoadBalancer(lbId, sub));
        }
    }

    public void startAll() { lbs.forEach(LoadBalancer::start); }
    public void stopAll() { lbs.forEach(LoadBalancer::stop); }
    public int getNumLBs() { return lbs.size(); }
    public LoadBalancer getLB(int id) { return lbs.get(id); }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        return lbs.get(Math.floorMod(tuple.hashCode(), lbs.size()));
    }

    public AggregatedStats getAggregatedStats() {
        long recv = 0, disp = 0;
        for (LoadBalancer lb : lbs) {
            var s = lb.getStats();
            recv += s.packetsReceived();
            disp += s.packetsDispatched();
        }
        return new AggregatedStats(recv, disp);
    }
}
