package com.deeppacket.model;

import java.util.Objects;

public final class FiveTuple {
    public final int srcIp;
    public final int dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol;

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort & 0xFFFF;
        this.dstPort = dstPort & 0xFFFF;
        this.protocol = protocol & 0xFF;
    }

    /**
     * Direction-independent flow hash: A->B and B->A produce the same value, so both
     * directions of a conversation are routed to the same load balancer and worker.
     */
    public int symmetricHash() {
        long e1 = ((srcIp & 0xFFFFFFFFL) << 16) | srcPort;
        long e2 = ((dstIp & 0xFFFFFFFFL) << 16) | dstPort;
        long lo = Math.min(e1, e2);
        long hi = Math.max(e1, e2);
        long h = lo * 0x9E3779B97F4A7C15L;
        h ^= (h >>> 32);
        h += hi * 0xC2B2AE3D27D4EB4FL;
        h ^= protocol * 0x165667B19E3779F9L;
        h ^= (h >>> 29);
        h *= 0xBF58476D1CE4E5B9L;
        h ^= (h >>> 32);
        return (int) h;
    }

    /**
     * Second-stage hash for picking a fast-path worker. It uses different bits than the
     * load-balancer stage; otherwise (hash % lbs) and (hash % fps) are correlated and
     * some workers never receive traffic.
     */
    public int fastPathHash() {
        return Integer.rotateRight(symmetricHash(), 16);
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?";
        return NetUtil.intToIpv4(srcIp) + ":" + srcPort + " -> " +
               NetUtil.intToIpv4(dstIp) + ":" + dstPort + " (" + proto + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple that)) return false;
        return srcIp == that.srcIp && dstIp == that.dstIp &&
               srcPort == that.srcPort && dstPort == that.dstPort &&
               protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}
