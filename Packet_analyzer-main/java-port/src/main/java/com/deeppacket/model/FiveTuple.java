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
