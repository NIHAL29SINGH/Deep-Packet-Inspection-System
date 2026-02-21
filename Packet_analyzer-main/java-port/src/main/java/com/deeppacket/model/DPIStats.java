package com.deeppacket.model;

import java.util.concurrent.atomic.AtomicLong;

public class DPIStats {
    public final AtomicLong totalPackets = new AtomicLong();
    public final AtomicLong totalBytes = new AtomicLong();
    public final AtomicLong forwardedPackets = new AtomicLong();
    public final AtomicLong droppedPackets = new AtomicLong();
    public final AtomicLong tcpPackets = new AtomicLong();
    public final AtomicLong udpPackets = new AtomicLong();
    public final AtomicLong otherPackets = new AtomicLong();
}
