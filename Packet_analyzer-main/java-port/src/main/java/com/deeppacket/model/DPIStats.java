package com.deeppacket.model;

import java.util.concurrent.atomic.AtomicLong;

public class DPIStats {
    public final AtomicLong totalPackets = new AtomicLong();
    public final AtomicLong totalBytes = new AtomicLong();
    public final AtomicLong forwardedPackets = new AtomicLong();
    public final AtomicLong droppedPackets = new AtomicLong();
    public final AtomicLong tcpPackets = new AtomicLong();
    public final AtomicLong udpPackets = new AtomicLong();
    /** IPv6, non-TCP/UDP and non-IP packets: parsed safely but not inspected. */
    public final AtomicLong otherPackets = new AtomicLong();
    /** Non-first IPv4 fragments (no transport header, so not inspected). */
    public final AtomicLong fragmentPackets = new AtomicLong();
    /** Frames rejected by the parser as truncated or malformed. */
    public final AtomicLong malformedPackets = new AtomicLong();
}
