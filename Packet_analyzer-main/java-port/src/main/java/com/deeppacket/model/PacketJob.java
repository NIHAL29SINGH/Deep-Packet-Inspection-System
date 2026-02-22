package com.deeppacket.model;

public class PacketJob {
    public int packetId;
    public FiveTuple tuple;
    public byte[] data;
    public int ethOffset;
    public int ipOffset;
    public int transportOffset;
    public int payloadOffset;
    public int payloadLength;
    public int tcpFlags;
    public int tsSec;
    public int tsUsec;
    public long enqueueNanos;
}
