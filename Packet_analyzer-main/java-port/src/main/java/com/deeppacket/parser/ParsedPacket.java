package com.deeppacket.parser;

public class ParsedPacket {
    public long timestampSec;
    public long timestampUsec;

    public String srcMac;
    public String destMac;
    public int etherType;

    public boolean hasIp;
    public int ipVersion;
    public String srcIp;
    public String destIp;
    public int protocol;
    public int ttl;

    public boolean hasTcp;
    public boolean hasUdp;
    public int srcPort;
    public int destPort;

    public int tcpFlags;
    public long seqNumber;
    public long ackNumber;

    public int payloadOffset;
    public int payloadLength;
}
