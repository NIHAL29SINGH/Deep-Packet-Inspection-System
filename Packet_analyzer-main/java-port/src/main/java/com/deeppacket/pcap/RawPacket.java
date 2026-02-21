package com.deeppacket.pcap;

public class RawPacket {
    public final PcapPacketHeader header = new PcapPacketHeader();
    public byte[] data;
}
