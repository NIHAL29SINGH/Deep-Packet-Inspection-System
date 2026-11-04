package com.deeppacket.pcap;

import java.nio.ByteOrder;

public class PcapGlobalHeader {
    public int magicNumber;
    public int versionMajor;
    public int versionMinor;
    public int thisZone;
    public long sigFigs;
    public long snapLen;
    public long network;
    public ByteOrder byteOrder;
    /** True when the source capture used nanosecond timestamps (converted to microseconds on read). */
    public boolean nanosecondResolution;
}
