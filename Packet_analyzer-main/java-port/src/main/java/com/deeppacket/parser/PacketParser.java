package com.deeppacket.parser;

import com.deeppacket.pcap.RawPacket;

public final class PacketParser {
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP = 0x0806;

    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    private PacketParser() {}

    public static ParsedPacket parse(RawPacket raw) {
        ParsedPacket parsed = new ParsedPacket();
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        if (data.length < 14) return null;

        int offset = 0;
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = readU16(data, 12);
        offset = 14;

        if (parsed.etherType == ETHERTYPE_IPV4) {
            if (data.length < offset + 20) return null;
            int versionIhl = data[offset] & 0xFF;
            parsed.ipVersion = (versionIhl >>> 4) & 0x0F;
            if (parsed.ipVersion != 4) return null;
            int ihl = (versionIhl & 0x0F) * 4;
            if (ihl < 20 || data.length < offset + ihl) return null;

            parsed.ttl = data[offset + 8] & 0xFF;
            parsed.protocol = data[offset + 9] & 0xFF;
            parsed.srcIp = ipToString(data, offset + 12);
            parsed.destIp = ipToString(data, offset + 16);
            parsed.hasIp = true;
            offset += ihl;

            if (parsed.protocol == PROTO_TCP) {
                if (data.length < offset + 20) return null;
                parsed.srcPort = readU16(data, offset);
                parsed.destPort = readU16(data, offset + 2);
                parsed.seqNumber = readU32(data, offset + 4);
                parsed.ackNumber = readU32(data, offset + 8);
                int tcpLen = ((data[offset + 12] >>> 4) & 0x0F) * 4;
                if (tcpLen < 20 || data.length < offset + tcpLen) return null;
                parsed.tcpFlags = data[offset + 13] & 0xFF;
                parsed.hasTcp = true;
                offset += tcpLen;
            } else if (parsed.protocol == PROTO_UDP) {
                if (data.length < offset + 8) return null;
                parsed.srcPort = readU16(data, offset);
                parsed.destPort = readU16(data, offset + 2);
                parsed.hasUdp = true;
                offset += 8;
            }
        }

        parsed.payloadOffset = offset;
        parsed.payloadLength = Math.max(0, data.length - offset);
        return parsed;
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP -> "TCP";
            case PROTO_UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder b = new StringBuilder();
        if ((flags & 0x02) != 0) b.append("SYN ");
        if ((flags & 0x10) != 0) b.append("ACK ");
        if ((flags & 0x01) != 0) b.append("FIN ");
        if ((flags & 0x04) != 0) b.append("RST ");
        if ((flags & 0x08) != 0) b.append("PSH ");
        if ((flags & 0x20) != 0) b.append("URG ");
        if (b.length() == 0) return "none";
        b.setLength(b.length() - 1);
        return b.toString();
    }

    private static int readU16(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }

    private static long readU32(byte[] data, int off) {
        return ((long) (data[off] & 0xFF) << 24) |
               ((long) (data[off + 1] & 0xFF) << 16) |
               ((long) (data[off + 2] & 0xFF) << 8) |
               (data[off + 3] & 0xFFL);
    }

    private static String ipToString(byte[] data, int off) {
        return (data[off] & 0xFF) + "." +
               (data[off + 1] & 0xFF) + "." +
               (data[off + 2] & 0xFF) + "." +
               (data[off + 3] & 0xFF);
    }

    private static String macToString(byte[] data, int off) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data[off] & 0xFF, data[off + 1] & 0xFF, data[off + 2] & 0xFF,
            data[off + 3] & 0xFF, data[off + 4] & 0xFF, data[off + 5] & 0xFF);
    }
}
