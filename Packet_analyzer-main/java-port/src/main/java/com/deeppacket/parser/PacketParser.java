package com.deeppacket.parser;

import com.deeppacket.pcap.RawPacket;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

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
        int end = data.length;
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = readU16(data, 12);
        offset = 14;
        if (parsed.etherType == 0x8100 || parsed.etherType == 0x88a8) {
            if (data.length < offset + 4) return null;
            parsed.vlanId = readU16(data, offset) & 0x0FFF;
            parsed.etherType = readU16(data, offset + 2);
            offset += 4;
        }

        if (parsed.etherType == ETHERTYPE_IPV4) {
            if (data.length < offset + 20) return null;
            int versionIhl = data[offset] & 0xFF;
            parsed.ipVersion = (versionIhl >>> 4) & 0x0F;
            if (parsed.ipVersion != 4) return null;
            int ihl = (versionIhl & 0x0F) * 4;
            if (ihl < 20 || data.length < offset + ihl) return null;

            int totalLength = readU16(data, offset + 2);
            int fragmentField = readU16(data, offset + 6);
            parsed.ttl = data[offset + 8] & 0xFF;
            parsed.protocol = data[offset + 9] & 0xFF;
            parsed.srcIp = ipToString(data, offset + 12);
            parsed.destIp = ipToString(data, offset + 16);
            parsed.hasIp = true;
            // Ethernet pads short frames; the IP total length says where the real packet ends.
            if (totalLength >= ihl && offset + totalLength <= data.length) {
                end = offset + totalLength;
            }
            offset += ihl;

            if ((fragmentField & 0x1FFF) != 0) {
                // Non-first fragment: there is no transport header here, only payload bytes, so
                // reading "ports" would invent flows. Report it as an IP packet and stop.
                parsed.fragment = true;
            } else if (parsed.protocol == PROTO_TCP) {
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
        } else if (parsed.etherType == ETHERTYPE_IPV6) {
            if (data.length < offset + 40) return null;
            int version = (data[offset] >>> 4) & 0x0F;
            if (version != 6) return null;
            parsed.ipVersion = 6;
            parsed.protocol = data[offset + 6] & 0xFF;
            parsed.ttl = data[offset + 7] & 0xFF;
            parsed.srcIp = ipv6ToString(data, offset + 8);
            parsed.destIp = ipv6ToString(data, offset + 24);
            parsed.hasIp = true;
            offset += 40;
        }

        parsed.payloadOffset = offset;
        parsed.payloadLength = Math.max(0, end - offset);
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

    private static String ipv6ToString(byte[] data, int off) {
        byte[] address = new byte[16];
        System.arraycopy(data, off, address, 0, address.length);
        try {
            InetAddress parsed = InetAddress.getByAddress(address);
            return parsed.getHostAddress();
        } catch (UnknownHostException e) {
            return "::";
        }
    }
}
