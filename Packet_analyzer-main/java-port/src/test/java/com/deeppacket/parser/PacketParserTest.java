package com.deeppacket.parser;

import com.deeppacket.pcap.PcapPacketHeader;
import com.deeppacket.pcap.RawPacket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PacketParserTest {
    @Test
    void parsesIpv4TcpAndPayload() {
        byte[] packet = ethernet(0x0800, ipv4(6, tcp(1234, 443, "hello".getBytes())));
        ParsedPacket parsed = PacketParser.parse(raw(packet));
        assertNotNull(parsed);
        assertTrue(parsed.hasIp);
        assertTrue(parsed.hasTcp);
        assertEquals("10.0.0.1", parsed.srcIp);
        assertEquals(1234, parsed.srcPort);
        assertEquals(5, parsed.payloadLength);
    }

    @Test
    void parsesVlanTaggedIpv4() {
        byte[] vlan = new byte[4];
        vlan[0] = (byte) 0x00; vlan[1] = 1; vlan[2] = 0x08; vlan[3] = 0x00;
        ParsedPacket parsed = PacketParser.parse(raw(concat(ethernetHeader(0x8100), vlan,
            ipv4(17, udp(53, 53000, new byte[0])))));
        assertNotNull(parsed);
        assertTrue(parsed.hasUdp);
        assertEquals(53, parsed.srcPort);
        assertEquals(1, parsed.vlanId);
    }

    @Test
    void parsesIpv6MetadataWithoutThrowing() {
        byte[] ip = new byte[40];
        ip[0] = 0x60;
        ip[6] = 17;
        ParsedPacket parsed = PacketParser.parse(raw(concat(ethernet(0x86dd, ip))));
        assertNotNull(parsed);
        assertEquals(6, parsed.ipVersion);
        assertEquals(17, parsed.protocol);
        assertFalse(parsed.hasUdp);
    }

    @Test
    void rejectsTruncatedFrames() {
        assertNull(PacketParser.parse(raw(new byte[13])));
        assertNull(PacketParser.parse(raw(ethernet(0x0800, new byte[10]))));
    }

    private static RawPacket raw(byte[] data) {
        RawPacket raw = new RawPacket();
        raw.data = data;
        return raw;
    }

    private static byte[] ethernet(int type, byte[] payload) {
        return concat(ethernetHeader(type), payload);
    }

    private static byte[] ethernetHeader(int type) {
        byte[] h = new byte[14];
        h[0] = 1; h[5] = 2; h[6] = 3; h[11] = 4;
        h[12] = (byte) (type >>> 8); h[13] = (byte) type;
        return h;
    }

    private static byte[] ipv4(int protocol, byte[] transport) {
        byte[] ip = new byte[20];
        ip[0] = 0x45; ip[8] = 64; ip[9] = (byte) protocol;
        ip[12] = 10; ip[15] = 1; ip[16] = 10; ip[19] = 2;
        int total = ip.length + transport.length;
        ip[2] = (byte) (total >>> 8); ip[3] = (byte) total;
        return concat(ip, transport);
    }

    private static byte[] tcp(int src, int dst, byte[] payload) {
        byte[] tcp = new byte[20];
        tcp[0] = (byte) (src >>> 8); tcp[1] = (byte) src;
        tcp[2] = (byte) (dst >>> 8); tcp[3] = (byte) dst;
        tcp[12] = 0x50; tcp[13] = 0x18;
        return concat(tcp, payload);
    }

    private static byte[] udp(int src, int dst, byte[] payload) {
        byte[] udp = new byte[8];
        udp[0] = (byte) (src >>> 8); udp[1] = (byte) src;
        udp[2] = (byte) (dst >>> 8); udp[3] = (byte) dst;
        int len = udp.length + payload.length;
        udp[4] = (byte) (len >>> 8); udp[5] = (byte) len;
        return concat(udp, payload);
    }

    private static byte[] concat(byte[]... parts) {
        int size = 0;
        for (byte[] part : parts) size += part.length;
        byte[] out = new byte[size];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }
}
