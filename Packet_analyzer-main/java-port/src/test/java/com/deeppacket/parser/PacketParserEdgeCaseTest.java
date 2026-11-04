package com.deeppacket.parser;

import com.deeppacket.pcap.RawPacket;
import com.deeppacket.testutil.PacketBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PacketParserEdgeCaseTest {
    private static final int A = 0x0a000001;
    private static final int B = 0x0a000002;

    @Test
    void ethernetPaddingIsNotCountedAsPayload() {
        byte[] frame = PacketBuilder.tcp(A, B, 1234, 80, 1, PacketBuilder.PSH_ACK, "hi".getBytes());
        ParsedPacket parsed = PacketParser.parse(raw(PacketBuilder.withTrailingPadding(frame, 12)));
        assertNotNull(parsed);
        assertEquals(2, parsed.payloadLength);
    }

    @Test
    void nonFirstFragmentHasNoTransportHeader() {
        byte[] l4 = new byte[64];
        l4[0] = 0x04; l4[1] = (byte) 0xd2; // would look like source port 1234 if parsed as TCP
        byte[] frame = PacketBuilder.ipv4Fragment(A, B, 6, l4, 0x00b9);
        ParsedPacket parsed = PacketParser.parse(raw(frame));
        assertNotNull(parsed);
        assertTrue(parsed.hasIp);
        assertTrue(parsed.fragment);
        assertFalse(parsed.hasTcp);
        assertFalse(parsed.hasUdp);
    }

    @Test
    void firstFragmentStillExposesPorts() {
        byte[] udp = new byte[40];
        udp[0] = 0x13; udp[1] = (byte) 0x88; udp[2] = 0x27; udp[3] = 0x0f;
        byte[] frame = PacketBuilder.ipv4Fragment(A, B, 17, udp, 0x2000); // MF set, offset 0
        ParsedPacket parsed = PacketParser.parse(raw(frame));
        assertNotNull(parsed);
        assertFalse(parsed.fragment);
        assertTrue(parsed.hasUdp);
        assertEquals(5000, parsed.srcPort);
    }

    @Test
    void readsTcpSequenceNumberAndFlags() {
        byte[] frame = PacketBuilder.tcp(A, B, 1, 2, 0xFFFFFFF0L, PacketBuilder.SYN, new byte[0]);
        ParsedPacket parsed = PacketParser.parse(raw(frame));
        assertEquals(0xFFFFFFF0L, parsed.seqNumber);
        assertEquals(PacketBuilder.SYN, parsed.tcpFlags & 0x3f);
    }

    private static RawPacket raw(byte[] data) {
        RawPacket raw = new RawPacket();
        raw.data = data;
        return raw;
    }
}
