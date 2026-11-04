package com.deeppacket.dpi;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class QuicInitialTest {
    private static byte[] referencePacket() throws IOException {
        return packet("initial-example-com");
    }

    public static byte[] packet(String name) throws IOException {
        try (InputStream in = QuicInitialTest.class.getResourceAsStream("/quic/" + name + ".hex")) {
            assertNotNull(in, "test vector missing");
            String hex = new String(in.readAllBytes(), StandardCharsets.US_ASCII).lines()
                .filter(l -> !l.startsWith("#")).findFirst().orElseThrow().trim();
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
            return out;
        }
    }

    @Test
    void keyScheduleMatchesRfc9001AppendixA() throws Exception {
        byte[] dcid = {(byte) 0x83, (byte) 0x94, (byte) 0xc8, (byte) 0xf0, 0x3e, 0x51, 0x57, 0x08};
        byte[] secret = QUICSNIExtractor.initialClientSecret(dcid);
        assertEquals("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", hex(secret));
        assertEquals("1f369613dd76d5467730efcbe3b1a22d", hex(QUICSNIExtractor.expandLabel(secret, "quic key", 16)));
        assertEquals("fa044b2f42a3fd3b46fb255c", hex(QUICSNIExtractor.expandLabel(secret, "quic iv", 12)));
        assertEquals("9f50449e04a0e810283a1e9933adedd2", hex(QUICSNIExtractor.expandLabel(secret, "quic hp", 16)));
    }

    @Test
    void decryptsAnIndependentlyBuiltInitialPacket() throws Exception {
        byte[] packet = referencePacket();
        assertEquals(1200, packet.length);
        assertTrue(QUICSNIExtractor.isQuicInitial(packet, packet.length));
        assertEquals("example.com", QUICSNIExtractor.extract(packet, packet.length).orElseThrow());
    }

    @Test
    void tamperedCiphertextIsRejectedByTheAuthenticationTag() throws Exception {
        byte[] packet = referencePacket();
        packet[packet.length - 40] ^= 0x01;
        assertTrue(QUICSNIExtractor.extract(packet, packet.length).isEmpty());
    }

    @Test
    void truncatedAndMalformedPacketsNeverThrow() throws Exception {
        byte[] packet = referencePacket();
        for (int cut : new int[]{0, 1, 6, 7, 20, 30, 60, 200, 1199}) {
            byte[] shortPacket = Arrays.copyOf(packet, cut);
            assertTrue(QUICSNIExtractor.extract(shortPacket, shortPacket.length).isEmpty(), "cut=" + cut);
        }
        byte[] garbage = new byte[1200];
        Arrays.fill(garbage, (byte) 0xC0);
        assertTrue(QUICSNIExtractor.extract(garbage, garbage.length).isEmpty());
        assertTrue(QUICSNIExtractor.extract(null, 0).isEmpty());
    }

    @Test
    void onlyVersion1InitialPacketsAreDecoded() throws Exception {
        byte[] packet = referencePacket();
        byte[] otherVersion = packet.clone();
        otherVersion[4] = 0x02;
        assertFalse(QUICSNIExtractor.isQuicInitial(otherVersion, otherVersion.length));

        byte[] handshakeType = packet.clone();
        handshakeType[0] = (byte) ((handshakeType[0] & 0xCF) | 0x20); // type 2 = Handshake
        assertFalse(QUICSNIExtractor.isQuicInitial(handshakeType, handshakeType.length));

        byte[] shortHeader = {0x40, 1, 2, 3, 4, 5, 6, 7};
        assertFalse(QUICSNIExtractor.isQuicInitial(shortHeader, shortHeader.length));
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Test
    void version2KeyScheduleMatchesRfc9369AppendixA() throws Exception {
        byte[] dcid = {(byte) 0x83, (byte) 0x94, (byte) 0xc8, (byte) 0xf0, 0x3e, 0x51, 0x57, 0x08};
        byte[] secret = QUICSNIExtractor.initialClientSecret(QUICSNIExtractor.VERSION_2, dcid);
        assertEquals("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b", hex(secret));
        assertEquals("8b1a0bc121284290a29e0971b5cd045d", hex(QUICSNIExtractor.expandLabel(secret, "quicv2 key", 16)));
        assertEquals("91f73e2351d8fa91660e909f", hex(QUICSNIExtractor.expandLabel(secret, "quicv2 iv", 12)));
        assertEquals("45b95e15235d6f45a6b19cbcb0294ba9", hex(QUICSNIExtractor.expandLabel(secret, "quicv2 hp", 16)));
    }

    @Test
    void decryptsAnIndependentlyBuiltVersion2Initial() throws Exception {
        byte[] packet = packet("initial-v2-example-com");
        assertTrue(QUICSNIExtractor.isQuicInitial(packet, packet.length));
        assertEquals("example.com", QUICSNIExtractor.extract(packet, packet.length).orElseThrow());
        // a v2 packet must not be accepted with v1 packet-type bits, and vice versa
        byte[] wrongType = packet.clone();
        wrongType[0] = (byte) (wrongType[0] & 0xCF); // type 0 is not an Initial in v2
        assertFalse(QUICSNIExtractor.isQuicInitial(wrongType, wrongType.length));
    }

    @Test
    void aSplitClientHelloYieldsFragmentsThatReassembleIntoTheSni() throws Exception {
        byte[] first = packet("split-initial-1");
        byte[] second = packet("split-initial-2");
        // Alone, neither packet reveals the SNI: it sits after a long padding extension in the second fragment.
        assertTrue(QUICSNIExtractor.extract(first, first.length).isEmpty());

        var f1 = QUICSNIExtractor.decrypt(first, first.length).orElseThrow().get(0);
        var f2 = QUICSNIExtractor.decrypt(second, second.length).orElseThrow().get(0);
        assertEquals(0, f1.offset());
        assertEquals(f1.data().length, f2.offset());
        int total = QUICSNIExtractor.announcedLength(f1.data(), f1.data().length);
        assertEquals(f1.data().length + f2.data().length, total);

        com.deeppacket.model.ReassemblyBuffer buffer = new com.deeppacket.model.ReassemblyBuffer(total);
        buffer.add(f2.offset(), f2.data(), 0, f2.data().length); // arrives out of order
        buffer.add(f1.offset(), f1.data(), 0, f1.data().length);
        assertEquals(total, buffer.contiguousLength());
        assertEquals("split.example.net", QUICSNIExtractor.sniFromHandshake(buffer.contiguousBytes(), total).orElseThrow());
    }

    @Test
    void anSniInTheFirstFragmentIsFoundBeforeTheMessageIsComplete() throws Exception {
        byte[] first = packet("early-initial-1");
        var fragment = QUICSNIExtractor.decrypt(first, first.length).orElseThrow().get(0);
        int announced = QUICSNIExtractor.announcedLength(fragment.data(), fragment.data().length);
        assertTrue(announced > fragment.data().length, "message must be incomplete");
        assertEquals("early.example.org", QUICSNIExtractor.extract(first, first.length).orElseThrow());
    }
}
