package com.deeppacket.dpi;

import com.deeppacket.testutil.PacketBuilder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TLSFingerprintTest {
    private record Vector(String name, byte[] record, String ja3String, String ja3, String version) {}

    private static List<Vector> vectors() throws IOException {
        List<Vector> out = new ArrayList<>();
        try (InputStream in = TLSFingerprintTest.class.getResourceAsStream("/tls/ja3-vectors.txt")) {
            assertNotNull(in, "vectors missing");
            for (String line : new String(in.readAllBytes(), StandardCharsets.US_ASCII).split("\n")) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] f = line.split("\\|");
                byte[] rec = new byte[f[1].length() / 2];
                for (int i = 0; i < rec.length; i++) rec[i] = (byte) Integer.parseInt(f[1].substring(2 * i, 2 * i + 2), 16);
                out.add(new Vector(f[0], rec, f[2], f[3], f[4]));
            }
        }
        return out;
    }

    @Test
    void matchesAnIndependentImplementationOnEveryVector() throws Exception {
        List<Vector> vectors = vectors();
        assertEquals(5, vectors.size());
        for (Vector v : vectors) {
            var result = TLSFingerprint.fromClientHello(v.record(), v.record().length).orElseThrow();
            assertEquals(v.ja3String(), result.ja3String(), v.name() + " JA3 string");
            assertEquals(v.ja3(), result.ja3(), v.name() + " JA3 hash");
            assertEquals(v.version(), result.tlsVersion(), v.name() + " version");
        }
    }

    @Test
    void greaseValuesAreIgnored() {
        assertTrue(TLSFingerprint.isGrease(0x0a0a));
        assertTrue(TLSFingerprint.isGrease(0xfafa));
        assertTrue(TLSFingerprint.isGrease(0x7a7a));
        assertFalse(TLSFingerprint.isGrease(0x1301));
        assertFalse(TLSFingerprint.isGrease(0x0a1a)); // low nibble pattern matches but the bytes differ
    }

    @Test
    void md5IsTheStandardDigest() {
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", TLSFingerprint.md5(""));
        assertEquals("900150983cd24fb0d6963f7d28e17f72", TLSFingerprint.md5("abc"));
    }

    @Test
    void truncatedOrNonHelloInputGivesNoFingerprint() throws Exception {
        byte[] hello = vectors().get(1).record();
        for (int cut = 0; cut < hello.length; cut += 7) {
            assertTrue(TLSFingerprint.fromClientHello(java.util.Arrays.copyOf(hello, cut), cut).isEmpty(), "cut=" + cut);
        }
        assertTrue(TLSFingerprint.fromClientHello(null, 0).isEmpty());
        assertTrue(TLSFingerprint.fromClientHello(new byte[200], 200).isEmpty());
    }

    @Test
    void theSameHelloGivesTheSameFingerprintRegardlessOfServerName() {
        byte[] a = PacketBuilder.clientHello("one.example.com");
        byte[] b = PacketBuilder.clientHello("two.example.org");
        var fa = TLSFingerprint.fromClientHello(a, a.length).orElseThrow();
        var fb = TLSFingerprint.fromClientHello(b, b.length).orElseThrow();
        assertEquals(fa.ja3(), fb.ja3(), "the fingerprint describes the client, not the destination");
        assertEquals(32, fa.ja3().length());
    }
}
