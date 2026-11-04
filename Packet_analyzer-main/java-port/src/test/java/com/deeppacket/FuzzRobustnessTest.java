package com.deeppacket;

import com.deeppacket.dpi.DNSExtractor;
import com.deeppacket.dpi.HTTPHostExtractor;
import com.deeppacket.dpi.QUICSNIExtractor;
import com.deeppacket.dpi.QuicInitialTest;
import com.deeppacket.dpi.SNIExtractor;
import com.deeppacket.dpi.TLSFingerprint;
import com.deeppacket.engine.DPIEngine;
import com.deeppacket.parser.PacketParser;
import com.deeppacket.parser.ParsedPacket;
import com.deeppacket.pcap.PcapReader;
import com.deeppacket.pcap.RawPacket;
import com.deeppacket.testutil.PacketBuilder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Seeded, deterministic fuzzing. A packet capture is untrusted input, so no byte sequence may make the parsers
 * throw, hang, or allocate without bound. These tests mutate valid traffic (bit flips, truncation, garbage,
 * zeroed runs) and require every component to cope.
 */
class FuzzRobustnessTest {
    private static final int CLIENT = 0x0a000001;
    private static final int SERVER = 0xcb007101;

    private static List<byte[]> corpus() throws IOException {
        List<byte[]> frames = new ArrayList<>();
        byte[] hello = PacketBuilder.clientHello("fuzz.example.com");
        frames.add(PacketBuilder.tcp(CLIENT, SERVER, 50000, 443, 1, PacketBuilder.PSH_ACK, hello));
        frames.add(PacketBuilder.tcp(CLIENT, SERVER, 50001, 80, 1, PacketBuilder.PSH_ACK,
            "GET / HTTP/1.1\r\nHost: fuzz.example.org\r\nAccept: */*\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
        frames.add(PacketBuilder.udp(CLIENT, SERVER, 40000, 53, PacketBuilder.dnsQuery("fuzz.example.net")));
        frames.add(PacketBuilder.udp(SERVER, CLIENT, 53, 40000, PacketBuilder.dnsResponse("fuzz.example.net", "edge.cdn.example", SERVER)));
        frames.add(PacketBuilder.udp(CLIENT, SERVER, 40001, 443, QuicInitialTest.packet("initial-example-com")));
        frames.add(PacketBuilder.udp(CLIENT, SERVER, 40002, 443, QuicInitialTest.packet("split-initial-1")));
        frames.add(PacketBuilder.udp(CLIENT, SERVER, 40002, 443, QuicInitialTest.packet("initial-v2-example-com")));
        frames.add(PacketBuilder.ipv4Fragment(CLIENT, SERVER, 6, new byte[64], 0x00b9));
        frames.add(PacketBuilder.tcp(CLIENT, SERVER, 50002, 23, 1, PacketBuilder.SYN, new byte[0]));
        return frames;
    }

    private static byte[] mutate(Random r, byte[] source) {
        byte[] b = source.clone();
        switch (r.nextInt(5)) {
            case 0 -> { // flip a few random bytes
                for (int i = 0, n = 1 + r.nextInt(8); i < n && b.length > 0; i++) b[r.nextInt(b.length)] ^= (byte) (1 + r.nextInt(255));
            }
            case 1 -> b = java.util.Arrays.copyOf(b, r.nextInt(b.length + 1)); // truncate
            case 2 -> { // append garbage
                byte[] extra = new byte[1 + r.nextInt(64)];
                r.nextBytes(extra);
                byte[] longer = java.util.Arrays.copyOf(b, b.length + extra.length);
                System.arraycopy(extra, 0, longer, b.length, extra.length);
                b = longer;
            }
            case 3 -> { // zero a run
                if (b.length > 0) {
                    int from = r.nextInt(b.length);
                    java.util.Arrays.fill(b, from, Math.min(b.length, from + 1 + r.nextInt(32)), (byte) 0);
                }
            }
            default -> { // set a few bytes to extreme values (lengths, flags)
                for (int i = 0, n = 1 + r.nextInt(4); i < n && b.length > 0; i++) b[r.nextInt(b.length)] = (byte) (r.nextBoolean() ? 0xFF : 0x00);
            }
        }
        return b;
    }

    private static void feedEveryExtractor(byte[] data) {
        SNIExtractor.isTlsClientHello(data, data.length);
        SNIExtractor.extract(data, data.length);
        HTTPHostExtractor.extract(data, data.length);
        DNSExtractor.extractQuery(data, data.length);
        DNSExtractor.extractAnswer(data, data.length);
        QUICSNIExtractor.isQuicInitial(data, data.length);
        QUICSNIExtractor.extract(data, data.length);
        QUICSNIExtractor.decrypt(data, data.length);
        TLSFingerprint.fromClientHello(data, data.length);
    }

    @Test
    void parserAndExtractorsNeverThrowOnMutatedPackets() throws Exception {
        List<byte[]> corpus = corpus();
        Random random = new Random(20240601L);
        int parsedOk = 0;
        for (int i = 0; i < 40_000; i++) {
            byte[] frame = mutate(random, corpus.get(random.nextInt(corpus.size())));
            RawPacket raw = new RawPacket();
            raw.data = frame;
            ParsedPacket parsed = PacketParser.parse(raw);
            feedEveryExtractor(frame); // the whole frame as if it were a payload
            if (parsed != null) {
                parsedOk++;
                if (parsed.payloadOffset >= 0 && parsed.payloadLength > 0 && parsed.payloadOffset + parsed.payloadLength <= frame.length) {
                    byte[] payload = java.util.Arrays.copyOfRange(frame, parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength);
                    feedEveryExtractor(payload);
                }
            }
        }
        assertTrue(parsedOk > 5_000, "mutations should leave many packets parseable, got " + parsedOk);
    }

    @Test
    void extractorsHandleCompletelyRandomBuffers() {
        Random random = new Random(7L);
        for (int i = 0; i < 20_000; i++) {
            byte[] data = new byte[random.nextInt(1400)];
            random.nextBytes(data);
            if (data.length > 0 && random.nextInt(3) == 0) data[0] = (byte) (random.nextBoolean() ? 0x16 : 0xC0); // look plausible
            feedEveryExtractor(data);
        }
    }

    @Test
    void captureFileReadersOnlyEverFailWithIoException() throws Exception {
        for (String name : new String[]{"/pcapng/tiny.pcap", "/pcapng/tiny.pcapng"}) {
            byte[] original;
            try (InputStream in = FuzzRobustnessTest.class.getResourceAsStream(name)) {
                original = in.readAllBytes();
            }
            Random random = new Random(name.hashCode());
            int clean = 0;
            for (int i = 0; i < 300; i++) {
                byte[] mutated = mutate(random, original);
                Path path = Files.createTempFile("dpi-fuzz", ".cap");
                try {
                    Files.write(path, mutated);
                    try (PcapReader reader = new PcapReader()) {
                        reader.open(path.toString());
                        for (int packets = 0; packets < 1_000_000; packets++) {
                            if (reader.readNextPacket().isEmpty()) break;
                        }
                        clean++;
                    } catch (IOException expected) {
                        // a corrupt capture is allowed to be rejected, but only through IOException
                    }
                } finally {
                    Files.deleteIfExists(path);
                }
            }
            assertTrue(clean > 0, name + ": some mutations should still be readable");
        }
    }

    @Test
    void theEngineAccountsForEveryFrameOfMutatedTraffic() throws Exception {
        List<byte[]> corpus = corpus();
        Random random = new Random(99L);
        List<byte[]> frames = new ArrayList<>();
        for (int i = 0; i < 4_000; i++) frames.add(mutate(random, corpus.get(random.nextInt(corpus.size()))));
        long start = System.nanoTime();
        DPIEngine engine = PacketBuilder.run(frames, null);
        long seconds = (System.nanoTime() - start) / 1_000_000_000L;
        var stats = engine.getStats();
        long accounted = stats.totalPackets.get() + stats.otherPackets.get() + stats.fragmentPackets.get() + stats.malformedPackets.get();
        assertEquals(frames.size(), accounted, "every frame must be inspected or counted as skipped");
        assertTrue(seconds < 60, "pipeline should not stall on hostile input (took " + seconds + "s)");
    }
}
