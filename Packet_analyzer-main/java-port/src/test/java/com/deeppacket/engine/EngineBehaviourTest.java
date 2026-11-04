package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.ConnectionState;
import com.deeppacket.model.PacketAction;
import com.deeppacket.testutil.PacketBuilder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static com.deeppacket.testutil.PacketBuilder.*;
import static org.junit.jupiter.api.Assertions.*;

/** End-to-end behaviour through the real multi-threaded pipeline. */
class EngineBehaviourTest {
    private static final int CLIENT = 0x0a000001;
    private static final int SERVER = 0xcb007101; // 203.0.113.1
    private static final int PORT = 50_000;

    @Test
    void tlsClientHelloSplitAcrossSegmentsIsReassembled() throws IOException {
        byte[] hello = clientHello("www.netflix.com");
        int cut = 40;
        List<byte[]> frames = List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1000, SYN, new byte[0]),
            tcp(SERVER, CLIENT, 443, PORT, 5000, 0x12, new byte[0]),
            tcp(CLIENT, SERVER, PORT, 443, 1001, ACK, new byte[0]),
            tcp(CLIENT, SERVER, PORT, 443, 1001, PSH_ACK, slice(hello, 0, cut)),
            tcp(CLIENT, SERVER, PORT, 443, 1001 + cut, PSH_ACK, slice(hello, cut, hello.length)));
        Connection flow = single(PacketBuilder.run(frames, null));
        assertEquals("www.netflix.com", flow.sni);
        assertEquals(AppType.NETFLIX, flow.appType);
        assertNull(flow.tlsBuffer, "buffer must be released after classification");
    }

    @Test
    void outOfOrderSegmentsAreNotStitchedIntoWrongData() throws IOException {
        byte[] hello = clientHello("www.netflix.com");
        int cut = 40;
        List<byte[]> frames = List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1001, PSH_ACK, slice(hello, 0, cut)),
            // second half arrives with a sequence gap (a segment was lost): must be ignored
            tcp(CLIENT, SERVER, PORT, 443, 1001 + cut + 500, PSH_ACK, slice(hello, cut, hello.length)));
        Connection flow = single(PacketBuilder.run(frames, null));
        assertTrue(flow.sni == null || flow.sni.isEmpty());
        assertNotEquals(AppType.NETFLIX, flow.appType);
    }

    @Test
    void nonTlsTrafficOnPort443NeverAllocatesReassemblyBuffers() throws IOException {
        byte[] junk = new byte[300];
        List<byte[]> frames = List.of(tcp(CLIENT, SERVER, PORT, 443, 1, PSH_ACK, junk));
        Connection flow = single(PacketBuilder.run(frames, null));
        assertNull(flow.tlsBuffer);
    }

    @Test
    void httpHostIsClassifiedAndUnknownHostsStayHttp() throws IOException {
        byte[] request = "GET / HTTP/1.1\r\nHost: portal.example.org\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        Connection flow = single(PacketBuilder.run(List.of(tcp(CLIENT, SERVER, PORT, 80, 1, PSH_ACK, request)), null));
        assertEquals("portal.example.org", flow.sni);
        assertEquals(AppType.HTTP, flow.appType);
    }

    @Test
    void dnsQueryIsClassifiedAsDns() throws IOException {
        byte[] query = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
        Connection flow = single(PacketBuilder.run(List.of(udp(CLIENT, SERVER, PORT, 53, query)), null));
        assertEquals(AppType.DNS, flow.appType);
        assertEquals("www.example.com", flow.sni);
    }

    @Test
    void blockingADomainDropsBothDirectionsOfTheFlow() throws IOException {
        byte[] hello = clientHello("www.facebook.com");
        List<byte[]> frames = List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1, PSH_ACK, hello),
            tcp(SERVER, CLIENT, 443, PORT, 9000, PSH_ACK, new byte[200]),
            tcp(CLIENT, SERVER, PORT, 443, 1 + hello.length, PSH_ACK, new byte[100]));
        DPIEngine engine = PacketBuilder.run(frames, e -> e.blockDomain("facebook"));
        Connection flow = single(engine);
        assertEquals(ConnectionState.BLOCKED, flow.state);
        assertEquals(PacketAction.DROP, flow.action);
        // The ClientHello itself is dropped, and so is everything after it in both directions.
        assertEquals(3, engine.getStats().droppedPackets.get());
        assertEquals(0, engine.getStats().forwardedPackets.get());
    }

    @Test
    void blockingAnApplicationDoesNotAffectOthers() throws IOException {
        List<byte[]> frames = List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1, PSH_ACK, clientHello("www.youtube.com")),
            tcp(CLIENT, SERVER, PORT + 1, 443, 1, PSH_ACK, clientHello("github.com")));
        DPIEngine engine = PacketBuilder.run(frames, e -> e.blockApp("YouTube"));
        assertEquals(1, engine.getStats().droppedPackets.get());
        assertEquals(1, engine.getStats().forwardedPackets.get());
    }

    @Test
    void reusedFourTupleAfterCloseStartsANewFlowAndKeepsTheOldOne() throws IOException {
        List<byte[]> frames = new ArrayList<>(List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1, SYN, new byte[0]),
            tcp(CLIENT, SERVER, PORT, 443, 2, PSH_ACK, clientHello("www.google.com")),
            tcp(CLIENT, SERVER, PORT, 443, 300, FIN_ACK, new byte[0]),
            tcp(SERVER, CLIENT, 443, PORT, 9, FIN_ACK, new byte[0]),
            tcp(CLIENT, SERVER, PORT, 443, 777, SYN, new byte[0]),
            tcp(CLIENT, SERVER, PORT, 443, 778, PSH_ACK, clientHello("github.com"))));
        List<Connection> flows = PacketBuilder.run(frames, null).getConnections();
        assertEquals(2, flows.size());
        assertTrue(flows.stream().anyMatch(c -> "www.google.com".equals(c.sni)));
        assertTrue(flows.stream().anyMatch(c -> "github.com".equals(c.sni)));
    }

    @Test
    void closedFlowsStillAppearInTheFinalReport() throws IOException {
        List<byte[]> frames = List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1, SYN, new byte[0]),
            tcp(CLIENT, SERVER, PORT, 443, 2, PSH_ACK, clientHello("www.google.com")),
            tcp(CLIENT, SERVER, PORT, 443, 300, FIN_ACK, new byte[0]),
            tcp(SERVER, CLIENT, 443, PORT, 9, FIN_ACK, new byte[0]));
        DPIEngine engine = PacketBuilder.run(frames, null);
        assertEquals(1, engine.getConnections().size());
        assertEquals("www.google.com", engine.getConnections().get(0).sni);
    }

    @Test
    void unsupportedAndMalformedPacketsAreCountedNotInspected() throws IOException {
        byte[] fragment = ipv4Fragment(CLIENT, SERVER, 6, new byte[64], 0x00b9);
        byte[] tooShort = new byte[9];
        byte[] icmp = ipv4Fragment(CLIENT, SERVER, 1, new byte[16], 0x4000);
        DPIEngine engine = PacketBuilder.run(List.of(fragment, tooShort, icmp,
            udp(CLIENT, SERVER, PORT, 9999, new byte[10])), null);
        assertEquals(1, engine.getStats().fragmentPackets.get());
        assertEquals(1, engine.getStats().malformedPackets.get());
        assertEquals(1, engine.getStats().otherPackets.get());
        assertEquals(1, engine.getStats().totalPackets.get());
    }

    @Test
    void highVolumeRunKeepsEveryPacket() throws IOException {
        List<byte[]> frames = new ArrayList<>();
        for (int i = 0; i < 5_000; i++) {
            frames.add(tcp(CLIENT + (i % 50), SERVER, 20_000 + (i % 200), 443, i, PSH_ACK, new byte[64]));
        }
        DPIEngine engine = PacketBuilder.run(frames, null);
        assertEquals(5_000, engine.getStats().totalPackets.get());
        assertEquals(5_000, engine.getStats().forwardedPackets.get());
    }

    @Test
    void quicInitialToAKnownServiceIsClassifiedByItsDecryptedSni() throws IOException {
        byte[] initial = quicReference();
        Connection flow = single(PacketBuilder.run(List.of(udp(CLIENT, SERVER, PORT, 443, initial)), null));
        assertEquals("example.com", flow.sni);
        assertEquals(AppType.QUIC, flow.appType, "unrecognised service over QUIC is labelled QUIC");
        assertEquals(ConnectionState.CLASSIFIED, flow.state);
    }

    @Test
    void randomUdpOn443IsNotMisreadAsQuic() throws IOException {
        byte[] noise = new byte[1200];
        new java.util.Random(5).nextBytes(noise);
        noise[0] = (byte) 0xC3;
        Connection flow = single(PacketBuilder.run(List.of(udp(CLIENT, SERVER, PORT, 443, noise)), null));
        assertTrue(flow.sni == null || flow.sni.isEmpty());
        assertTrue(flow.quicAttempts <= 3);
    }

    @Test
    void quicClientHelloSplitAcrossTwoInitialPacketsIsReassembledByTheWorker() throws IOException {
        byte[] first = com.deeppacket.dpi.QuicInitialTest.packet("split-initial-1");
        byte[] second = com.deeppacket.dpi.QuicInitialTest.packet("split-initial-2");
        Connection flow = single(PacketBuilder.run(List.of(
            udp(CLIENT, SERVER, PORT, 443, first), udp(CLIENT, SERVER, PORT, 443, second)), null));
        assertEquals("split.example.net", flow.sni);
        assertEquals(AppType.QUIC, flow.appType);
        assertEquals("QUIC Initial", flow.classifiedBy);
        assertNull(flow.quicCrypto, "reassembly buffer must be released");
    }

    @Test
    void quicFragmentsArrivingOutOfOrderDoNotCorruptOrLeak() throws IOException {
        byte[] first = com.deeppacket.dpi.QuicInitialTest.packet("split-initial-1");
        byte[] second = com.deeppacket.dpi.QuicInitialTest.packet("split-initial-2");
        // The second fragment alone cannot be sized (its start is missing), so it is ignored; the first then waits.
        Connection flow = single(PacketBuilder.run(List.of(
            udp(CLIENT, SERVER, PORT, 443, second), udp(CLIENT, SERVER, PORT, 443, first)), null));
        assertTrue(flow.sni == null || flow.sni.isEmpty());
        assertNotNull(flow.quicCrypto, "first fragment is buffered, waiting for the rest");
    }

    @Test
    void quicVersion2InitialIsClassified() throws IOException {
        byte[] v2 = com.deeppacket.dpi.QuicInitialTest.packet("initial-v2-example-com");
        Connection flow = single(PacketBuilder.run(List.of(udp(CLIENT, SERVER, PORT, 443, v2)), null));
        assertEquals("example.com", flow.sni);
        assertEquals(AppType.QUIC, flow.appType);
    }

    @Test
    void tlsFlowsCarryAJa3FingerprintAndVersion() throws IOException {
        byte[] hello = clientHello("www.github.com");
        String expected = com.deeppacket.dpi.TLSFingerprint.fromClientHello(hello, hello.length).orElseThrow().ja3();
        Connection flow = single(PacketBuilder.run(List.of(tcp(CLIENT, SERVER, PORT, 443, 1, PSH_ACK, hello)), null));
        assertEquals(expected, flow.ja3);
        assertEquals("TLS 1.2", flow.tlsVersion);
        assertEquals("TLS SNI", flow.classifiedBy);
    }

    @Test
    void aSplitClientHelloGetsTheSameFingerprintAsAWholeOne() throws IOException {
        byte[] hello = clientHello("www.github.com");
        Connection whole = single(PacketBuilder.run(List.of(tcp(CLIENT, SERVER, PORT, 443, 1, PSH_ACK, hello)), null));
        Connection split = single(PacketBuilder.run(List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1, PSH_ACK, slice(hello, 0, 60)),
            tcp(CLIENT, SERVER, PORT, 443, 61, PSH_ACK, slice(hello, 60, hello.length))), null));
        assertFalse(whole.ja3.isEmpty());
        assertEquals(whole.ja3, split.ja3);
    }

    @Test
    void blockingByJa3DropsTheMatchingClientButNotOthers() throws IOException {
        byte[] hello = clientHello("anything.example.com");
        String ja3 = com.deeppacket.dpi.TLSFingerprint.fromClientHello(hello, hello.length).orElseThrow().ja3();
        List<byte[]> frames = List.of(
            tcp(CLIENT, SERVER, PORT, 443, 1, PSH_ACK, hello),
            tcp(SERVER, CLIENT, 443, PORT, 9000, PSH_ACK, new byte[100]),
            udp(CLIENT, SERVER, PORT + 5, 9999, new byte[20]));
        DPIEngine engine = PacketBuilder.run(frames, e -> e.blockJa3(ja3.toUpperCase()));
        assertEquals(2, engine.getStats().droppedPackets.get(), "hello and its reply are dropped");
        assertEquals(1, engine.getStats().forwardedPackets.get(), "unrelated UDP traffic is untouched");
        assertThrows(IllegalArgumentException.class, () -> new RuleManager().blockJa3("not-a-hash"));
    }

    private static byte[] quicReference() throws IOException {
        try (var in = EngineBehaviourTest.class.getResourceAsStream("/quic/initial-example-com.hex")) {
            String hex = new String(in.readAllBytes(), StandardCharsets.US_ASCII).lines()
                .filter(l -> !l.startsWith("#")).findFirst().orElseThrow().trim();
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
            return out;
        }
    }

    private static Connection single(DPIEngine engine) {
        List<Connection> flows = engine.getConnections();
        assertEquals(1, flows.size());
        return flows.get(0);
    }
}
