package com.deeppacket.engine;

import com.deeppacket.dpi.DnsHeuristics;
import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.FiveTuple;
import com.deeppacket.testutil.PacketBuilder;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.deeppacket.testutil.PacketBuilder.*;
import static org.junit.jupiter.api.Assertions.*;

class DnsFeaturesTest {
    private static final int CLIENT = 0x0a000001;
    private static final int RESOLVER = 0x0a000099;
    private static final int SERVER = 0xcb007109; // 203.0.113.9

    // ------------------------------------------------------------ DnsCache

    @Test
    void cacheKeepsTheLatestAnswerIndependentlyOfArrivalOrder() {
        DnsCache forward = new DnsCache();
        DnsCache backward = new DnsCache();
        forward.observe(5, "old.example", 100);
        forward.observe(5, "new.example", 200);
        backward.observe(5, "new.example", 200);
        backward.observe(5, "old.example", 100);
        assertEquals("new.example", forward.lookup(5).orElseThrow());
        assertEquals("new.example", backward.lookup(5).orElseThrow());

        DnsCache tie = new DnsCache();
        tie.observe(7, "b.example", 50);
        tie.observe(7, "a.example", 50);
        assertEquals("a.example", tie.lookup(7).orElseThrow(), "equal timestamps resolve by name order");
    }

    @Test
    void cacheIsBoundedAndCountsDrops() {
        DnsCache cache = new DnsCache(3);
        for (int i = 0; i < 10; i++) cache.observe(i, "h" + i + ".example", i);
        assertEquals(3, cache.size());
        assertEquals(7, cache.dropped());
        cache.observe(0, "updated.example", 999); // existing keys can still be refreshed
        assertEquals("updated.example", cache.lookup(0).orElseThrow());
    }

    // ----------------------------------------------------------- heuristics

    @Test
    void entropyAndMachineGeneratedDetection() {
        assertEquals(0.0, DnsHeuristics.entropy("aaaa"), 1e-9);
        assertEquals(2.0, DnsHeuristics.entropy("abcd"), 1e-9);
        assertTrue(DnsHeuristics.looksMachineGenerated("mfrggzdfmztwq2lknnwg23tpobyxe43u.t.example.net", 24, 3.5));
        assertTrue(DnsHeuristics.looksMachineGenerated("a3f9c2b7d41e08956fcb23a1e7d09c4b.example.com", 24, 3.5));
        // Ordinary names, hyphenated cloud names and short labels are not flagged.
        assertFalse(DnsHeuristics.looksMachineGenerated("www.example.com", 24, 3.5));
        assertFalse(DnsHeuristics.looksMachineGenerated(
            "prod-use1-api-gateway-internal-load-balancer-123456789.us-east-1.elb.amazonaws.com", 24, 3.5));
        assertFalse(DnsHeuristics.looksMachineGenerated("d111111abcdef8.cloudfront.net", 24, 3.5));
    }

    @Test
    void registeredDomainHandlesCommonSecondLevels() {
        assertEquals("example.com", DnsHeuristics.registeredDomain("a.b.example.com"));
        assertEquals("example.co.uk", DnsHeuristics.registeredDomain("www.example.co.uk"));
        assertEquals("example.com", DnsHeuristics.registeredDomain("example.com"));
        assertEquals("localhost", DnsHeuristics.registeredDomain("localhost"));
    }

    // ----------------------------------------------- end to end correlation

    @Test
    void aFlowWithoutSniIsTiedToTheNameDnsResolvedForItsServer() throws IOException {
        byte[] noSni = clientHello("placeholder.example"); // replaced below by a hello with no extensions
        byte[] helloWithoutSni = withoutExtensions(noSni);
        List<byte[]> frames = List.of(
            udp(CLIENT, RESOLVER, 40000, 53, dnsQuery("www.netflix.com")),
            udp(RESOLVER, CLIENT, 53, 40000, dnsResponse("www.netflix.com", null, SERVER)),
            tcp(CLIENT, SERVER, 50000, 443, 1, PSH_ACK, helloWithoutSni));
        DPIEngine engine = PacketBuilder.run(frames, null);
        Connection tls = engine.getConnections().stream().filter(c -> c.tuple.dstPort == 443).findFirst().orElseThrow();
        assertEquals("www.netflix.com", tls.dnsHint);
        assertEquals(AppType.NETFLIX, tls.appType, "application is inferred from the DNS answer");
        assertEquals("DNS answer", tls.classifiedBy);
        assertTrue(tls.sni == null || tls.sni.isEmpty(), "the inferred name is evidence, not a fake SNI");

        var risk = RiskAnalyzer.assess(tls);
        assertTrue(risk.findings().stream().anyMatch(f -> f.contains("DNS answer in the capture resolved")));
    }

    @Test
    void theDnsReplyIsLearnedEvenThoughItsFlowWasAlreadyClassifiedByTheQuery() throws IOException {
        List<byte[]> frames = List.of(
            udp(CLIENT, RESOLVER, 40000, 53, dnsQuery("github.com")),
            udp(RESOLVER, CLIENT, 53, 40000, dnsResponse("github.com", null, SERVER)),
            udp(CLIENT, SERVER, 40001, 9999, new byte[10]));
        DPIEngine engine = PacketBuilder.run(frames, null);
        Connection other = engine.getConnections().stream().filter(c -> c.tuple.dstPort == 9999).findFirst().orElseThrow();
        assertEquals("github.com", other.dnsHint);
    }

    @Test
    void manyDistinctNamesUnderOneDomainAreFlaggedButAFewAreNot() throws IOException {
        List<byte[]> tunnel = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            tunnel.add(udp(CLIENT, RESOLVER, 41000 + i, 53, dnsQuery("chunk" + i + ".t.evil-tunnel.example")));
        }
        List<Connection> flows = PacketBuilder.run(tunnel, null).getConnections();
        assertEquals(25, flows.size());
        assertTrue(flows.stream().allMatch(c -> c.tunnelNote.contains("25 distinct names under evil-tunnel.example")));
        var risk = RiskAnalyzer.assess(flows.get(0));
        assertTrue(risk.findings().stream().anyMatch(f -> f.contains("possible DNS tunnelling")));

        List<byte[]> normal = new ArrayList<>();
        for (int i = 0; i < 5; i++) normal.add(udp(CLIENT, RESOLVER, 42000 + i, 53, dnsQuery("host" + i + ".example.org")));
        assertTrue(PacketBuilder.run(normal, null).getConnections().stream().allMatch(c -> c.tunnelNote.isEmpty()));
    }

    // ------------------------------------------------------- risk additions

    @Test
    void ja3WatchlistAndDeprecatedTlsRaiseFindings() throws IOException {
        Connection c = new Connection(new FiveTuple(1, 2, 3, 443, 6));
        c.appType = AppType.GITHUB;
        c.sni = "github.com";
        c.ja3 = "e7d705a3286e19ea42f587b344ee6865";
        c.tlsVersion = "TLS 1.0";
        assertTrue(RiskAnalyzer.assess(c).findings().stream().noneMatch(f -> f.contains("watchlist")));

        RiskRules rules = RiskRules.defaults();
        rules.suspiciousJa3.add(c.ja3);
        var risk = RiskAnalyzer.assess(c, rules);
        assertTrue(risk.findings().stream().anyMatch(f -> f.contains("watchlist")));
        assertTrue(risk.findings().stream().anyMatch(f -> f.contains("deprecated")));
        assertEquals("HIGH", risk.severity()); // 40 + 15
    }

    @Test
    void newRiskSettingsLoadFromAPropertiesFileAndAreValidated() throws IOException {
        java.nio.file.Path good = java.nio.file.Files.createTempFile("risk-new", ".properties");
        java.nio.file.Path bad = java.nio.file.Files.createTempFile("risk-new-bad", ".properties");
        try {
            java.nio.file.Files.writeString(good, "suspicious_ja3=E7D705A3286E19EA42F587B344EE6865\ndns_tunnel_entropy=3.9\n"
                + "dns_tunnel_min_queries=5\ndns_tunnel_label_length=30\n");
            RiskRules rules = RiskRules.load(good.toString());
            assertTrue(rules.suspiciousJa3.contains("e7d705a3286e19ea42f587b344ee6865"));
            assertEquals(3.9, rules.dnsTunnelEntropy, 1e-9);
            assertEquals(5, rules.dnsTunnelMinQueries);
            assertEquals(30, rules.dnsTunnelLabelLength);

            java.nio.file.Files.writeString(bad, "suspicious_ja3=not-a-hash\n");
            assertThrows(IllegalArgumentException.class, () -> RiskRules.load(bad.toString()));
            java.nio.file.Files.writeString(bad, "dns_tunnel_entropy=-1\n");
            assertThrows(IllegalArgumentException.class, () -> RiskRules.load(bad.toString()));
        } finally {
            java.nio.file.Files.deleteIfExists(good);
            java.nio.file.Files.deleteIfExists(bad);
        }
    }

    /** Strips the extensions block from a ClientHello record so it carries no SNI (as with ECH or minimal clients). */
    private static byte[] withoutExtensions(byte[] record) {
        int extensionsStart = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1; // up to and including compression methods
        byte[] out = new byte[extensionsStart + 2];
        System.arraycopy(record, 0, out, 0, extensionsStart);
        int handshakeLength = out.length - 5 - 4;
        int recordLength = out.length - 5;
        out[3] = (byte) (recordLength >> 8);
        out[4] = (byte) recordLength;
        out[6] = (byte) (handshakeLength >> 16);
        out[7] = (byte) (handshakeLength >> 8);
        out[8] = (byte) handshakeLength;
        return out; // the two trailing zero bytes are an empty extensions list
    }
}
