package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.DPIStats;
import com.deeppacket.model.FiveTuple;
import com.deeppacket.testutil.MiniJson;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ReportExporterTest {
    private static final String HOSTILE = "evil</script><!--\"\\\u0001\u2028 =cmd|' /C calc'!A0";

    private static ReportExporter exporter(String sni) {
        Connection c = new Connection(new FiveTuple(0x0a000001, 0x0a000002, 1234, 443, 6));
        c.appType = AppType.HTTPS;
        c.sni = sni;
        c.bytesOut = 500;
        c.bytesIn = 700;
        var global = new GlobalConnectionTable.GlobalStats(1, 1, 0, Map.of(AppType.HTTPS, 1L), List.of());
        var perf = new PerformanceMonitor().summary(10, 1000);
        return new ReportExporter(new DPIStats(), global, List.of(c), RiskRules.defaults(), perf);
    }

    @Test
    void jsonStaysValidEvenWithHostileStrings() {
        String json = exporter(HOSTILE).buildJson();
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = (Map<String, Object>) MiniJson.parse(json);
        assertTrue(parsed.containsKey("stats"));
        assertTrue(parsed.containsKey("performance"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> flows = (List<Map<String, Object>>) parsed.get("priority_flows");
        assertEquals(HOSTILE, flows.get(0).get("sni"), "value must survive an escape/parse round trip");
        assertEquals(1200.0, flows.get(0).get("bytes_total"));
        assertEquals(700.0, flows.get(0).get("bytes_in"));
    }

    @Test
    void htmlDataBlockCannotBreakOutOfTheScriptTag() {
        String html = ReportExporter.buildHtml(exporter(HOSTILE).buildJson());
        int start = html.indexOf("const report=") + "const report=".length();
        int end = html.indexOf(";const s=report.stats", start);
        assertTrue(start > 0 && end > start, "template markers not found");
        String data = html.substring(start, end);
        assertFalse(data.contains("</script"));
        assertFalse(data.contains("<!--"));
        assertFalse(data.contains("<"));
        assertNotNull(MiniJson.parse(data), "escaped data must still be valid JSON");
        assertFalse(html.contains("__REPORT__"));
    }

    @Test
    void csvNeutralisesSpreadsheetFormulas() {
        assertEquals("'=cmd|calc", ReportExporter.csv("=cmd|calc"));
        assertEquals("'+1", ReportExporter.csv("+1"));
        assertEquals("'-1", ReportExporter.csv("-1"));
        assertEquals("'@SUM(A1)", ReportExporter.csv("@SUM(A1)"));
        assertEquals("plain.example.com", ReportExporter.csv("plain.example.com"));
        assertEquals("\"a,b\"", ReportExporter.csv("a,b"));
        assertEquals("\"say \"\"hi\"\"\"", ReportExporter.csv("say \"hi\""));
        assertEquals("", ReportExporter.csv(null));
    }

    @Test
    void jsonEscapingCoversControlCharacters() {
        assertEquals("a\\u0001b", ReportExporter.json("a\u0001b"));
        assertEquals("\\u2028", ReportExporter.json("\u2028"));
        assertEquals("\\\\ \\\" \\n \\r \\t", ReportExporter.json("\\ \" \n \r \t"));
    }

    @Test
    void writesAllThreeFormatsToDisk() throws IOException {
        Path dir = Files.createTempDirectory("dpi-report");
        try {
            ReportExporter exporter = exporter("www.example.com");
            exporter.writeCsv(dir.resolve("nested/flows.csv"));
            exporter.writeJson(dir.resolve("report.json"));
            exporter.writeHtml(dir.resolve("report.html"));
            List<String> csv = Files.readAllLines(dir.resolve("nested/flows.csv"));
            assertEquals(2, csv.size());
            assertTrue(csv.get(0).startsWith("src_ip,dst_ip"));
            assertTrue(csv.get(1).contains("www.example.com"));
            MiniJson.parse(Files.readString(dir.resolve("report.json"), StandardCharsets.UTF_8));
            assertTrue(Files.readString(dir.resolve("report.html")).startsWith("<!doctype html>"));
        } finally {
            try (var walk = Files.walk(dir)) {
                walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void highRiskFlowsAreListedBeforeBusyBenignOnes() {
        Connection busy = new Connection(new FiveTuple(0x0a000001, 0x0a000002, 1111, 443, 6));
        busy.appType = AppType.GITHUB;
        busy.sni = "github.com";
        busy.bytesIn = 9_000_000;
        busy.bytesOut = 1_000_000;
        Connection telnet = new Connection(new FiveTuple(0x0a000003, 0x0a000004, 2222, 23, 6));
        telnet.bytesOut = 40;
        var global = new GlobalConnectionTable.GlobalStats(2, 2, 0, Map.of(), List.of());
        var perf = new PerformanceMonitor().summary(2, 10);
        var exporter = new ReportExporter(new DPIStats(), global, List.of(busy, telnet), RiskRules.defaults(), perf);
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = (Map<String, Object>) MiniJson.parse(exporter.buildJson());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> flows = (List<Map<String, Object>>) parsed.get("priority_flows");
        assertEquals(23.0, flows.get(0).get("dst_port"), "cleartext Telnet must outrank the big benign flow");
        assertEquals("github.com", flows.get(1).get("sni"));
    }

    @Test
    void jsonContainsAnOrderedTlsFingerprintInventoryAndTheNewFlowFields() {
        List<Connection> flows = new ArrayList<>();
        String common = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        String rare = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        for (int i = 0; i < 3; i++) flows.add(tlsFlow(1000 + i, common, "TLS 1.3", "z" + i + ".example.com"));
        flows.add(tlsFlow(2000, rare, "TLS 1.0", "legacy.example.com"));
        Connection dns = tlsFlow(3000, "", "", "");
        dns.dnsHint = "resolved.example.org";
        dns.classifiedBy = "DNS answer";
        flows.add(dns);

        var global = new GlobalConnectionTable.GlobalStats(5, 5, 0, Map.of(), List.of());
        var perf = new PerformanceMonitor().summary(5, 5);
        var exporter = new ReportExporter(new DPIStats(), global, flows, RiskRules.defaults(), perf);
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = (Map<String, Object>) MiniJson.parse(exporter.buildJson());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> inventory = (List<Map<String, Object>>) parsed.get("tls_fingerprints");
        assertEquals(2, inventory.size());
        assertEquals(common, inventory.get(0).get("ja3"));
        assertEquals(3.0, inventory.get(0).get("flows"));
        assertEquals("z0.example.com", inventory.get(0).get("example_sni"), "example is the alphabetically first name");
        assertEquals("TLS 1.0", inventory.get(1).get("tls_version"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> priority = (List<Map<String, Object>>) parsed.get("priority_flows");
        Map<String, Object> inferred = priority.stream().filter(f -> "resolved.example.org".equals(f.get("dns_name"))).findFirst().orElseThrow();
        assertEquals("DNS answer", inferred.get("classified_by"));
        assertEquals("", inferred.get("ja3"));
    }

    private static Connection tlsFlow(int srcPort, String ja3, String version, String sni) {
        Connection c = new Connection(new FiveTuple(0x0a000001, 0x0a000002, srcPort, 443, 6));
        c.appType = AppType.HTTPS;
        c.sni = sni;
        c.ja3 = ja3;
        c.tlsVersion = version;
        c.bytesOut = 100;
        return c;
    }

    @Test
    void csvIncludesTheNewColumns() throws IOException {
        Path dir = Files.createTempDirectory("dpi-csv");
        try {
            Connection c = tlsFlow(1234, "cccccccccccccccccccccccccccccccc", "TLS 1.2", "www.example.com");
            c.classifiedBy = "TLS SNI";
            var global = new GlobalConnectionTable.GlobalStats(1, 1, 0, Map.of(), List.of());
            new ReportExporter(new DPIStats(), global, List.of(c), RiskRules.defaults(),
                new PerformanceMonitor().summary(1, 1)).writeCsv(dir.resolve("f.csv"));
            List<String> lines = Files.readAllLines(dir.resolve("f.csv"));
            assertTrue(lines.get(0).endsWith(",ja3,tls_version,classified_by,dns_name"));
            assertTrue(lines.get(1).endsWith(",cccccccccccccccccccccccccccccccc,TLS 1.2,TLS SNI,"));
        } finally {
            try (var walk = Files.walk(dir)) {
                walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }
}
