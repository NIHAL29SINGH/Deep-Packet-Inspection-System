package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.DPIStats;
import com.deeppacket.model.NetUtil;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds the CSV, JSON and HTML reports from an immutable snapshot of a finished run.
 *
 * <p>Everything that can originate in packet data (SNI, Host, DNS names) is escaped for the output
 * format; CSV cells are additionally neutralised against spreadsheet formula injection.
 */
public final class ReportExporter {
    /** Number of flows listed in the JSON/HTML report (risk totals always cover every flow). */
    static final int TOP_FLOWS = 50;

    private static final String TEMPLATE_RESOURCE = "/report-template.html";

    private final DPIStats stats;
    private final GlobalConnectionTable.GlobalStats global;
    private final List<Connection> connections;
    private final RiskRules riskRules;
    private final PerformanceMonitor.Summary perf;

    ReportExporter(DPIStats stats, GlobalConnectionTable.GlobalStats global, List<Connection> connections,
                   RiskRules riskRules, PerformanceMonitor.Summary perf) {
        this.stats = stats;
        this.global = global;
        this.connections = connections;
        this.riskRules = riskRules;
        this.perf = perf;
    }

    // ------------------------------------------------------------------ CSV

    public void writeCsv(Path out) throws IOException {
        List<Connection> rows = new ArrayList<>(connections);
        rows.sort(Comparator.comparingLong(c -> c.firstSeenNanos));
        createParent(out);
        try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            writer.write("src_ip,dst_ip,src_port,dst_port,protocol,app,state,action,sni,packets_in,packets_out,"
                + "bytes_in,bytes_out,first_seen_ns,last_seen_ns,ja3,tls_version,classified_by,dns_name");
            writer.newLine();
            for (Connection c : rows) {
                writer.write(String.join(",",
                    csv(NetUtil.intToIpv4(c.tuple.srcIp)),
                    csv(NetUtil.intToIpv4(c.tuple.dstIp)),
                    Integer.toString(c.tuple.srcPort),
                    Integer.toString(c.tuple.dstPort),
                    csv(protocolName(c.tuple.protocol)),
                    csv(c.appType.displayName()),
                    csv(c.state.name()),
                    csv(c.action.name()),
                    csv(c.sni == null ? "" : c.sni),
                    Long.toString(c.packetsIn),
                    Long.toString(c.packetsOut),
                    Long.toString(c.bytesIn),
                    Long.toString(c.bytesOut),
                    Long.toString(c.firstSeenNanos),
                    Long.toString(c.lastSeenNanos),
                    csv(c.ja3),
                    csv(c.tlsVersion),
                    csv(c.classifiedBy),
                    csv(c.dnsHint)));
                writer.newLine();
            }
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    // ----------------------------------------------------------------- JSON

    public void writeJson(Path out) throws IOException {
        createParent(out);
        Files.writeString(out, buildJson(), StandardCharsets.UTF_8);
    }

    public String buildJson() {
        // Assess every flow once; the same results feed the priority list and the severity totals.
        List<ScoredFlow> scored = new ArrayList<>(connections.size());
        for (Connection c : connections) scored.add(new ScoredFlow(c, RiskAnalyzer.assess(c, riskRules)));
        // Highest risk first, then largest volume, so alerts are never hidden behind busy benign flows.
        scored.sort(Comparator
            .comparingInt((ScoredFlow f) -> f.risk().score()).reversed()
            .thenComparing(Comparator.comparingLong((ScoredFlow f) -> f.connection().bytesIn + f.connection().bytesOut).reversed()));
        List<ScoredFlow> top = scored.size() > TOP_FLOWS ? scored.subList(0, TOP_FLOWS) : scored;

        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\n  \"stats\": {\n");
        field(sb, 4, "total_packets", stats.totalPackets.get(), false);
        field(sb, 4, "total_bytes", stats.totalBytes.get(), false);
        field(sb, 4, "tcp_packets", stats.tcpPackets.get(), false);
        field(sb, 4, "udp_packets", stats.udpPackets.get(), false);
        field(sb, 4, "forwarded_packets", stats.forwardedPackets.get(), false);
        field(sb, 4, "dropped_packets", stats.droppedPackets.get(), false);
        field(sb, 4, "other_packets", stats.otherPackets.get(), false);
        field(sb, 4, "fragment_packets", stats.fragmentPackets.get(), false);
        field(sb, 4, "malformed_packets", stats.malformedPackets.get(), false);
        field(sb, 4, "active_connections", global.totalActiveConnections(), false);
        field(sb, 4, "retired_connections", global.retiredConnections(), false);
        field(sb, 4, "connections_seen", global.totalConnectionsSeen(), true);
        sb.append("  },\n  \"performance\": {\n");
        field(sb, 4, "processing_time_sec", fixed(perf.durationSec(), 6), false);
        field(sb, 4, "packets_per_second", fixed(perf.packetsPerSecond(), 2), false);
        field(sb, 4, "throughput_bps", fixed(perf.throughputBps(), 2), false);
        field(sb, 4, "avg_latency_us", fixed(perf.avgLatencyUs(), 3), false);
        field(sb, 4, "min_latency_us", fixed(perf.minLatencyUs(), 3), false);
        field(sb, 4, "max_latency_us", fixed(perf.maxLatencyUs(), 3), false);
        field(sb, 4, "p95_latency_us", fixed(perf.p95LatencyUs(), 3), false);
        field(sb, 4, "cpu_cores", perf.cpuCores(), false);
        field(sb, 4, "avg_cpu_usage_percent", fixed(perf.avgCpuPercent(), 2), false);
        field(sb, 4, "system_cpu_load_end_percent",
            perf.systemCpuEndPercent() >= 0.0 ? fixed(perf.systemCpuEndPercent(), 2) : "null", false);
        field(sb, 4, "memory_before_mb", fixed(perf.memoryBeforeMb(), 2), false);
        field(sb, 4, "memory_after_mb", fixed(perf.memoryAfterMb(), 2), false);
        field(sb, 4, "peak_memory_mb", fixed(perf.peakMemoryMb(), 2), true);
        sb.append("  },\n");

        sb.append("  \"app_distribution\": [\n");
        List<Map.Entry<AppType, Long>> apps = new ArrayList<>(global.appDistribution().entrySet());
        apps.sort(Comparator.comparingLong((Map.Entry<AppType, Long> e) -> e.getValue()).reversed());
        for (int i = 0; i < apps.size(); i++) {
            var e = apps.get(i);
            sb.append("    {\"app\": \"").append(json(e.getKey().displayName()))
              .append("\", \"count\": ").append(e.getValue()).append('}')
              .append(i + 1 < apps.size() ? "," : "").append('\n');
        }
        sb.append("  ],\n  \"top_domains\": [\n");
        var domains = global.topDomains();
        for (int i = 0; i < domains.size(); i++) {
            var e = domains.get(i);
            sb.append("    {\"domain\": \"").append(json(e.getKey()))
              .append("\", \"count\": ").append(e.getValue()).append('}')
              .append(i + 1 < domains.size() ? "," : "").append('\n');
        }
        sb.append("  ],\n  \"tls_fingerprints\": [\n");
        appendFingerprints(sb);
        sb.append("  ],\n  \"priority_flows\": [\n");
        for (int i = 0; i < top.size(); i++) {
            appendFlow(sb, top.get(i).connection(), top.get(i).risk());
            sb.append(i + 1 < top.size() ? "," : "").append('\n');
        }
        sb.append("  ],\n  \"risk_summary\": {\n");
        long critical = 0, high = 0, medium = 0, low = 0;
        for (ScoredFlow flow : scored) {
            switch (flow.risk().severity()) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
                case "MEDIUM" -> medium++;
                default -> low++;
            }
        }
        field(sb, 4, "critical", critical, false);
        field(sb, 4, "high", high, false);
        field(sb, 4, "medium", medium, false);
        field(sb, 4, "low", low, true);
        sb.append("  }\n}\n");
        return sb.toString();
    }

    /** Inventory of TLS client implementations: JA3 hash, flows using it, TLS version, and an example server name. */
    private void appendFingerprints(StringBuilder sb) {
        Map<String, long[]> flows = new java.util.TreeMap<>();
        Map<String, String> versions = new java.util.HashMap<>();
        Map<String, String> examples = new java.util.HashMap<>();
        for (Connection c : connections) {
            if (c.ja3 == null || c.ja3.isEmpty()) continue;
            flows.computeIfAbsent(c.ja3, k -> new long[1])[0]++;
            versions.putIfAbsent(c.ja3, c.tlsVersion);
            if (c.sni != null && !c.sni.isEmpty()) examples.merge(c.ja3, c.sni, (a, b) -> a.compareTo(b) <= 0 ? a : b);
        }
        List<Map.Entry<String, long[]>> ordered = new ArrayList<>(flows.entrySet());
        ordered.sort(Comparator.comparingLong((Map.Entry<String, long[]> e) -> e.getValue()[0]).reversed()
            .thenComparing(Map.Entry::getKey));
        int shown = Math.min(ordered.size(), 10);
        for (int i = 0; i < shown; i++) {
            var e = ordered.get(i);
            sb.append("    {\"ja3\": \"").append(json(e.getKey()))
              .append("\", \"flows\": ").append(e.getValue()[0])
              .append(", \"tls_version\": \"").append(json(versions.getOrDefault(e.getKey(), "")))
              .append("\", \"example_sni\": \"").append(json(examples.getOrDefault(e.getKey(), "")))
              .append("\"}").append(i + 1 < shown ? "," : "").append('\n');
        }
    }

    private record ScoredFlow(Connection connection, RiskAnalyzer.Assessment risk) {}

    private void appendFlow(StringBuilder sb, Connection c, RiskAnalyzer.Assessment risk) {
        sb.append("    {")
          .append("\"src_ip\": \"").append(json(NetUtil.intToIpv4(c.tuple.srcIp))).append("\", ")
          .append("\"dst_ip\": \"").append(json(NetUtil.intToIpv4(c.tuple.dstIp))).append("\", ")
          .append("\"src_port\": ").append(c.tuple.srcPort).append(", ")
          .append("\"dst_port\": ").append(c.tuple.dstPort).append(", ")
          .append("\"protocol\": \"").append(json(protocolName(c.tuple.protocol))).append("\", ")
          .append("\"app\": \"").append(json(c.appType.displayName())).append("\", ")
          .append("\"sni\": \"").append(json(c.sni == null ? "" : c.sni)).append("\", ")
          .append("\"classified_by\": \"").append(json(c.classifiedBy)).append("\", ")
          .append("\"ja3\": \"").append(json(c.ja3)).append("\", ")
          .append("\"tls_version\": \"").append(json(c.tlsVersion)).append("\", ")
          .append("\"dns_name\": \"").append(json(c.dnsHint)).append("\", ")
          .append("\"evidence_id\": \"").append(RiskAnalyzer.evidenceId(c)).append("\", ")
          .append("\"bytes_total\": ").append(c.bytesIn + c.bytesOut).append(", ")
          .append("\"bytes_in\": ").append(c.bytesIn).append(", ")
          .append("\"bytes_out\": ").append(c.bytesOut).append(", ")
          .append("\"packets_in\": ").append(c.packetsIn).append(", ")
          .append("\"packets_out\": ").append(c.packetsOut).append(", ")
          .append("\"risk_score\": ").append(risk.score()).append(", ")
          .append("\"risk_severity\": \"").append(json(risk.severity())).append("\", ")
          .append("\"risk_confidence\": ").append(risk.confidence()).append(", ")
          .append("\"recommended_action\": \"").append(json(risk.recommendedAction())).append("\", ")
          .append("\"risk_findings\": [");
        for (int i = 0; i < risk.findings().size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append('"').append(json(risk.findings().get(i))).append('"');
        }
        sb.append("]}");
    }

    // ----------------------------------------------------------------- HTML

    public void writeHtml(Path out) throws IOException {
        createParent(out);
        Files.writeString(out, buildHtml(buildJson()), StandardCharsets.UTF_8);
    }

    static String buildHtml(String reportJson) {
        // '<' only occurs inside JSON strings, so escaping every one is valid JSON and prevents
        // "</script>" and "<!--" from ever appearing in the inline data block.
        String safeData = reportJson.replace("<", "\\u003c");
        return loadTemplate().replace("__REPORT__", safeData);
    }

    private static String loadTemplate() {
        try (InputStream in = ReportExporter.class.getResourceAsStream(TEMPLATE_RESOURCE)) {
            if (in == null) throw new IllegalStateException("Missing resource " + TEMPLATE_RESOURCE);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // -------------------------------------------------------------- helpers

    private static void createParent(Path out) throws IOException {
        Path parent = out.getParent();
        if (parent != null) Files.createDirectories(parent);
    }

    private static void field(StringBuilder sb, int indent, String name, Object value, boolean last) {
        sb.append(" ".repeat(indent)).append('"').append(name).append("\": ").append(value);
        sb.append(last ? "\n" : ",\n");
    }

    private static String fixed(double value, int decimals) {
        return String.format(Locale.US, "%." + decimals + "f", value);
    }

    static String protocolName(int protocol) {
        return switch (protocol) {
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> Integer.toString(protocol);
        };
    }

    /** RFC 4180 quoting plus neutralisation of cells that a spreadsheet would run as a formula. */
    static String csv(String value) {
        if (value == null || value.isEmpty()) return "";
        String cell = value;
        char first = cell.charAt(0);
        if (first == '=' || first == '+' || first == '-' || first == '@' || first == '\t' || first == '\r') {
            cell = "'" + cell;
        }
        boolean needsQuotes = cell.contains(",") || cell.contains("\"") || cell.contains("\n") || cell.contains("\r");
        return needsQuotes ? "\"" + cell.replace("\"", "\"\"") + "\"" : cell;
    }

    /** JSON string escaping, including every control character and the JS line separators. */
    static String json(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }
}
