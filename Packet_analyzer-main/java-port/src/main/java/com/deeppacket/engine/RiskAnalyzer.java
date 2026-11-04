package com.deeppacket.engine;

import com.deeppacket.dpi.DnsHeuristics;
import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.PacketAction;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Deterministic, explainable flow triage for analyst reports.
 *
 * This is intentionally a signal layer, not a verdict engine: every score is
 * accompanied by the observations that produced it.
 */
public final class RiskAnalyzer {
    public record Assessment(int score, String severity, int confidence,
                             String recommendedAction, List<String> findings) {}

    private RiskAnalyzer() {}

    public static Assessment assess(Connection connection) {
        return assess(connection, RiskRules.defaults());
    }

    public static Assessment assess(Connection connection, RiskRules rules) {
        int score = 0;
        List<String> findings = new ArrayList<>();
        int destinationPort = connection.tuple.dstPort;
        String domain = connection.sni == null ? "" : connection.sni.toLowerCase(Locale.ROOT);

        if (connection.action == PacketAction.DROP) {
            score += rules.blockedFlowScore;
            findings.add("Blocked by an active policy rule");
        }
        if (rules.cleartextPorts.contains(destinationPort)) {
            score += rules.cleartextPortScore;
            findings.add("Telnet traffic is exposed in cleartext");
        } else if (rules.sensitivePorts.contains(destinationPort)) {
            score += rules.sensitivePortScore;
            findings.add("Remote administration or file-sharing port is in use");
        } else if (rules.highRiskPorts.contains(destinationPort)) {
            score += rules.highRiskPortScore;
            findings.add("Known high-risk or backdoor-associated port is in use");
        }
        if ((destinationPort == 443 || destinationPort == 8443)
                && connection.appType != AppType.UNKNOWN
                && domain.isEmpty()) {
            if (connection.dnsHint != null && !connection.dnsHint.isEmpty()) {
                score += rules.missingSniWithDnsScore;
                findings.add("Encrypted flow has no visible SNI, but a DNS answer in the capture resolved the server to "
                    + connection.dnsHint);
            } else {
                score += rules.missingSniScore;
                findings.add("Encrypted flow has no visible SNI");
            }
        }
        if (connection.ja3 != null && rules.suspiciousJa3.contains(connection.ja3)) {
            score += rules.suspiciousJa3Score;
            findings.add("TLS client fingerprint (JA3 " + connection.ja3 + ") is on the watchlist");
        }
        if ("TLS 1.0".equals(connection.tlsVersion) || "SSL 3.0".equals(connection.tlsVersion)) {
            score += rules.deprecatedTlsScore;
            findings.add("Client offers only a deprecated protocol version (" + connection.tlsVersion + ")");
        }
        if (connection.appType == AppType.DNS && !domain.isEmpty()
                && DnsHeuristics.looksMachineGenerated(domain, rules.dnsTunnelLabelLength, rules.dnsTunnelEntropy)) {
            score += rules.dnsTunnelScore;
            findings.add("DNS name has a long, high-entropy label that may carry encoded data");
        }
        if (connection.tunnelNote != null && !connection.tunnelNote.isEmpty()) {
            score += rules.dnsTunnelScore;
            findings.add(connection.tunnelNote);
        }
        if (connection.appType == AppType.UNKNOWN) {
            score += rules.unknownApplicationScore;
            findings.add("Application could not be classified");
        }
        long totalBytes = connection.bytesIn + connection.bytesOut;
        if (connection.bytesOut > rules.outboundAsymmetryBytes
                && connection.bytesOut > Math.max(1, connection.bytesIn) * rules.outboundAsymmetryRatio) {
            score += rules.outboundAsymmetryScore;
            findings.add("Strong outbound byte asymmetry may indicate data exfiltration");
        }
        if (domain.contains("xn--") || domain.matches(".*\\d{6,}.*")) {
            score += rules.unusualDomainScore;
            findings.add("Domain contains an unusual encoded or numeric pattern");
        }

        score = Math.min(100, score);
        if (findings.isEmpty() && totalBytes > 0) {
            findings.add("No high-signal indicators observed");
        }
        String severity = score >= 70 ? "CRITICAL" : score >= 40 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";
        int confidence = findings.size() >= 2 ? 90 : findings.isEmpty() ? 55 : 75;
        String action = score >= 70 ? "Isolate flow and review immediately"
            : score >= 40 ? "Prioritize analyst review"
            : score >= 20 ? "Monitor and correlate with host telemetry"
            : "No immediate action; retain as baseline";
        return new Assessment(score, severity, confidence, action, List.copyOf(findings));
    }

    /**
     * Stable pseudonymous identifier for sharing reports without relying on raw
     * endpoint strings as the primary correlation key.
     */
    public static String evidenceId(Connection connection) {
        String material = connection.tuple + "|" + connection.appType.displayName() + "|" + connection.sni;
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(material.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(16);
            for (int i = 0; i < 8; i++) hex.append(String.format("%02x", digest[i]));
            return "flow-" + hex;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for evidence IDs", e);
        }
    }
}
