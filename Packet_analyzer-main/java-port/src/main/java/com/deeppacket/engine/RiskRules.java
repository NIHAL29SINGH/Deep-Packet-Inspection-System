package com.deeppacket.engine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/**
 * Validated, human-editable thresholds for deterministic risk triage.
 */
public final class RiskRules {
    public int blockedFlowScore = 100;
    public int cleartextPortScore = 45;
    public int sensitivePortScore = 35;
    public int highRiskPortScore = 45;
    public int missingSniScore = 25;
    public int unknownApplicationScore = 10;
    public int outboundAsymmetryScore = 20;
    public int unusualDomainScore = 15;
    public int missingSniWithDnsScore = 10;
    public int suspiciousJa3Score = 40;
    public int deprecatedTlsScore = 15;
    public int dnsTunnelScore = 30;
    public int dnsTunnelLabelLength = 24;
    public double dnsTunnelEntropy = 3.5;
    public long dnsTunnelMinQueries = 20;
    public long outboundAsymmetryBytes = 100_000;
    public long outboundAsymmetryRatio = 20;
    public final Set<Integer> cleartextPorts = new HashSet<>(Set.of(23, 2323));
    public final Set<Integer> sensitivePorts = new HashSet<>(Set.of(445, 3389));
    public final Set<Integer> highRiskPorts = new HashSet<>(Set.of(4444, 1337, 31337));
    /** JA3 fingerprints (32 hex characters) that raise a finding when seen. */
    public final Set<String> suspiciousJa3 = new HashSet<>();

    public static RiskRules defaults() {
        return new RiskRules();
    }

    public static RiskRules load(String file) throws IOException {
        RiskRules rules = defaults();
        if (file == null || file.isBlank()) return rules;

        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(Path.of(file))) {
            properties.load(reader);
        }
        rules.blockedFlowScore = positive(properties, "blocked_flow_score", rules.blockedFlowScore);
        rules.cleartextPortScore = positive(properties, "cleartext_port_score", rules.cleartextPortScore);
        rules.sensitivePortScore = positive(properties, "sensitive_port_score", rules.sensitivePortScore);
        rules.highRiskPortScore = positive(properties, "high_risk_port_score", rules.highRiskPortScore);
        rules.missingSniScore = positive(properties, "missing_sni_score", rules.missingSniScore);
        rules.unknownApplicationScore = positive(properties, "unknown_application_score", rules.unknownApplicationScore);
        rules.outboundAsymmetryScore = positive(properties, "outbound_asymmetry_score", rules.outboundAsymmetryScore);
        rules.unusualDomainScore = positive(properties, "unusual_domain_score", rules.unusualDomainScore);
        rules.missingSniWithDnsScore = positive(properties, "missing_sni_with_dns_score", rules.missingSniWithDnsScore);
        rules.suspiciousJa3Score = positive(properties, "suspicious_ja3_score", rules.suspiciousJa3Score);
        rules.deprecatedTlsScore = positive(properties, "deprecated_tls_score", rules.deprecatedTlsScore);
        rules.dnsTunnelScore = positive(properties, "dns_tunnel_score", rules.dnsTunnelScore);
        rules.dnsTunnelLabelLength = (int) positiveLong(properties, "dns_tunnel_label_length", rules.dnsTunnelLabelLength);
        rules.dnsTunnelEntropy = positiveDouble(properties, "dns_tunnel_entropy", rules.dnsTunnelEntropy);
        rules.dnsTunnelMinQueries = positiveLong(properties, "dns_tunnel_min_queries", rules.dnsTunnelMinQueries);
        replaceJa3(rules.suspiciousJa3, properties, "suspicious_ja3");
        rules.outboundAsymmetryBytes = positiveLong(properties, "outbound_asymmetry_bytes", rules.outboundAsymmetryBytes);
        rules.outboundAsymmetryRatio = positiveLong(properties, "outbound_asymmetry_ratio", rules.outboundAsymmetryRatio);
        replacePorts(rules.cleartextPorts, properties, "cleartext_ports");
        replacePorts(rules.sensitivePorts, properties, "sensitive_ports");
        replacePorts(rules.highRiskPorts, properties, "high_risk_ports");
        return rules;
    }

    private static int positive(Properties p, String key, int fallback) {
        String value = p.getProperty(key);
        if (value == null) return fallback;
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 0 || parsed > 100) throw new IllegalArgumentException();
            return parsed;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid risk rule '" + key + "': " + value, e);
        }
    }

    private static long positiveLong(Properties p, String key, long fallback) {
        String value = p.getProperty(key);
        if (value == null) return fallback;
        try {
            long parsed = Long.parseLong(value.trim());
            if (parsed <= 0) throw new IllegalArgumentException();
            return parsed;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid risk rule '" + key + "': " + value, e);
        }
    }

    private static double positiveDouble(Properties p, String key, double fallback) {
        String value = p.getProperty(key);
        if (value == null) return fallback;
        try {
            double parsed = Double.parseDouble(value.trim());
            if (!(parsed > 0.0) || parsed > 8.0) throw new IllegalArgumentException();
            return parsed;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid risk rule '" + key + "': " + value, e);
        }
    }

    private static void replaceJa3(Set<String> target, Properties p, String key) {
        String value = p.getProperty(key);
        if (value == null || value.isBlank()) return;
        Set<String> parsed = new HashSet<>();
        for (String token : value.split(",")) {
            String hash = token.trim().toLowerCase(Locale.ROOT);
            if (!hash.matches("[0-9a-f]{32}")) {
                throw new IllegalArgumentException("Invalid JA3 in risk rule '" + key + "': " + token);
            }
            parsed.add(hash);
        }
        target.clear();
        target.addAll(parsed);
    }

    private static void replacePorts(Set<Integer> target, Properties p, String key) {
        String value = p.getProperty(key);
        if (value == null) return;
        Set<Integer> parsed = new HashSet<>();
        for (String token : value.split(",")) {
            try {
                int port = Integer.parseInt(token.trim());
                if (port < 1 || port > 65535) throw new IllegalArgumentException();
                parsed.add(port);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("Invalid port in risk rule '" + key + "': " + token, e);
            }
        }
        target.clear();
        target.addAll(parsed);
    }
}
