package com.deeppacket.dpi;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Heuristics for DNS names that look machine-generated or that carry data (DNS tunnelling, DGA malware).
 *
 * <p>These are triage signals with known false positives (hash-named CDN hosts, for example), so they feed an
 * explainable risk score and never block traffic on their own.
 */
public final class DnsHeuristics {
    private static final Set<String> SECOND_LEVEL_LABELS = Set.of("co", "com", "org", "net", "gov", "edu", "ac");

    private DnsHeuristics() {}

    /** Shannon entropy of the characters of s, in bits per character. */
    public static double entropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < s.length(); i++) counts.merge(s.charAt(i), 1, Integer::sum);
        double bits = 0.0;
        for (int c : counts.values()) {
            double p = (double) c / s.length();
            bits -= p * (Math.log(p) / Math.log(2));
        }
        return bits;
    }

    /**
     * True when some label is long, has no hyphen (real hostnames separate words with hyphens) and has
     * high character entropy, which is typical of encoded data such as base32 or hex payloads.
     */
    public static boolean looksMachineGenerated(String name, int minLabelLength, double minEntropy) {
        if (name == null || name.isEmpty()) return false;
        for (String label : name.toLowerCase(Locale.ROOT).split("\\.")) {
            if (label.length() >= minLabelLength && label.indexOf('-') < 0 && entropy(label) >= minEntropy) {
                return true;
            }
        }
        return false;
    }

    /** Approximate registered domain: the last two labels, or three under a common second-level such as co.uk. */
    public static String registeredDomain(String name) {
        if (name == null) return "";
        String[] labels = name.toLowerCase(Locale.ROOT).split("\\.");
        int n = labels.length;
        if (n <= 2) return String.join(".", labels);
        boolean compound = labels[n - 1].length() == 2 && SECOND_LEVEL_LABELS.contains(labels[n - 2]);
        int keep = compound ? 3 : 2;
        return String.join(".", java.util.Arrays.copyOfRange(labels, n - keep, n));
    }
}
