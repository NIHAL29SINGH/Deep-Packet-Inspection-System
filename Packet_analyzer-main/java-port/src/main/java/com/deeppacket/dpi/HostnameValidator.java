package com.deeppacket.dpi;

/**
 * Validates hostnames taken from untrusted packets (TLS SNI, HTTP Host, DNS QNAME).
 *
 * <p>Extracted names flow into HTML, JSON, CSV and Prometheus output and into blocking rules, so
 * anything that is not a plausible hostname is rejected at the source rather than escaped later.
 */
public final class HostnameValidator {
    public static final int MAX_HOSTNAME_LENGTH = 253;
    public static final int MAX_LABEL_LENGTH = 63;

    private HostnameValidator() {}

    public static boolean isPlausibleHostname(String host) {
        if (host == null || host.isEmpty() || host.length() > MAX_HOSTNAME_LENGTH) return false;
        int labelLength = 0;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == '.') {
                if (labelLength == 0 && i != host.length() - 1) return false; // empty label
                labelLength = 0;
                continue;
            }
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '-' || c == '_' || c == '*';
            if (!ok) return false;
            if (++labelLength > MAX_LABEL_LENGTH) return false;
        }
        return host.charAt(0) != '.';
    }
}
