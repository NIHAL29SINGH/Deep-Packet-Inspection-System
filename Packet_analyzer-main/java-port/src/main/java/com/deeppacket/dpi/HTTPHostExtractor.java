package com.deeppacket.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public final class HTTPHostExtractor {
    private HTTPHostExtractor() {}

    public static boolean isHttpRequest(byte[] payload, int length) {
        if (payload == null || length < 4) return false;
        String pfx = new String(payload, 0, 4, StandardCharsets.US_ASCII);
        return pfx.equals("GET ") || pfx.equals("POST") || pfx.equals("PUT ") ||
               pfx.equals("HEAD") || pfx.equals("DELE") || pfx.equals("PATC") || pfx.equals("OPTI");
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isHttpRequest(payload, length)) return Optional.empty();
        for (int i = 0; i + 5 < length; i++) {
            // The Host header must begin a header line, not appear inside the URL or another value.
            if (i > 0 && payload[i - 1] == '\n' &&
                eqIgnore(payload[i], 'h') &&
                eqIgnore(payload[i + 1], 'o') &&
                eqIgnore(payload[i + 2], 's') &&
                eqIgnore(payload[i + 3], 't') &&
                payload[i + 4] == ':') {
                int start = i + 5;
                while (start < length && (payload[start] == ' ' || payload[start] == '\t')) start++;
                int end = start;
                while (end < length && payload[end] != '\r' && payload[end] != '\n') end++;
                if (end > start) {
                    String host = new String(payload, start, end - start, StandardCharsets.US_ASCII);
                    int colon = host.indexOf(':');
                    String name = (colon >= 0 ? host.substring(0, colon) : host).trim();
                    return HostnameValidator.isPlausibleHostname(name) ? Optional.of(name) : Optional.empty();
                }
            }
        }
        return Optional.empty();
    }

    private static boolean eqIgnore(byte b, char c) {
        return Character.toLowerCase((char) (b & 0xFF)) == c;
    }
}
