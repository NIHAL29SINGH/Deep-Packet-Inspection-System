package com.deeppacket.dpi;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class DNSExtractor {
    /** The name that was asked about and the IPv4 addresses a response gave for it. */
    public record Answer(String name, List<Integer> addresses) {}

    private static final int MAX_RECORDS = 32;

    private DNSExtractor() {}

    /**
     * Parses a DNS response and returns the question name with its IPv4 (A record) answers. CNAME chains are
     * followed implicitly: the addresses are attributed to the name the client asked for.
     */
    public static Optional<Answer> extractAnswer(byte[] p, int length) {
        try {
            if (p == null || length < 12 || (p[2] & 0x80) == 0) return Optional.empty(); // not a response
            if ((p[3] & 0x0F) != 0) return Optional.empty();                              // error response
            int qd = u16(p, 4);
            int an = Math.min(u16(p, 6), MAX_RECORDS);
            if (qd < 1 || an < 1) return Optional.empty();

            StringBuilder name = new StringBuilder();
            int pos = readName(p, 12, length, name);
            if (pos < 0 || pos + 4 > length) return Optional.empty();
            pos += 4; // type + class
            for (int skipped = 1; skipped < qd; skipped++) {
                pos = readName(p, pos, length, null);
                if (pos < 0 || pos + 4 > length) return Optional.empty();
                pos += 4;
            }

            List<Integer> addresses = new ArrayList<>();
            for (int i = 0; i < an && pos < length; i++) {
                pos = readName(p, pos, length, null);
                if (pos < 0 || pos + 10 > length) break;
                int type = u16(p, pos);
                int cls = u16(p, pos + 2);
                int rdLength = u16(p, pos + 8);
                pos += 10;
                if (pos + rdLength > length) break;
                if (type == 1 && cls == 1 && rdLength == 4) {
                    addresses.add(((p[pos] & 0xFF) << 24) | ((p[pos + 1] & 0xFF) << 16)
                        | ((p[pos + 2] & 0xFF) << 8) | (p[pos + 3] & 0xFF));
                }
                pos += rdLength;
            }
            String asked = name.toString();
            if (addresses.isEmpty() || !HostnameValidator.isPlausibleHostname(asked)) return Optional.empty();
            return Optional.of(new Answer(asked, addresses));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** Reads a (possibly compressed) name starting at pos; returns the position after it, or -1 if malformed. */
    private static int readName(byte[] p, int pos, int length, StringBuilder out) {
        int steps = 0;
        while (pos < length && steps++ < 128) {
            int len = p[pos] & 0xFF;
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2 <= length ? pos + 2 : -1; // pointer ends the name
            if (len > 63 || pos + 1 + len > length) return -1;
            if (out != null) {
                if (out.length() > 0) out.append('.');
                out.append(new String(p, pos + 1, len, StandardCharsets.US_ASCII));
            }
            pos += 1 + len;
        }
        return -1;
    }

    private static int u16(byte[] p, int off) {
        return ((p[off] & 0xFF) << 8) | (p[off + 1] & 0xFF);
    }

    public static boolean isDnsQuery(byte[] payload, int length) {
        if (payload == null || length < 12) return false;
        int flags = payload[2] & 0xFF;
        if ((flags & 0x80) != 0) return false;
        int qd = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
        return qd > 0;
    }

    public static Optional<String> extractQuery(byte[] payload, int length) {
        if (!isDnsQuery(payload, length)) return Optional.empty();
        int offset = 12;
        StringBuilder out = new StringBuilder();
        while (offset < length) {
            int labelLen = payload[offset] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63 || offset + 1 + labelLen > length) break;
            if (out.length() > 0) out.append('.');
            out.append(new String(payload, offset + 1, labelLen, StandardCharsets.US_ASCII));
            offset += 1 + labelLen;
        }
        String name = out.toString();
        return HostnameValidator.isPlausibleHostname(name) ? Optional.of(name) : Optional.empty();
    }
}
