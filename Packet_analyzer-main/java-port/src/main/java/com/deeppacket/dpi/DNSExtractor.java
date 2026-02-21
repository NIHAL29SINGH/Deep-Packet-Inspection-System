package com.deeppacket.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public final class DNSExtractor {
    private DNSExtractor() {}

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
        return out.length() == 0 ? Optional.empty() : Optional.of(out.toString());
    }
}
