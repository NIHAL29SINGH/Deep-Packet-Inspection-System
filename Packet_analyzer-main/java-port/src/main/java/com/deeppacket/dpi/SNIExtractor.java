package com.deeppacket.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public final class SNIExtractor {
    private SNIExtractor() {}

    public static boolean isTlsClientHello(byte[] payload, int length) {
        if (payload == null || length < 9) return false;
        if ((payload[0] & 0xFF) != 0x16) return false;
        int version = readU16(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;
        int recordLen = readU16(payload, 3);
        if (recordLen > length - 5) return false;
        return (payload[5] & 0xFF) == 0x01;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isTlsClientHello(payload, length)) return Optional.empty();

        int offset = 5 + 4 + 2 + 32; // tls header + handshake header + version + random
        if (offset >= length) return Optional.empty();

        int sessionLen = payload[offset] & 0xFF;
        offset += 1 + sessionLen;
        if (offset + 2 > length) return Optional.empty();

        int cipherLen = readU16(payload, offset);
        offset += 2 + cipherLen;
        if (offset >= length) return Optional.empty();

        int compLen = payload[offset] & 0xFF;
        offset += 1 + compLen;
        if (offset + 2 > length) return Optional.empty();

        int extLen = readU16(payload, offset);
        offset += 2;
        int extEnd = Math.min(length, offset + extLen);

        while (offset + 4 <= extEnd) {
            int extType = readU16(payload, offset);
            int oneLen = readU16(payload, offset + 2);
            offset += 4;
            if (offset + oneLen > extEnd) break;
            if (extType == 0x0000) {
                if (oneLen < 5) break;
                int sniType = payload[offset + 2] & 0xFF;
                int sniLen = readU16(payload, offset + 3);
                if (sniType != 0x00 || sniLen > oneLen - 5) break;
                return Optional.of(new String(payload, offset + 5, sniLen, StandardCharsets.US_ASCII));
            }
            offset += oneLen;
        }
        return Optional.empty();
    }

    private static int readU16(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }
}
