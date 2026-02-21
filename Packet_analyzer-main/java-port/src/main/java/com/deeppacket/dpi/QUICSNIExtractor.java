package com.deeppacket.dpi;

import java.util.Optional;

public final class QUICSNIExtractor {
    private QUICSNIExtractor() {}

    public static boolean isQuicInitial(byte[] payload, int length) {
        if (payload == null || length < 5) return false;
        return (payload[0] & 0x80) != 0;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isQuicInitial(payload, length)) return Optional.empty();
        for (int i = 0; i + 60 < length; i++) {
            if ((payload[i] & 0xFF) == 0x01) {
                int start = Math.max(0, i - 5);
                int len = length - start;
                Optional<String> sni = SNIExtractor.extract(slice(payload, start, len), len);
                if (sni.isPresent()) return sni;
            }
        }
        return Optional.empty();
    }

    private static byte[] slice(byte[] src, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }
}
