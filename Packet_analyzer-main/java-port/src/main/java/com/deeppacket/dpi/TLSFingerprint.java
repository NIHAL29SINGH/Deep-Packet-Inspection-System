package com.deeppacket.dpi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * JA3 fingerprint of a TLS ClientHello.
 *
 * <p>JA3 identifies a TLS <em>client implementation</em> (a browser build, a scripting library, a piece of
 * malware) from the way it builds its hello, independently of the server name. The fingerprint is the MD5 of
 * {@code version,ciphers,extensions,groups,pointFormats}, each list written as dash-separated decimals,
 * with GREASE placeholder values (RFC 8701) removed. It is a triage signal, not proof of identity: any client
 * can imitate another's hello.
 */
public final class TLSFingerprint {
    /** The fingerprint, its source string, and the highest TLS version the client offers. */
    public record Result(String ja3String, String ja3, String tlsVersion) {}

    private static final int EXT_SUPPORTED_GROUPS = 10;
    private static final int EXT_EC_POINT_FORMATS = 11;
    private static final int EXT_SUPPORTED_VERSIONS = 43;

    private TLSFingerprint() {}

    public static Optional<Result> fromClientHello(byte[] record, int length) {
        try {
            return parse(record, length);
        } catch (RuntimeException e) {
            return Optional.empty(); // malformed hello: never throw into the pipeline
        }
    }

    private static Optional<Result> parse(byte[] d, int length) {
        if (d == null || length < 44 || !SNIExtractor.isTlsClientHello(d, length)) return Optional.empty();
        int recordEnd = Math.min(length, 5 + u16(d, 3));
        int p = 9;                       // handshake header ends here: type(1) length(3) after the 5-byte record header
        int clientVersion = u16(d, p);
        p += 2 + 32;                     // version + random
        if (p >= recordEnd) return Optional.empty();
        p += 1 + (d[p] & 0xFF);          // session id
        if (p + 2 > recordEnd) return Optional.empty();
        int cipherBytes = u16(d, p);
        p += 2;
        if (cipherBytes % 2 != 0 || p + cipherBytes > recordEnd) return Optional.empty();
        List<Integer> ciphers = new ArrayList<>();
        for (int i = 0; i < cipherBytes; i += 2) ciphers.add(u16(d, p + i));
        p += cipherBytes;
        if (p >= recordEnd) return Optional.empty();
        p += 1 + (d[p] & 0xFF);          // compression methods

        List<Integer> extensionTypes = new ArrayList<>();
        List<Integer> groups = new ArrayList<>();
        List<Integer> pointFormats = new ArrayList<>();
        List<Integer> versions = new ArrayList<>();
        if (p + 2 <= recordEnd) {
            int extensionsEnd = p + 2 + u16(d, p);
            p += 2;
            if (extensionsEnd > recordEnd) return Optional.empty(); // truncated: a partial hello gives a wrong JA3
            while (p + 4 <= extensionsEnd) {
                int type = u16(d, p);
                int len = u16(d, p + 2);
                int body = p + 4;
                if (body + len > extensionsEnd) return Optional.empty();
                extensionTypes.add(type);
                if (type == EXT_SUPPORTED_GROUPS && len >= 2) {
                    int n = Math.min(u16(d, body), len - 2);
                    for (int i = 0; i + 1 < n; i += 2) groups.add(u16(d, body + 2 + i));
                } else if (type == EXT_EC_POINT_FORMATS && len >= 1) {
                    int n = Math.min(d[body] & 0xFF, len - 1);
                    for (int i = 0; i < n; i++) pointFormats.add(d[body + 1 + i] & 0xFF);
                } else if (type == EXT_SUPPORTED_VERSIONS && len >= 1) {
                    int n = Math.min(d[body] & 0xFF, len - 1);
                    for (int i = 0; i + 1 < n; i += 2) versions.add(u16(d, body + 1 + i));
                }
                p = body + len;
            }
        }

        String ja3String = clientVersion + "," + join(ciphers, true) + "," + join(extensionTypes, true) + ","
            + join(groups, true) + "," + join(pointFormats, false);
        return Optional.of(new Result(ja3String, md5(ja3String), versionName(clientVersion, versions)));
    }

    /** GREASE values are 0x0A0A, 0x1A1A, ... 0xFAFA (both bytes equal, low nibble A). */
    static boolean isGrease(int v) {
        return (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF);
    }

    private static String join(List<Integer> values, boolean dropGrease) {
        StringBuilder sb = new StringBuilder();
        for (int v : values) {
            if (dropGrease && isGrease(v)) continue;
            if (sb.length() > 0) sb.append('-');
            sb.append(v);
        }
        return sb.toString();
    }

    private static String versionName(int clientVersion, List<Integer> offered) {
        int best = -1;
        for (int v : offered) if (!isGrease(v) && v > best) best = v;
        int shown = best >= 0 ? best : clientVersion;
        return switch (shown) {
            case 0x0304 -> "TLS 1.3";
            case 0x0303 -> "TLS 1.2";
            case 0x0302 -> "TLS 1.1";
            case 0x0301 -> "TLS 1.0";
            case 0x0300 -> "SSL 3.0";
            default -> String.format("0x%04x", shown);
        };
    }

    private static int u16(byte[] d, int off) {
        return ((d[off] & 0xFF) << 8) | (d[off + 1] & 0xFF);
    }

    static String md5(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("MD5").digest(text.getBytes(StandardCharsets.US_ASCII));
            StringBuilder sb = new StringBuilder(32);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 is required by the JA3 specification", e);
        }
    }
}
