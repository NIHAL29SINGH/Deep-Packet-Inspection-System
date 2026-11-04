package com.deeppacket.dpi;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Reads the TLS ClientHello carried in QUIC client Initial packets (RFC 9000, RFC 9001, RFC 9369).
 *
 * <p>Initial packets are encrypted, but the keys derive from the <em>public</em> destination connection ID
 * and a fixed per-version salt, so any on-path observer can read them. {@link #decrypt} derives the keys,
 * removes header protection, decrypts the payload with AES-128-GCM and returns the CRYPTO frame fragments.
 * Modern clients split a large ClientHello over several Initial packets, so callers feed the fragments of
 * one flow into a {@link com.deeppacket.model.ReassemblyBuffer} until the message is complete.
 *
 * <p>Supported: QUIC version 1 and version 2. Not supported: drafts, Retry/0-RTT/Handshake packets.
 */
public final class QUICSNIExtractor {
    public static final int VERSION_1 = 0x00000001;
    public static final int VERSION_2 = 0x6b3343cf;
    /** Upper bound for a ClientHello we are willing to reassemble. */
    public static final int MAX_CLIENT_HELLO = 4096;

    private static final byte[] SALT_V1 = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static final byte[] SALT_V2 = hex("0dede3def700a6db819381be6e269dcbf9bd2ed9");
    private static final int MAX_CID_LENGTH = 20;
    private static final int TAG_LENGTH = 16;

    private QUICSNIExtractor() {}

    /** One CRYPTO frame's worth of handshake bytes at a given stream offset. */
    public record CryptoFragment(long offset, byte[] data) {}

    /** True for a long-header packet with the fixed bit set, a supported version, and type Initial. */
    public static boolean isQuicInitial(byte[] payload, int length) {
        if (payload == null || length < 7) return false;
        int first = payload[0] & 0xFF;
        if ((first & 0xC0) != 0xC0) return false; // long header + fixed bit
        int type = (first >> 4) & 0x03;
        int version = readInt(payload, 1);
        return (version == VERSION_1 && type == 0) || (version == VERSION_2 && type == 1);
    }

    /**
     * Convenience for a ClientHello that fits in a single Initial packet: returns the SNI if it is present in
     * the first contiguous bytes of the CRYPTO data.
     */
    public static Optional<String> extract(byte[] payload, int length) {
        return decrypt(payload, length).flatMap(fragments -> sniFromFragments(fragments));
    }

    /** Decrypts one Initial packet and returns its CRYPTO fragments (empty if it cannot be authenticated). */
    public static Optional<List<CryptoFragment>> decrypt(byte[] payload, int length) {
        if (!isQuicInitial(payload, length)) return Optional.empty();
        try {
            return decode(payload, length);
        } catch (GeneralSecurityException | RuntimeException e) {
            return Optional.empty(); // truncated, corrupt or not actually QUIC: never throw into the pipeline
        }
    }

    /** Parses the SNI out of a (possibly partial) ClientHello handshake message with no TLS record header. */
    public static Optional<String> sniFromHandshake(byte[] handshake, int length) {
        if (handshake == null || length < 4 || (handshake[0] & 0xFF) != 0x01) return Optional.empty();
        // Wrap the handshake message in a TLS record header so the regular SNI parser can read it.
        byte[] record = new byte[5 + length];
        record[0] = 0x16;
        record[1] = 0x03;
        record[2] = 0x01;
        record[3] = (byte) (length >> 8);
        record[4] = (byte) length;
        System.arraycopy(handshake, 0, record, 5, length);
        return SNIExtractor.extract(record, record.length);
    }

    /** Total size in bytes of the handshake message announced by its 4-byte header, or -1 if unknown. */
    public static int announcedLength(byte[] handshake, int available) {
        if (handshake == null || available < 4 || (handshake[0] & 0xFF) != 0x01) return -1;
        return 4 + (((handshake[1] & 0xFF) << 16) | ((handshake[2] & 0xFF) << 8) | (handshake[3] & 0xFF));
    }

    private static Optional<String> sniFromFragments(List<CryptoFragment> fragments) {
        byte[] data = new byte[MAX_CLIENT_HELLO];
        int highest = 0;
        for (CryptoFragment f : fragments) {
            if (f.offset() != 0 && f.offset() > MAX_CLIENT_HELLO) continue;
            if (f.offset() + f.data().length > MAX_CLIENT_HELLO) continue;
            System.arraycopy(f.data(), 0, data, (int) f.offset(), f.data().length);
            highest = Math.max(highest, (int) f.offset() + f.data().length);
        }
        // Only a gap-free prefix is meaningful; a single packet normally starts at offset 0.
        int prefix = 0;
        for (CryptoFragment f : fragments) {
            if (f.offset() == 0) prefix = Math.max(prefix, f.data().length);
        }
        return prefix == 0 ? Optional.empty() : sniFromHandshake(data, Math.min(prefix, highest));
    }

    private static Optional<List<CryptoFragment>> decode(byte[] p, int length) throws GeneralSecurityException {
        int version = readInt(p, 1);
        int pos = 5;
        int dcidLength = p[pos++] & 0xFF;
        if (dcidLength > MAX_CID_LENGTH || pos + dcidLength >= length) return Optional.empty();
        byte[] dcid = Arrays.copyOfRange(p, pos, pos + dcidLength);
        pos += dcidLength;

        int scidLength = p[pos++] & 0xFF;
        if (scidLength > MAX_CID_LENGTH) return Optional.empty();
        pos += scidLength;

        Varint token = readVarint(p, pos, length);
        if (token == null || token.value() > length) return Optional.empty();
        pos = token.next() + (int) token.value();
        Varint payloadLength = readVarint(p, pos, length);
        if (payloadLength == null) return Optional.empty();
        int pnOffset = payloadLength.next();
        long declared = payloadLength.value();
        if (declared < 4 + TAG_LENGTH || pnOffset + declared > length) return Optional.empty();
        int packetEnd = (int) (pnOffset + declared);
        if (pnOffset + 4 + 16 > packetEnd) return Optional.empty();

        // Key schedule (RFC 9001 section 5.2; RFC 9369 changes the salt and the label prefix for v2).
        boolean v2 = version == VERSION_2;
        String prefix = v2 ? "quicv2 " : "quic ";
        byte[] initialSecret = hmac(v2 ? SALT_V2 : SALT_V1, dcid);
        byte[] clientSecret = expandLabel(initialSecret, "client in", 32);
        byte[] key = expandLabel(clientSecret, prefix + "key", 16);
        byte[] iv = expandLabel(clientSecret, prefix + "iv", 12);
        byte[] hp = expandLabel(clientSecret, prefix + "hp", 16);

        // Header protection removal (RFC 9001 section 5.4).
        byte[] sample = Arrays.copyOfRange(p, pnOffset + 4, pnOffset + 4 + 16);
        Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hp, "AES"));
        byte[] mask = ecb.doFinal(sample);
        int firstByte = (p[0] & 0xFF) ^ (mask[0] & 0x0F);
        int pnLength = (firstByte & 0x03) + 1;
        if (pnOffset + pnLength > packetEnd) return Optional.empty();

        byte[] header = Arrays.copyOfRange(p, 0, pnOffset + pnLength);
        header[0] = (byte) firstByte;
        long packetNumber = 0;
        for (int i = 0; i < pnLength; i++) {
            header[pnOffset + i] = (byte) (p[pnOffset + i] ^ mask[1 + i]);
            packetNumber = (packetNumber << 8) | (header[pnOffset + i] & 0xFF);
        }

        // AEAD decryption (RFC 9001 section 5.3).
        byte[] nonce = iv.clone();
        for (int i = 0; i < 8; i++) {
            nonce[nonce.length - 1 - i] ^= (byte) (packetNumber >>> (8 * i));
        }
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        gcm.updateAAD(header);
        int cipherStart = pnOffset + pnLength;
        byte[] plaintext = gcm.doFinal(p, cipherStart, packetEnd - cipherStart);

        List<CryptoFragment> fragments = collectCryptoFragments(plaintext);
        return fragments.isEmpty() ? Optional.empty() : Optional.of(fragments);
    }

    /** Walks the frames of a decrypted Initial packet and returns its CRYPTO frames. */
    private static List<CryptoFragment> collectCryptoFragments(byte[] frames) {
        List<CryptoFragment> out = new ArrayList<>();
        int pos = 0;
        while (pos < frames.length) {
            int type = frames[pos] & 0xFF;
            if (type == 0x00 || type == 0x01) { // PADDING, PING
                pos++;
                continue;
            }
            if (type != 0x06) break;            // anything else (ACK etc.): stop, keep what we have
            Varint offset = readVarint(frames, pos + 1, frames.length);
            if (offset == null) break;
            Varint len = readVarint(frames, offset.next(), frames.length);
            if (len == null) break;
            int dataStart = len.next();
            if (dataStart + len.value() > frames.length) break;
            if (offset.value() + len.value() > MAX_CLIENT_HELLO) break;
            out.add(new CryptoFragment(offset.value(),
                Arrays.copyOfRange(frames, dataStart, dataStart + (int) len.value())));
            pos = dataStart + (int) len.value();
        }
        return out;
    }

    private record Varint(long value, int next) {}

    /** Reads a QUIC variable-length integer (RFC 9000 section 16); null if it runs past the limit. */
    private static Varint readVarint(byte[] data, int pos, int limit) {
        if (pos < 0 || pos >= limit) return null;
        int size = 1 << ((data[pos] & 0xFF) >> 6);
        if (pos + size > limit) return null;
        long value = data[pos] & 0x3F;
        for (int i = 1; i < size; i++) value = (value << 8) | (data[pos + i] & 0xFF);
        return new Varint(value, pos + size);
    }

    // ------------------------------------------------------------ crypto helpers

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    /** HKDF-Expand-Label with an empty context and output length <= 32 (one HMAC block). */
    static byte[] expandLabel(byte[] secret, String label, int length) throws GeneralSecurityException {
        byte[] full = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[2 + 1 + full.length + 1];
        info[0] = (byte) (length >> 8);
        info[1] = (byte) length;
        info[2] = (byte) full.length;
        System.arraycopy(full, 0, info, 3, full.length);
        // trailing byte is the zero-length context
        byte[] input = Arrays.copyOf(info, info.length + 1);
        input[input.length - 1] = 0x01; // HKDF-Expand counter for T(1)
        return Arrays.copyOf(hmac(secret, input), length);
    }

    static byte[] initialClientSecret(byte[] dcid) throws GeneralSecurityException {
        return initialClientSecret(VERSION_1, dcid);
    }

    static byte[] initialClientSecret(int version, byte[] dcid) throws GeneralSecurityException {
        return expandLabel(hmac(version == VERSION_2 ? SALT_V2 : SALT_V1, dcid), "client in", 32);
    }

    private static int readInt(byte[] d, int off) {
        return ((d[off] & 0xFF) << 24) | ((d[off + 1] & 0xFF) << 16) | ((d[off + 2] & 0xFF) << 8) | (d[off + 3] & 0xFF);
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }
}
