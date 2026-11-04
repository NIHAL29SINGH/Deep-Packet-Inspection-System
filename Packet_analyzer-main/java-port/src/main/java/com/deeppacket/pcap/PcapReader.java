package com.deeppacket.pcap;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Reads packet captures: classic pcap (microsecond or nanosecond, either byte order) and pcapng.
 *
 * <p>Every length read from the file is validated before it is used, so a hostile or corrupt capture
 * produces an {@link IOException} rather than an out-of-memory error or an endless loop. Only Ethernet
 * link types are supported; packets are always returned with microsecond timestamps.
 */
public class PcapReader implements Closeable {
    public static final long LINKTYPE_ETHERNET = 1;

    private static final int MAX_CLASSIC_PACKET = 65535;
    private static final int MAX_NG_PACKET = 262_144;
    private static final int MAX_NG_BLOCK = 16 * 1024 * 1024;
    private static final int BLOCK_SHB = 0x0A0D0D0A;
    private static final int BLOCK_IDB = 1;
    private static final int BLOCK_SPB = 3;
    private static final int BLOCK_EPB = 6;
    private static final int BYTE_ORDER_MAGIC = 0x1A2B3C4D;
    private static final int OPT_IF_TSRESOL = 9;
    private static final int BUFFER_BYTES = 1 << 16;

    private record NgInterface(long linkType, long unitsPerSecond) {}

    private InputStream in;
    private PcapGlobalHeader globalHeader;

    // pcapng state
    private boolean pcapng;
    private ByteOrder ngOrder = ByteOrder.LITTLE_ENDIAN;
    private final List<NgInterface> interfaces = new ArrayList<>();
    private long ethernetPackets;
    private long skippedNonEthernet;

    public void open(String filename) throws IOException {
        close();
        pcapng = false;
        interfaces.clear();
        ethernetPackets = 0;
        skippedNonEthernet = 0;
        in = new BufferedInputStream(Files.newInputStream(Path.of(filename)), BUFFER_BYTES);
        try {
            in.mark(8);
            byte[] magic = readExact(in, 4, true);
            in.reset();
            if (isPcapngMagic(magic)) {
                pcapng = true;
                globalHeader = syntheticHeader();
                readSectionHeader();
            } else {
                globalHeader = readGlobalHeader(in);
            }
        } catch (IOException | RuntimeException e) {
            close();
            throw e;
        }
    }

    public boolean isOpen() {
        return in != null;
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean isPcapng() {
        return pcapng;
    }

    /** Packets skipped because they came from a non-Ethernet pcapng interface. */
    public long getSkippedNonEthernet() {
        return skippedNonEthernet;
    }

    public Optional<RawPacket> readNextPacket() throws IOException {
        if (in == null) return Optional.empty();
        return pcapng ? readNextPcapng() : readNextClassic();
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
            in = null;
        }
    }

    // ------------------------------------------------------------ classic pcap

    private Optional<RawPacket> readNextClassic() throws IOException {
        byte[] headerBytes = readExact(in, 16, false);
        if (headerBytes == null) return Optional.empty();

        ByteBuffer hb = ByteBuffer.wrap(headerBytes).order(globalHeader.byteOrder);
        RawPacket packet = new RawPacket();
        packet.header.tsSec = Integer.toUnsignedLong(hb.getInt());
        long fraction = Integer.toUnsignedLong(hb.getInt());
        packet.header.tsUsec = globalHeader.nanosecondResolution ? fraction / 1000 : fraction;
        packet.header.inclLen = Integer.toUnsignedLong(hb.getInt());
        packet.header.origLen = Integer.toUnsignedLong(hb.getInt());

        if (packet.header.inclLen > globalHeader.snapLen || packet.header.inclLen > MAX_CLASSIC_PACKET) {
            throw new IOException("Invalid packet length: " + packet.header.inclLen);
        }

        packet.data = readExact(in, (int) packet.header.inclLen, true);
        return Optional.of(packet);
    }

    private static PcapGlobalHeader readGlobalHeader(InputStream in) throws IOException {
        byte[] h = readExact(in, 24, true);
        int b0 = h[0] & 0xFF;
        int b1 = h[1] & 0xFF;
        int b2 = h[2] & 0xFF;
        int b3 = h[3] & 0xFF;

        ByteOrder order;
        boolean nanos = false;
        if (b0 == 0xd4 && b1 == 0xc3 && b2 == 0xb2 && b3 == 0xa1) {
            order = ByteOrder.LITTLE_ENDIAN;
        } else if (b0 == 0xa1 && b1 == 0xb2 && b2 == 0xc3 && b3 == 0xd4) {
            order = ByteOrder.BIG_ENDIAN;
        } else if (b0 == 0x4d && b1 == 0x3c && b2 == 0xb2 && b3 == 0xa1) {
            order = ByteOrder.LITTLE_ENDIAN;
            nanos = true;
        } else if (b0 == 0xa1 && b1 == 0xb2 && b2 == 0x3c && b3 == 0x4d) {
            order = ByteOrder.BIG_ENDIAN;
            nanos = true;
        } else {
            throw new IOException("Invalid PCAP magic: " + String.format("%02x%02x%02x%02x", b0, b1, b2, b3));
        }

        ByteBuffer bb = ByteBuffer.wrap(h).order(order);
        PcapGlobalHeader gh = new PcapGlobalHeader();
        gh.magicNumber = bb.getInt();
        gh.versionMajor = bb.getShort() & 0xFFFF;
        gh.versionMinor = bb.getShort() & 0xFFFF;
        gh.thisZone = bb.getInt();
        gh.sigFigs = Integer.toUnsignedLong(bb.getInt());
        gh.snapLen = Integer.toUnsignedLong(bb.getInt());
        gh.network = Integer.toUnsignedLong(bb.getInt());
        gh.byteOrder = order;
        gh.nanosecondResolution = nanos;
        if (nanos) {
            // Normalise to the microsecond format so filtered output stays a standard pcap.
            gh.magicNumber = 0xa1b2c3d4;
        }
        if (gh.network != LINKTYPE_ETHERNET) {
            throw new IOException("Unsupported link type " + gh.network + "; only Ethernet (1) captures are supported");
        }
        return gh;
    }

    // ------------------------------------------------------------------ pcapng

    private static boolean isPcapngMagic(byte[] m) {
        return (m[0] & 0xFF) == 0x0a && (m[1] & 0xFF) == 0x0d && (m[2] & 0xFF) == 0x0d && (m[3] & 0xFF) == 0x0a;
    }

    /** The filtered output is always written as a standard microsecond pcap, whatever the input format. */
    private static PcapGlobalHeader syntheticHeader() {
        PcapGlobalHeader gh = new PcapGlobalHeader();
        gh.magicNumber = 0xa1b2c3d4;
        gh.versionMajor = 2;
        gh.versionMinor = 4;
        gh.snapLen = MAX_NG_PACKET;
        gh.network = LINKTYPE_ETHERNET;
        gh.byteOrder = ByteOrder.LITTLE_ENDIAN;
        return gh;
    }

    /** Reads a Section Header Block, which also fixes the byte order for the section that follows. */
    private void readSectionHeader() throws IOException {
        byte[] first = readExact(in, 12, true); // type, length, byte-order magic
        ByteBuffer raw = ByteBuffer.wrap(first);
        int bom = raw.order(ByteOrder.LITTLE_ENDIAN).getInt(8);
        if (bom == BYTE_ORDER_MAGIC) {
            ngOrder = ByteOrder.LITTLE_ENDIAN;
        } else if (Integer.reverseBytes(bom) == BYTE_ORDER_MAGIC) {
            ngOrder = ByteOrder.BIG_ENDIAN;
        } else {
            throw new IOException("Invalid pcapng byte-order magic");
        }
        long total = Integer.toUnsignedLong(ByteBuffer.wrap(first).order(ngOrder).getInt(4));
        if (total < 28 || total > MAX_NG_BLOCK) throw new IOException("Invalid pcapng section header length: " + total);
        skipFully(in, total - 12);
        interfaces.clear(); // interface ids restart in every section
    }

    private Optional<RawPacket> readNextPcapng() throws IOException {
        while (true) {
            byte[] head = readExact(in, 8, false);
            if (head == null) {
                if (ethernetPackets == 0 && skippedNonEthernet > 0) {
                    throw new IOException("pcapng capture has no Ethernet interface; only Ethernet (link type 1) is supported");
                }
                return Optional.empty();
            }
            int type = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
            if (type == BLOCK_SHB) {
                // A new section may use a different byte order, so re-read the header from its start.
                byte[] bomBytes = readExact(in, 4, true);
                ByteBuffer bomBuf = ByteBuffer.wrap(bomBytes).order(ByteOrder.LITTLE_ENDIAN);
                int bom = bomBuf.getInt(0);
                if (bom == BYTE_ORDER_MAGIC) ngOrder = ByteOrder.LITTLE_ENDIAN;
                else if (Integer.reverseBytes(bom) == BYTE_ORDER_MAGIC) ngOrder = ByteOrder.BIG_ENDIAN;
                else throw new IOException("Invalid pcapng byte-order magic");
                long total = Integer.toUnsignedLong(ByteBuffer.wrap(head).order(ngOrder).getInt(4));
                if (total < 28 || total > MAX_NG_BLOCK) throw new IOException("Invalid pcapng section header length: " + total);
                skipFully(in, total - 12);
                interfaces.clear();
                continue;
            }

            ByteBuffer hb = ByteBuffer.wrap(head).order(ngOrder);
            long total = Integer.toUnsignedLong(hb.getInt(4));
            if (total < 12 || total > MAX_NG_BLOCK) throw new IOException("Invalid pcapng block length: " + total);
            byte[] body = readExact(in, (int) total - 12, true);
            byte[] trailer = readExact(in, 4, true);
            if (Integer.toUnsignedLong(ByteBuffer.wrap(trailer).order(ngOrder).getInt(0)) != total) {
                throw new IOException("pcapng block length mismatch (corrupt file)");
            }
            ByteBuffer b = ByteBuffer.wrap(body).order(ngOrder);

            switch (hb.getInt(0)) {
                case BLOCK_IDB -> parseInterface(b);
                case BLOCK_EPB -> {
                    Optional<RawPacket> packet = parseEnhancedPacket(b);
                    if (packet.isPresent()) return packet;
                }
                case BLOCK_SPB -> {
                    Optional<RawPacket> packet = parseSimplePacket(b);
                    if (packet.isPresent()) return packet;
                }
                default -> { /* name resolution, statistics, comments, custom blocks: not needed */ }
            }
        }
    }

    private void parseInterface(ByteBuffer b) throws IOException {
        if (b.remaining() < 8) throw new IOException("Truncated pcapng interface block");
        long linkType = b.getShort() & 0xFFFF;
        b.getShort(); // reserved
        b.getInt();   // snap length
        long units = 1_000_000L; // default resolution: microseconds
        while (b.remaining() >= 4) {
            int code = b.getShort() & 0xFFFF;
            int length = b.getShort() & 0xFFFF;
            if (code == 0) break;
            if (length > b.remaining()) throw new IOException("Truncated pcapng option");
            if (code == OPT_IF_TSRESOL && length >= 1) {
                units = unitsPerSecond(b.get(b.position()));
            }
            int padded = (length + 3) & ~3;
            b.position(b.position() + Math.min(padded, b.remaining()));
        }
        interfaces.add(new NgInterface(linkType, units));
    }

    private static long unitsPerSecond(byte resolution) {
        int v = resolution & 0xFF;
        if ((v & 0x80) == 0) {
            if (v > 18) return 1_000_000L; // out of range: fall back to the default
            long u = 1;
            for (int i = 0; i < v; i++) u *= 10;
            return u;
        }
        int exp = v & 0x7F;
        return exp > 62 ? 1_000_000L : 1L << exp;
    }

    private Optional<RawPacket> parseEnhancedPacket(ByteBuffer b) throws IOException {
        if (b.remaining() < 20) throw new IOException("Truncated pcapng packet block");
        long interfaceId = Integer.toUnsignedLong(b.getInt());
        long high = Integer.toUnsignedLong(b.getInt());
        long low = Integer.toUnsignedLong(b.getInt());
        long captured = Integer.toUnsignedLong(b.getInt());
        long original = Integer.toUnsignedLong(b.getInt());
        if (interfaceId >= interfaces.size()) throw new IOException("pcapng packet refers to unknown interface " + interfaceId);
        if (captured > MAX_NG_PACKET || captured > b.remaining()) throw new IOException("Invalid pcapng packet length: " + captured);
        NgInterface iface = interfaces.get((int) interfaceId);
        byte[] data = new byte[(int) captured];
        b.get(data);
        if (iface.linkType() != LINKTYPE_ETHERNET) {
            skippedNonEthernet++;
            return Optional.empty();
        }
        ethernetPackets++;
        RawPacket packet = new RawPacket();
        long ticks = (high << 32) | low;
        long units = iface.unitsPerSecond();
        packet.header.tsSec = Long.divideUnsigned(ticks, units);
        long remainder = Long.remainderUnsigned(ticks, units);
        packet.header.tsUsec = units <= 4_000_000_000_000L
            ? remainder * 1_000_000L / units
            : BigInteger.valueOf(remainder).multiply(BigInteger.valueOf(1_000_000L)).divide(BigInteger.valueOf(units)).longValue();
        packet.header.inclLen = captured;
        packet.header.origLen = original;
        packet.data = data;
        return Optional.of(packet);
    }

    private Optional<RawPacket> parseSimplePacket(ByteBuffer b) throws IOException {
        if (b.remaining() < 4) throw new IOException("Truncated pcapng simple packet block");
        long original = Integer.toUnsignedLong(b.getInt());
        if (interfaces.isEmpty()) throw new IOException("pcapng simple packet before any interface description");
        if (interfaces.get(0).linkType() != LINKTYPE_ETHERNET) {
            skippedNonEthernet++;
            return Optional.empty();
        }
        int captured = (int) Math.min(Math.min(original, b.remaining()), MAX_NG_PACKET);
        byte[] data = new byte[captured];
        b.get(data);
        ethernetPackets++;
        RawPacket packet = new RawPacket(); // simple packets carry no timestamp
        packet.header.inclLen = captured;
        packet.header.origLen = original;
        packet.data = data;
        return Optional.of(packet);
    }

    // ----------------------------------------------------------------- helpers

    private static byte[] readExact(InputStream in, int len, boolean failOnEof) throws IOException {
        byte[] out = new byte[len];
        int read = 0;
        while (read < len) {
            int n = in.read(out, read, len - read);
            if (n < 0) {
                if (!failOnEof && read == 0) return null;
                throw new EOFException("Unexpected EOF");
            }
            read += n;
        }
        return out;
    }

    private static void skipFully(InputStream in, long count) throws IOException {
        long remaining = count;
        byte[] sink = new byte[4096];
        while (remaining > 0) {
            int n = in.read(sink, 0, (int) Math.min(sink.length, remaining));
            if (n < 0) throw new EOFException("Unexpected EOF");
            remaining -= n;
        }
    }
}
