package com.deeppacket.pcap;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class PcapReader implements Closeable {
    private InputStream in;
    private PcapGlobalHeader globalHeader;

    public void open(String filename) throws IOException {
        close();
        in = Files.newInputStream(Path.of(filename));
        globalHeader = readGlobalHeader(in);
    }

    public boolean isOpen() {
        return in != null;
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public Optional<RawPacket> readNextPacket() throws IOException {
        if (in == null) return Optional.empty();
        byte[] headerBytes = readExact(in, 16, false);
        if (headerBytes == null) return Optional.empty();

        ByteBuffer hb = ByteBuffer.wrap(headerBytes).order(globalHeader.byteOrder);
        RawPacket packet = new RawPacket();
        packet.header.tsSec = Integer.toUnsignedLong(hb.getInt());
        packet.header.tsUsec = Integer.toUnsignedLong(hb.getInt());
        packet.header.inclLen = Integer.toUnsignedLong(hb.getInt());
        packet.header.origLen = Integer.toUnsignedLong(hb.getInt());

        if (packet.header.inclLen > globalHeader.snapLen || packet.header.inclLen > 65535) {
            throw new IOException("Invalid packet length: " + packet.header.inclLen);
        }

        packet.data = readExact(in, (int) packet.header.inclLen, true);
        return Optional.of(packet);
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
            in = null;
        }
    }

    private static PcapGlobalHeader readGlobalHeader(InputStream in) throws IOException {
        byte[] h = readExact(in, 24, true);
        int b0 = h[0] & 0xFF;
        int b1 = h[1] & 0xFF;
        int b2 = h[2] & 0xFF;
        int b3 = h[3] & 0xFF;

        ByteOrder order;
        if (b0 == 0xd4 && b1 == 0xc3 && b2 == 0xb2 && b3 == 0xa1) {
            order = ByteOrder.LITTLE_ENDIAN;
        } else if (b0 == 0xa1 && b1 == 0xb2 && b2 == 0xc3 && b3 == 0xd4) {
            order = ByteOrder.BIG_ENDIAN;
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
        return gh;
    }

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
}
