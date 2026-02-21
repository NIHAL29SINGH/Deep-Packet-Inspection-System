package com.deeppacket.pcap;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;

public class PcapWriter implements Closeable {
    private OutputStream out;
    private PcapGlobalHeader header;

    public void open(String filename, PcapGlobalHeader header) throws IOException {
        close();
        this.out = Files.newOutputStream(Path.of(filename));
        this.header = header;
        writeGlobalHeader(header);
    }

    public synchronized void writePacket(PcapPacketHeader pktHeader, byte[] data) throws IOException {
        if (out == null) throw new IOException("Writer not open");
        ByteBuffer hb = ByteBuffer.allocate(16).order(header.byteOrder);
        hb.putInt((int) pktHeader.tsSec);
        hb.putInt((int) pktHeader.tsUsec);
        hb.putInt(data.length);
        hb.putInt(data.length);
        out.write(hb.array());
        out.write(data);
    }

    private void writeGlobalHeader(PcapGlobalHeader h) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(24).order(h.byteOrder);
        bb.putInt(h.magicNumber);
        bb.putShort((short) h.versionMajor);
        bb.putShort((short) h.versionMinor);
        bb.putInt(h.thisZone);
        bb.putInt((int) h.sigFigs);
        bb.putInt((int) h.snapLen);
        bb.putInt((int) h.network);
        out.write(bb.array());
    }

    @Override
    public void close() throws IOException {
        if (out != null) {
            out.close();
            out = null;
        }
    }
}
