package com.deeppacket.pcap;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PcapFormatTest {
    @Test
    void readsNanosecondCapturesAsMicroseconds() throws Exception {
        byte[] file = capture(0xa1b23c4d, ByteOrder.LITTLE_ENDIAN, 1, 2_500_000, new byte[]{1, 2, 3});
        Path path = Files.createTempFile("dpi-ns", ".pcap");
        try {
            Files.write(path, file);
            try (PcapReader reader = new PcapReader()) {
                reader.open(path.toString());
                assertEquals(0xa1b2c3d4, reader.getGlobalHeader().magicNumber);
                RawPacket packet = reader.readNextPacket().orElseThrow();
                assertEquals(1, packet.header.tsSec);
                assertEquals(2_500, packet.header.tsUsec);
                assertEquals(3, packet.data.length);
            }
        } finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    void readsBigEndianMicrosecondCaptures() throws Exception {
        byte[] file = capture(0xa1b2c3d4, ByteOrder.BIG_ENDIAN, 7, 123, new byte[]{9});
        Path path = Files.createTempFile("dpi-be", ".pcap");
        try {
            Files.write(path, file);
            try (PcapReader reader = new PcapReader()) {
                reader.open(path.toString());
                RawPacket packet = reader.readNextPacket().orElseThrow();
                assertEquals(7, packet.header.tsSec);
                assertEquals(123, packet.header.tsUsec);
            }
        } finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    void rejectsNonEthernetLinkTypes() throws Exception {
        byte[] file = capture(0xa1b2c3d4, ByteOrder.LITTLE_ENDIAN, 0, 0, new byte[]{1});
        ByteBuffer.wrap(file).order(ByteOrder.LITTLE_ENDIAN).putInt(20, 113); // LINKTYPE_LINUX_SLL
        Path path = Files.createTempFile("dpi-sll", ".pcap");
        try {
            Files.write(path, file);
            IOException e = assertThrowsIo(path);
            assertTrue(e.getMessage().contains("link type"));
        } finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    void corruptPcapngHeaderIsRejectedWithAClearMessage() throws Exception {
        byte[] file = new byte[64];
        file[0] = 0x0a; file[1] = 0x0d; file[2] = 0x0d; file[3] = 0x0a;
        Path path = Files.createTempFile("dpi-ng", ".pcapng");
        try {
            Files.write(path, file);
            IOException e = assertThrowsIo(path);
            assertTrue(e.getMessage().contains("pcapng"));
        } finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    void writerOutputIsReadableByReader() throws Exception {
        Path path = Files.createTempFile("dpi-roundtrip", ".pcap");
        try {
            PcapGlobalHeader header = new PcapGlobalHeader();
            header.magicNumber = 0xa1b2c3d4;
            header.versionMajor = 2;
            header.versionMinor = 4;
            header.snapLen = 65535;
            header.network = 1;
            header.byteOrder = ByteOrder.LITTLE_ENDIAN;
            try (PcapWriter writer = new PcapWriter()) {
                writer.open(path.toString(), header);
                PcapPacketHeader h = new PcapPacketHeader();
                h.tsSec = 42;
                h.tsUsec = 7;
                writer.writePacket(h, new byte[]{5, 6, 7, 8});
            }
            try (PcapReader reader = new PcapReader()) {
                reader.open(path.toString());
                RawPacket packet = reader.readNextPacket().orElseThrow();
                assertEquals(42, packet.header.tsSec);
                assertEquals(4, packet.data.length);
                assertTrue(reader.readNextPacket().isEmpty());
            }
        } finally {
            Files.deleteIfExists(path);
        }
    }

    private static IOException assertThrowsIo(Path path) {
        try (PcapReader reader = new PcapReader()) {
            reader.open(path.toString());
        } catch (IOException e) {
            return e;
        }
        throw new AssertionError("expected IOException");
    }

    private static byte[] capture(int magic, ByteOrder order, int sec, int fraction, byte[] data) {
        ByteBuffer b = ByteBuffer.allocate(24 + 16 + data.length).order(order);
        b.putInt(magic).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0).putInt(65535).putInt(1);
        b.putInt(sec).putInt(fraction).putInt(data.length).putInt(data.length).put(data);
        return b.array();
    }
}
