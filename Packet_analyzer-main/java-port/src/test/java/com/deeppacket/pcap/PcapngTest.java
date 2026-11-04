package com.deeppacket.pcap;

import com.deeppacket.engine.DPIEngine;
import com.deeppacket.model.Connection;
import com.deeppacket.testutil.PacketBuilder;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PcapngTest {
    private static final byte[] FRAME_A = {1, 2, 3, 4, 5};
    private static final byte[] FRAME_B = {9, 8, 7, 6, 5, 4, 3};

    // ------------------------------------------------------------ builders

    private static ByteBuffer le(int n) { return ByteBuffer.allocate(n).order(ByteOrder.LITTLE_ENDIAN); }

    private static byte[] block(ByteOrder order, int type, byte[] body) {
        int pad = (4 - body.length % 4) % 4;
        int total = 12 + body.length + pad;
        ByteBuffer b = ByteBuffer.allocate(total).order(order);
        b.putInt(type).putInt(total).put(body).put(new byte[pad]).putInt(total);
        return b.array();
    }

    private static byte[] shb(ByteOrder order) {
        ByteBuffer b = ByteBuffer.allocate(16).order(order);
        b.putInt(0x1A2B3C4D).putShort((short) 1).putShort((short) 0).putLong(-1L);
        return block(order, 0x0A0D0D0A, b.array());
    }

    private static byte[] idb(ByteOrder order, int linkType, Integer tsResol) {
        ByteBuffer b = ByteBuffer.allocate(24).order(order);
        b.putShort((short) linkType).putShort((short) 0).putInt(65535);
        if (tsResol != null) {
            b.putShort((short) 9).putShort((short) 1).put((byte) (int) tsResol).put(new byte[3]);
            b.putShort((short) 0).putShort((short) 0);
        }
        byte[] body = new byte[tsResol != null ? 20 : 8];
        System.arraycopy(b.array(), 0, body, 0, body.length);
        return block(order, 1, body);
    }

    private static byte[] epb(ByteOrder order, int iface, long ticks, byte[] data) {
        ByteBuffer b = ByteBuffer.allocate(20 + data.length).order(order);
        b.putInt(iface).putInt((int) (ticks >>> 32)).putInt((int) ticks).putInt(data.length).putInt(data.length).put(data);
        return block(order, 6, b.array());
    }

    private static byte[] spb(ByteOrder order, byte[] data) {
        ByteBuffer b = ByteBuffer.allocate(4 + data.length).order(order);
        b.putInt(data.length).put(data);
        return block(order, 3, b.array());
    }

    private static byte[] join(byte[]... parts) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.write(p);
        return out.toByteArray();
    }

    private static List<RawPacket> readAll(byte[] file) throws IOException {
        Path path = Files.createTempFile("dpi-ng", ".pcapng");
        try {
            Files.write(path, file);
            return readAll(path);
        } finally {
            Files.deleteIfExists(path);
        }
    }

    private static List<RawPacket> readAll(Path path) throws IOException {
        List<RawPacket> out = new ArrayList<>();
        try (PcapReader reader = new PcapReader()) {
            reader.open(path.toString());
            while (true) {
                var next = reader.readNextPacket();
                if (next.isEmpty()) break;
                out.add(next.get());
            }
        }
        return out;
    }

    // --------------------------------------------------------------- tests

    @Test
    void readsLittleEndianMicrosecondCapture() throws Exception {
        byte[] file = join(shb(ByteOrder.LITTLE_ENDIAN), idb(ByteOrder.LITTLE_ENDIAN, 1, null),
            epb(ByteOrder.LITTLE_ENDIAN, 0, 3_500_000L, FRAME_A), epb(ByteOrder.LITTLE_ENDIAN, 0, 7_000_123L, FRAME_B));
        List<RawPacket> packets = readAll(file);
        assertEquals(2, packets.size());
        assertEquals(3, packets.get(0).header.tsSec);
        assertEquals(500_000, packets.get(0).header.tsUsec);
        assertArrayEquals(FRAME_A, packets.get(0).data);
        assertEquals(7, packets.get(1).header.tsSec);
        assertEquals(123, packets.get(1).header.tsUsec);
        assertArrayEquals(FRAME_B, packets.get(1).data);
    }

    @Test
    void readsBigEndianCapture() throws Exception {
        ByteOrder be = ByteOrder.BIG_ENDIAN;
        byte[] file = join(shb(be), idb(be, 1, null), epb(be, 0, 2_000_001L, FRAME_A));
        List<RawPacket> packets = readAll(file);
        assertEquals(1, packets.size());
        assertEquals(2, packets.get(0).header.tsSec);
        assertEquals(1, packets.get(0).header.tsUsec);
    }

    @Test
    void honoursNanosecondAndPowerOfTwoResolutions() throws Exception {
        ByteOrder le = ByteOrder.LITTLE_ENDIAN;
        byte[] nanos = join(shb(le), idb(le, 1, 9), epb(le, 0, 5_250_000_000L, FRAME_A)); // 5.25 s
        RawPacket n = readAll(nanos).get(0);
        assertEquals(5, n.header.tsSec);
        assertEquals(250_000, n.header.tsUsec);

        byte[] binary = join(shb(le), idb(le, 1, 0x80 | 10), epb(le, 0, 1024L * 3 + 512, FRAME_A)); // 3.5 s in 1/1024 s
        RawPacket p = readAll(binary).get(0);
        assertEquals(3, p.header.tsSec);
        assertEquals(500_000, p.header.tsUsec);
    }

    @Test
    void readsSimplePacketsAndSkipsUnknownBlocks() throws Exception {
        ByteOrder le = ByteOrder.LITTLE_ENDIAN;
        byte[] file = join(shb(le), idb(le, 1, null),
            block(le, 5, new byte[16]),               // interface statistics: ignored
            block(le, 0x00000BAD, new byte[12]),      // unknown/custom block: ignored
            spb(le, FRAME_B));
        List<RawPacket> packets = readAll(file);
        assertEquals(1, packets.size());
        assertArrayEquals(FRAME_B, packets.get(0).data);
    }

    @Test
    void onlyEthernetInterfacesProducepackets() throws Exception {
        ByteOrder le = ByteOrder.LITTLE_ENDIAN;
        byte[] file = join(shb(le), idb(le, 113, null), idb(le, 1, null),
            epb(le, 0, 1, FRAME_A), epb(le, 1, 2, FRAME_B));
        Path path = Files.createTempFile("dpi-mixed", ".pcapng");
        try {
            Files.write(path, file);
            try (PcapReader reader = new PcapReader()) {
                reader.open(path.toString());
                assertTrue(reader.isPcapng());
                assertArrayEquals(FRAME_B, reader.readNextPacket().orElseThrow().data);
                assertTrue(reader.readNextPacket().isEmpty());
                assertEquals(1, reader.getSkippedNonEthernet());
            }
        } finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    void aCaptureWithNoEthernetInterfaceIsRejected() throws Exception {
        ByteOrder le = ByteOrder.LITTLE_ENDIAN;
        byte[] file = join(shb(le), idb(le, 113, null), epb(le, 0, 1, FRAME_A));
        IOException e = assertThrows(IOException.class, () -> readAll(file));
        assertTrue(e.getMessage().contains("Ethernet"));
    }

    @Test
    void aSecondSectionMayChangeByteOrderAndInterfaces() throws Exception {
        byte[] file = join(
            shb(ByteOrder.LITTLE_ENDIAN), idb(ByteOrder.LITTLE_ENDIAN, 1, null), epb(ByteOrder.LITTLE_ENDIAN, 0, 1_000_000L, FRAME_A),
            shb(ByteOrder.BIG_ENDIAN), idb(ByteOrder.BIG_ENDIAN, 1, null), epb(ByteOrder.BIG_ENDIAN, 0, 9_000_000L, FRAME_B));
        List<RawPacket> packets = readAll(file);
        assertEquals(2, packets.size());
        assertEquals(1, packets.get(0).header.tsSec);
        assertEquals(9, packets.get(1).header.tsSec);
        assertArrayEquals(FRAME_B, packets.get(1).data);
    }

    @Test
    void corruptStructuresFailCleanlyInsteadOfHangingOrCrashing() throws Exception {
        ByteOrder le = ByteOrder.LITTLE_ENDIAN;
        byte[] good = join(shb(le), idb(le, 1, null), epb(le, 0, 1, FRAME_A));

        byte[] truncated = java.util.Arrays.copyOf(good, good.length - 6);
        assertThrows(IOException.class, () -> readAll(truncated));

        byte[] mismatch = good.clone();
        mismatch[mismatch.length - 1] ^= 0x7f; // trailing block length no longer matches
        assertThrows(IOException.class, () -> readAll(mismatch));

        byte[] unknownInterface = join(shb(le), idb(le, 1, null), epb(le, 5, 1, FRAME_A));
        assertThrows(IOException.class, () -> readAll(unknownInterface));

        byte[] hugeBlock = join(shb(le), idb(le, 1, null));
        byte[] withHuge = java.util.Arrays.copyOf(hugeBlock, hugeBlock.length + 12);
        ByteBuffer.wrap(withHuge).order(le).putInt(hugeBlock.length, 6).putInt(hugeBlock.length + 4, 0x7fffff00);
        assertThrows(IOException.class, () -> readAll(withHuge));

        byte[] bigPacket = join(shb(le), idb(le, 1, null), epb(le, 0, 1, new byte[300_000]));
        assertThrows(IOException.class, () -> readAll(bigPacket));
    }

    @Test
    void pythonGeneratedPcapngMatchesTheClassicPcapOfTheSamePackets() throws Exception {
        List<RawPacket> classic = readAll(resource("/pcapng/tiny.pcap"));
        List<RawPacket> ng = readAll(resource("/pcapng/tiny.pcapng"));
        assertEquals(187, classic.size());
        assertEquals(classic.size(), ng.size());
        for (int i = 0; i < classic.size(); i++) {
            assertArrayEquals(classic.get(i).data, ng.get(i).data, "packet " + i);
            assertEquals(classic.get(i).header.tsSec, ng.get(i).header.tsSec, "tsSec " + i);
            assertEquals(classic.get(i).header.tsUsec, ng.get(i).header.tsUsec, "tsUsec " + i);
        }
    }

    @Test
    void engineProducesIdenticalFlowsForPcapAndPcapng() throws Exception {
        List<Connection> fromPcap = analyse("/pcapng/tiny.pcap");
        List<Connection> fromNg = analyse("/pcapng/tiny.pcapng");
        assertEquals(fromPcap.size(), fromNg.size());
        assertTrue(fromPcap.size() > 20);
        assertEquals(snapshot(fromPcap), snapshot(fromNg));
    }

    // ------------------------------------------------------------- helpers

    private static Path resource(String name) throws IOException {
        Path copy = Files.createTempFile("dpi-fixture", ".bin");
        try (InputStream in = PcapngTest.class.getResourceAsStream(name)) {
            assertNotNull(in, name + " missing");
            Files.write(copy, in.readAllBytes());
        }
        copy.toFile().deleteOnExit();
        return copy;
    }

    private static List<Connection> analyse(String name) throws IOException {
        Path in = resource(name);
        Path out = Files.createTempFile("dpi-out", ".pcap");
        try {
            DPIEngine.Config config = new DPIEngine.Config();
            DPIEngine engine = new DPIEngine(config);
            assertTrue(engine.initialize());
            assertTrue(engine.processFile(in.toString(), out.toString()));
            return engine.getConnections();
        } finally {
            Files.deleteIfExists(out);
        }
    }

    private static List<String> snapshot(List<Connection> flows) {
        List<String> rows = new ArrayList<>();
        for (Connection c : flows) {
            rows.add(c.tuple + "|" + c.appType + "|" + c.sni + "|" + c.bytesIn + "|" + c.bytesOut);
        }
        java.util.Collections.sort(rows);
        return rows;
    }
}
