package com.deeppacket.engine;

import com.deeppacket.model.Connection;
import com.deeppacket.model.FiveTuple;
import com.deeppacket.pcap.PcapGlobalHeader;
import com.deeppacket.pcap.PcapPacketHeader;
import com.deeppacket.pcap.PcapWriter;
import org.junit.jupiter.api.Test;

import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class FlowDirectionTest {
    private static final int CLIENT = 0x0a000001;
    private static final int SERVER = 0x0a000002;

    @Test
    void trackerMapsReplyDirectionToTheSameConnection() {
        ConnectionTracker tracker = new ConnectionTracker(0, 100);
        FiveTuple request = new FiveTuple(CLIENT, SERVER, 50000, 443, 6);
        Connection conn = tracker.getOrCreateConnection(request);
        assertSame(conn, tracker.getOrCreateConnection(request.reverse()));
        assertTrue(conn.isOutbound(request));
        assertFalse(conn.isOutbound(request.reverse()));
        assertEquals(1, tracker.getActiveCount());
    }

    @Test
    void bothDirectionsAreCountedOnOneFlowAcrossWorkers() throws Exception {
        Path input = Files.createTempFile("dpi-flow", ".pcap");
        Path output = Files.createTempFile("dpi-flow-out", ".pcap");
        try {
            PcapGlobalHeader header = new PcapGlobalHeader();
            header.magicNumber = 0xa1b2c3d4;
            header.versionMajor = 2;
            header.versionMinor = 4;
            header.snapLen = 65535;
            header.byteOrder = ByteOrder.BIG_ENDIAN;
            header.network = 1;
            try (PcapWriter writer = new PcapWriter()) {
                writer.open(input.toString(), header);
                for (int i = 0; i < 3; i++) {
                    writer.writePacket(new PcapPacketHeader(), tcp(CLIENT, SERVER, 50000, 443, 100));
                }
                for (int i = 0; i < 2; i++) {
                    writer.writePacket(new PcapPacketHeader(), tcp(SERVER, CLIENT, 443, 50000, 1000));
                }
            }

            DPIEngine.Config config = new DPIEngine.Config();
            config.numLoadBalancers = 2;
            config.fpsPerLb = 2;
            DPIEngine engine = new DPIEngine(config);
            assertTrue(engine.initialize());
            assertTrue(engine.processFile(input.toString(), output.toString()));

            var connections = engine.getConnections();
            assertEquals(1, connections.size(), "request and reply must share one flow");
            Connection flow = connections.get(0);
            assertEquals(3, flow.packetsOut);
            assertEquals(2, flow.packetsIn);
            assertEquals(3L * (14 + 20 + 20 + 100), flow.bytesOut);
            assertEquals(2L * (14 + 20 + 20 + 1000), flow.bytesIn);
        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(output);
        }
    }

    private static byte[] tcp(int src, int dst, int srcPort, int dstPort, int payload) {
        byte[] p = new byte[14 + 20 + 20 + payload];
        p[12] = 0x08;
        p[13] = 0x00;
        int ip = 14;
        p[ip] = 0x45;
        p[ip + 8] = 64;
        p[ip + 9] = 6;
        putInt(p, ip + 12, src);
        putInt(p, ip + 16, dst);
        int tcp = ip + 20;
        p[tcp] = (byte) (srcPort >> 8);
        p[tcp + 1] = (byte) srcPort;
        p[tcp + 2] = (byte) (dstPort >> 8);
        p[tcp + 3] = (byte) dstPort;
        p[tcp + 12] = 0x50;
        p[tcp + 13] = 0x10;
        return p;
    }

    private static void putInt(byte[] a, int off, int v) {
        a[off] = (byte) (v >>> 24);
        a[off + 1] = (byte) (v >>> 16);
        a[off + 2] = (byte) (v >>> 8);
        a[off + 3] = (byte) v;
    }
}
