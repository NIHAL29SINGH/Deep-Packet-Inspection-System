package com.deeppacket.engine;

import com.deeppacket.pcap.PcapGlobalHeader;
import com.deeppacket.pcap.PcapPacketHeader;
import com.deeppacket.pcap.PcapWriter;
import org.junit.jupiter.api.Test;

import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DPIEngineIntegrationTest {
    @Test
    void processesPacketAndWritesReports() throws Exception {
        Path input = Files.createTempFile("dpi-input", ".pcap");
        Path output = Files.createTempFile("dpi-output", ".pcap");
        Path json = Files.createTempFile("dpi-report", ".json");
        try {
            PcapGlobalHeader header = new PcapGlobalHeader();
            header.magicNumber = 0xa1b2c3d4;
            header.versionMajor = 2;
            header.versionMinor = 4;
            header.snapLen = 65535;
            header.byteOrder = ByteOrder.BIG_ENDIAN;
            header.network = 1;
            byte[] packet = udpPacket();
            try (PcapWriter writer = new PcapWriter()) {
                writer.open(input.toString(), header);
                PcapPacketHeader packetHeader = new PcapPacketHeader();
                packetHeader.tsSec = 1;
                packetHeader.tsUsec = 2;
                writer.writePacket(packetHeader, packet);
            }

            DPIEngine.Config config = new DPIEngine.Config();
            config.numLoadBalancers = 1;
            config.fpsPerLb = 1;
            config.verbose = false;
            DPIEngine engine = new DPIEngine(config);
            assertTrue(engine.initialize());
            assertTrue(engine.processFile(input.toString(), output.toString()));
            assertTrue(engine.exportReportJson(json.toString()));
            assertTrue(Files.size(output) > 24);
            assertTrue(Files.readString(json).contains("\"total_packets\": 1"));
        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(output);
            Files.deleteIfExists(json);
        }
    }

    private static byte[] udpPacket() {
        byte[] packet = new byte[14 + 20 + 8 + 4];
        packet[12] = 0x08;
        packet[13] = 0x00;
        int ip = 14;
        packet[ip] = 0x45;
        packet[ip + 8] = 64;
        packet[ip + 9] = 17;
        packet[ip + 12] = 10;
        packet[ip + 15] = 1;
        packet[ip + 16] = 10;
        packet[ip + 19] = 2;
        int udp = ip + 20;
        packet[udp + 1] = 53;
        packet[udp + 2] = 0x12;
        packet[udp + 3] = 0x34;
        packet[udp + 4] = 0;
        packet[udp + 5] = 12;
        packet[udp + 8] = 1;
        return packet;
    }
}
