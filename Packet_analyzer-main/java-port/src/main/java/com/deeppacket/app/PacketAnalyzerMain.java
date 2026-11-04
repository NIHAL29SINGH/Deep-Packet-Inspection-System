package com.deeppacket.app;

import com.deeppacket.parser.PacketParser;
import com.deeppacket.parser.ParsedPacket;
import com.deeppacket.pcap.PcapReader;

import java.util.HexFormat;

public class PacketAnalyzerMain {
    private static void usage() {
        System.out.println("Usage: java com.deeppacket.app.PacketAnalyzerMain <pcap_file> [max_packets]");
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            usage();
            System.exit(1);
        }
        String file = args[0];
        int max = args.length > 1 ? Integer.parseInt(args[1]) : -1;

        int packetCount = 0;
        int parseErrors = 0;

        try (PcapReader reader = new PcapReader()) {
            reader.open(file);
            while (true) {
                var opt = reader.readNextPacket();
                if (opt.isEmpty()) break;
                packetCount++;
                ParsedPacket p = PacketParser.parse(opt.get());
                if (p == null) {
                    parseErrors++;
                    continue;
                }
                printSummary(p, opt.get().data);
                if (max > 0 && packetCount >= max) break;
            }
        }

        System.out.println("\nSummary:");
        System.out.println("  Total packets read: " + packetCount);
        System.out.println("  Parse errors:       " + parseErrors);
    }

    private static void printSummary(ParsedPacket p, byte[] data) {
        System.out.println("\n========== Packet ==========");
        System.out.println("Time: " + p.timestampSec + "." + p.timestampUsec);
        System.out.println("[Ethernet]");
        System.out.println("  Source MAC:      " + p.srcMac);
        System.out.println("  Destination MAC: " + p.destMac);
        System.out.printf("  EtherType:       0x%04x%n", p.etherType);
        if (p.hasIp) {
            System.out.println("[IPv" + p.ipVersion + "]");
            System.out.println("  Source IP:      " + p.srcIp);
            System.out.println("  Destination IP: " + p.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(p.protocol));
            System.out.println("  TTL:            " + p.ttl);
        }
        if (p.hasTcp) {
            System.out.println("[TCP]");
            System.out.println("  Source Port:      " + p.srcPort);
            System.out.println("  Destination Port: " + p.destPort);
            System.out.println("  Sequence Number:  " + p.seqNumber);
            System.out.println("  Ack Number:       " + p.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(p.tcpFlags));
        }
        if (p.hasUdp) {
            System.out.println("[UDP]");
            System.out.println("  Source Port:      " + p.srcPort);
            System.out.println("  Destination Port: " + p.destPort);
        }
        if (p.payloadLength > 0) {
            int preview = Math.min(32, p.payloadLength);
            byte[] out = new byte[preview];
            System.arraycopy(data, p.payloadOffset, out, 0, preview);
            System.out.println("[Payload]");
            System.out.println("  Length: " + p.payloadLength + " bytes");
            System.out.println("  Preview: " + HexFormat.ofDelimiter(" ").formatHex(out) + (p.payloadLength > 32 ? " ..." : ""));
        }
    }
}
