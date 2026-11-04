package com.deeppacket.app;

import com.deeppacket.dpi.SNIExtractor;
import com.deeppacket.parser.PacketParser;
import com.deeppacket.pcap.PcapReader;

public class SimpleDpiMain {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java com.deeppacket.app.SimpleDpiMain <pcap_file>");
            System.exit(1);
        }
        int count = 0;
        int sniCount = 0;
        try (PcapReader reader = new PcapReader()) {
            reader.open(args[0]);
            while (true) {
                var rawOpt = reader.readNextPacket();
                if (rawOpt.isEmpty()) break;
                count++;
                var parsed = PacketParser.parse(rawOpt.get());
                if (parsed == null || !parsed.hasIp) continue;

                System.out.print("Packet " + count + ": " + parsed.srcIp + ":" + parsed.srcPort +
                    " -> " + parsed.destIp + ":" + parsed.destPort);

                if (parsed.hasTcp && parsed.destPort == 443 && parsed.payloadLength > 0) {
                    byte[] payload = new byte[parsed.payloadLength];
                    System.arraycopy(rawOpt.get().data, parsed.payloadOffset, payload, 0, parsed.payloadLength);
                    var sni = SNIExtractor.extract(payload, payload.length);
                    if (sni.isPresent()) {
                        System.out.print(" [SNI: " + sni.get() + "]");
                        sniCount++;
                    }
                }
                System.out.println();
            }
        }
        System.out.println("Total packets: " + count);
        System.out.println("SNI extracted: " + sniCount);
    }
}
