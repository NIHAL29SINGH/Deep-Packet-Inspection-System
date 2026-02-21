package com.deeppacket.engine;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeoutException;

public final class LiveCaptureService {
    public record CaptureStats(String ifaceName, long packets, long bytes, String captureFile) {}

    private LiveCaptureService() {}

    public static void listInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> ifaces = Pcaps.findAllDevs();
        if (ifaces == null || ifaces.isEmpty()) {
            System.out.println("No capture interfaces found.");
            return;
        }
        for (PcapNetworkInterface nif : ifaces) {
            System.out.println("- " + nif.getName() + " | " + safe(nif.getDescription()) +
                " | " + formatAddresses(nif.getAddresses()));
        }
    }

    public static CaptureStats capture(String ifaceQuery, int durationSec, String outPcap,
                                       String bpfFilter, boolean verbose)
        throws PcapNativeException, NotOpenException {

        PcapNetworkInterface nif = chooseInterface(ifaceQuery);
        if (nif == null) {
            throw new IllegalArgumentException("No matching interface found: " + ifaceQuery);
        }

        if (verbose) {
            System.out.println("[Live] Interface: " + nif.getName() + " (" + safe(nif.getDescription()) + ")");
            System.out.println("[Live] Duration: " + durationSec + "s");
            System.out.println("[Live] Capture file: " + outPcap);
        }

        long packetCount = 0;
        long byteCount = 0;
        long endTs = System.currentTimeMillis() + (durationSec * 1000L);

        try (PcapHandle handle = nif.openLive(
            65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
            10
        );
             PcapDumper dumper = handle.dumpOpen(outPcap)) {

            if (bpfFilter != null && !bpfFilter.isBlank()) {
                handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
            }

            while (System.currentTimeMillis() < endTs) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    Timestamp ts = handle.getTimestamp();
                    dumper.dump(packet, ts);
                    packetCount++;
                    byteCount += packet.length();
                } catch (TimeoutException ignored) {
                    // Poll timeout is expected.
                } catch (EOFException e) {
                    break;
                }
            }
        }

        if (verbose) {
            System.out.println("[Live] Captured packets: " + packetCount);
            System.out.println("[Live] Captured bytes:   " + byteCount);
        }
        return new CaptureStats(nif.getName(), packetCount, byteCount, outPcap);
    }

    private static PcapNetworkInterface chooseInterface(String ifaceQuery) throws PcapNativeException {
        List<PcapNetworkInterface> ifaces = Pcaps.findAllDevs();
        if (ifaces == null || ifaces.isEmpty()) {
            return null;
        }

        if (ifaceQuery != null && !ifaceQuery.isBlank()) {
            String q = ifaceQuery.toLowerCase(Locale.ROOT);
            for (PcapNetworkInterface nif : ifaces) {
                String name = safe(nif.getName()).toLowerCase(Locale.ROOT);
                String desc = safe(nif.getDescription()).toLowerCase(Locale.ROOT);
                if (name.equals(q) || name.contains(q) || desc.contains(q)) {
                    return nif;
                }
            }
            return null;
        }

        for (PcapNetworkInterface nif : ifaces) {
            if (!nif.isLoopBack()) return nif;
        }
        return ifaces.get(0);
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String formatAddresses(List<PcapAddress> addrs) {
        if (addrs == null || addrs.isEmpty()) return "no-ip";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < addrs.size(); i++) {
            if (addrs.get(i).getAddress() == null) continue;
            if (sb.length() > 0) sb.append(", ");
            sb.append(addrs.get(i).getAddress().getHostAddress());
        }
        return sb.length() == 0 ? "no-ip" : sb.toString();
    }
}
