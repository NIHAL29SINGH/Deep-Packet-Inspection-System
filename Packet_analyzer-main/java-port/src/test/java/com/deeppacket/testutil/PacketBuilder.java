package com.deeppacket.testutil;

import com.deeppacket.engine.DPIEngine;
import com.deeppacket.pcap.PcapGlobalHeader;
import com.deeppacket.pcap.PcapPacketHeader;
import com.deeppacket.pcap.PcapWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

/** Builds raw Ethernet/IPv4 frames and runs them through a real engine instance in tests. */
public final class PacketBuilder {
    public static final int SYN = 0x02;
    public static final int ACK = 0x10;
    public static final int PSH_ACK = 0x18;
    public static final int FIN_ACK = 0x11;

    private PacketBuilder() {}

    public static byte[] tcp(int src, int dst, int srcPort, int dstPort, long seq, int flags, byte[] payload) {
        byte[] l4 = new byte[20 + payload.length];
        l4[0] = (byte) (srcPort >> 8); l4[1] = (byte) srcPort;
        l4[2] = (byte) (dstPort >> 8); l4[3] = (byte) dstPort;
        putInt(l4, 4, (int) seq);
        l4[12] = 0x50;
        l4[13] = (byte) flags;
        System.arraycopy(payload, 0, l4, 20, payload.length);
        return frame(src, dst, 6, l4, 0x4000);
    }

    public static byte[] udp(int src, int dst, int srcPort, int dstPort, byte[] payload) {
        byte[] l4 = new byte[8 + payload.length];
        l4[0] = (byte) (srcPort >> 8); l4[1] = (byte) srcPort;
        l4[2] = (byte) (dstPort >> 8); l4[3] = (byte) dstPort;
        l4[4] = (byte) (l4.length >> 8); l4[5] = (byte) l4.length;
        System.arraycopy(payload, 0, l4, 8, payload.length);
        return frame(src, dst, 17, l4, 0x4000);
    }

    /** IPv4 frame with an explicit flags/fragment-offset field (e.g. 0x00B9 = non-first fragment). */
    public static byte[] ipv4Fragment(int src, int dst, int protocol, byte[] l4, int flagsAndOffset) {
        return frame(src, dst, protocol, l4, flagsAndOffset);
    }

    private static byte[] frame(int src, int dst, int protocol, byte[] l4, int flagsAndOffset) {
        byte[] f = new byte[14 + 20 + l4.length];
        f[12] = 0x08;
        int ip = 14;
        f[ip] = 0x45;
        int total = 20 + l4.length;
        f[ip + 2] = (byte) (total >> 8); f[ip + 3] = (byte) total;
        f[ip + 6] = (byte) (flagsAndOffset >> 8); f[ip + 7] = (byte) flagsAndOffset;
        f[ip + 8] = 64;
        f[ip + 9] = (byte) protocol;
        putInt(f, ip + 12, src);
        putInt(f, ip + 16, dst);
        System.arraycopy(l4, 0, f, ip + 20, l4.length);
        return f;
    }

    public static byte[] withTrailingPadding(byte[] frame, int pad) {
        byte[] padded = new byte[frame.length + pad];
        System.arraycopy(frame, 0, padded, 0, frame.length);
        return padded;
    }

    public static byte[] clientHello(String host) {
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        int sniExtLen = 2 + 1 + 2 + name.length;
        int extensionsLen = 4 + sniExtLen;
        int helloBody = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLen;
        byte[] b = new byte[5 + 4 + helloBody];
        int o = 0;
        b[o++] = 0x16; b[o++] = 3; b[o++] = 1;
        b[o++] = (byte) ((4 + helloBody) >> 8); b[o++] = (byte) (4 + helloBody);
        b[o++] = 0x01; b[o++] = 0; b[o++] = (byte) (helloBody >> 8); b[o++] = (byte) helloBody;
        b[o++] = 3; b[o++] = 3;
        o += 32;
        b[o++] = 0;
        b[o++] = 0; b[o++] = 2; b[o++] = 0x13; b[o++] = 0x01;
        b[o++] = 1; b[o++] = 0;
        b[o++] = (byte) (extensionsLen >> 8); b[o++] = (byte) extensionsLen;
        b[o++] = 0; b[o++] = 0;
        b[o++] = (byte) (sniExtLen >> 8); b[o++] = (byte) sniExtLen;
        b[o++] = (byte) ((sniExtLen - 2) >> 8); b[o++] = (byte) (sniExtLen - 2);
        b[o++] = 0;
        b[o++] = (byte) (name.length >> 8); b[o++] = (byte) name.length;
        System.arraycopy(name, 0, b, o, name.length);
        return b;
    }

    private static byte[] dnsName(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String label : name.split("\\.")) {
            out.write(label.length());
            out.writeBytes(label.getBytes(StandardCharsets.US_ASCII));
        }
        out.write(0);
        return out.toByteArray();
    }

    public static byte[] dnsQuery(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0});
        out.writeBytes(dnsName(name));
        out.writeBytes(new byte[]{0, 1, 0, 1});
        return out.toByteArray();
    }

    /** A DNS response for an A query. When cnameTarget is set, the answers are preceded by a CNAME record. */
    public static byte[] dnsResponse(String name, String cnameTarget, int... addresses) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int answers = addresses.length + (cnameTarget != null ? 1 : 0);
        out.writeBytes(new byte[]{0x12, 0x34, (byte) 0x81, (byte) 0x80, 0, 1, (byte) (answers >> 8), (byte) answers, 0, 0, 0, 0});
        out.writeBytes(dnsName(name));
        out.writeBytes(new byte[]{0, 1, 0, 1});
        byte[] target = cnameTarget == null ? new byte[0] : dnsName(cnameTarget);
        if (cnameTarget != null) {
            out.writeBytes(new byte[]{(byte) 0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 1, 0x2C, 0, (byte) target.length});
            out.writeBytes(target);
        }
        for (int a : addresses) {
            out.writeBytes(new byte[]{(byte) 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4,
                (byte) (a >>> 24), (byte) (a >>> 16), (byte) (a >>> 8), (byte) a});
        }
        return out.toByteArray();
    }

    public static byte[] slice(byte[] data, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }

    /** Writes the frames to a temporary PCAP and processes it with a 2x2 engine. */
    public static DPIEngine run(List<byte[]> frames, Consumer<DPIEngine> configure) throws IOException {
        Path in = Files.createTempFile("dpi-test-in", ".pcap");
        Path out = Files.createTempFile("dpi-test-out", ".pcap");
        try {
            writePcap(in, frames);
            DPIEngine.Config config = new DPIEngine.Config();
            config.numLoadBalancers = 2;
            config.fpsPerLb = 2;
            DPIEngine engine = new DPIEngine(config);
            if (!engine.initialize()) throw new IllegalStateException("engine failed to initialize");
            if (configure != null) configure.accept(engine);
            if (!engine.processFile(in.toString(), out.toString())) throw new IllegalStateException("processFile failed");
            return engine;
        } finally {
            Files.deleteIfExists(in);
            Files.deleteIfExists(out);
        }
    }

    public static void writePcap(Path path, List<byte[]> frames) throws IOException {
        PcapGlobalHeader header = new PcapGlobalHeader();
        header.magicNumber = 0xa1b2c3d4;
        header.versionMajor = 2;
        header.versionMinor = 4;
        header.snapLen = 65535;
        header.byteOrder = ByteOrder.BIG_ENDIAN;
        header.network = 1;
        try (PcapWriter writer = new PcapWriter()) {
            writer.open(path.toString(), header);
            for (byte[] frame : frames) writer.writePacket(new PcapPacketHeader(), frame);
        }
    }

    private static void putInt(byte[] a, int off, int v) {
        a[off] = (byte) (v >>> 24); a[off + 1] = (byte) (v >>> 16); a[off + 2] = (byte) (v >>> 8); a[off + 3] = (byte) v;
    }
}
