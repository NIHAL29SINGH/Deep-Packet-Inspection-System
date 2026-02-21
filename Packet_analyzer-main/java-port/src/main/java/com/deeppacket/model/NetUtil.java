package com.deeppacket.model;

public final class NetUtil {
    private NetUtil() {}

    public static int parseIpv4ToInt(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4: " + ip);
        }
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(parts[i]);
            value |= (octet & 0xFF) << (i * 8);
        }
        return value;
    }

    public static String intToIpv4(int ip) {
        return (ip & 0xFF) + "." +
               ((ip >>> 8) & 0xFF) + "." +
               ((ip >>> 16) & 0xFF) + "." +
               ((ip >>> 24) & 0xFF);
    }
}
