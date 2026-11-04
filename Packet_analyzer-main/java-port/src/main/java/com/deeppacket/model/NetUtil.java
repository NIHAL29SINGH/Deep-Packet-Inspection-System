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

    /**
     * Converts an address read in network byte order (first octet in the high byte, as parsed straight from a
     * packet) into this class's internal representation (first octet in the low byte).
     */
    public static int fromNetworkOrder(int networkOrderAddress) {
        return Integer.reverseBytes(networkOrderAddress);
    }

    public static String intToIpv4(int ip) {
        return (ip & 0xFF) + "." +
               ((ip >>> 8) & 0xFF) + "." +
               ((ip >>> 16) & 0xFF) + "." +
               ((ip >>> 24) & 0xFF);
    }
}
