package com.deeppacket.model;

public class Connection {
    public final FiveTuple tuple;
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";

    public long packetsIn = 0;
    public long packetsOut = 0;
    public long bytesIn = 0;
    public long bytesOut = 0;

    public long firstSeenNanos;
    public long lastSeenNanos;

    public PacketAction action = PacketAction.FORWARD;
    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
        this.firstSeenNanos = System.nanoTime();
        this.lastSeenNanos = this.firstSeenNanos;
    }
}
