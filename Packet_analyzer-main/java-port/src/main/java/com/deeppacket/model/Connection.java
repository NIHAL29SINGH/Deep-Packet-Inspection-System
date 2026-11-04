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
    /** Reassembly buffer for a TLS record that spans several TCP segments (null when unused). */
    public byte[] tlsBuffer;
    public int tlsFilled;
    public long tlsNextSeq;

    /** QUIC Initial datagrams examined so far (bounded to keep per-flow CPU cost small). */
    public int quicAttempts;
    /** Reassembles a QUIC ClientHello split across several Initial packets (null when unused). */
    public ReassemblyBuffer quicCrypto;

    /** JA3 fingerprint (MD5) of the TLS ClientHello, empty when none was seen. */
    public String ja3 = "";
    /** Highest TLS version offered by the client, for example "TLS 1.3". */
    public String tlsVersion = "";
    /** What the classification is based on: "SNI", "HTTP Host", "QUIC Initial", "DNS answer", "port" or empty. */
    public String classifiedBy = "";
    /** Name a DNS answer in the capture associated with this flow's server address (set after the run). */
    public String dnsHint = "";
    /** Set after the run when the client queried many distinct names under one domain (possible tunnelling). */
    public String tunnelNote = "";

    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;

    /** True when the packet travels in the initiator-to-responder direction of this flow. */
    public boolean isOutbound(FiveTuple packetTuple) {
        return tuple.equals(packetTuple);
    }

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
        this.firstSeenNanos = System.nanoTime();
        this.lastSeenNanos = this.firstSeenNanos;
    }
}
