package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.ConnectionState;
import com.deeppacket.model.FiveTuple;
import com.deeppacket.model.PacketAction;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections = new HashMap<>();
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public record TrackerStats(long activeConnections, long totalConnectionsSeen,
                               long classifiedConnections, long blockedConnections) {}

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        if (connections.size() >= maxConnections) evictOldest();
        Connection created = new Connection(tuple);
        connections.put(tuple, created);
        totalSeen++;
        return created;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection direct = connections.get(tuple);
        if (direct != null) return direct;
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, int packetSize, boolean outbound) {
        conn.lastSeenNanos = System.nanoTime();
        if (outbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn.state != ConnectionState.CLASSIFIED) classifiedCount++;
        conn.appType = app;
        conn.sni = sni;
        conn.state = ConnectionState.CLASSIFIED;
    }

    public void blockConnection(Connection conn) {
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public long cleanupStale(long timeoutNanos) {
        long now = System.nanoTime();
        List<FiveTuple> stale = new ArrayList<>();
        for (var entry : connections.entrySet()) {
            Connection c = entry.getValue();
            if (c.state == ConnectionState.CLOSED || now - c.lastSeenNanos > timeoutNanos) {
                stale.add(entry.getKey());
            }
        }
        stale.forEach(connections::remove);
        return stale.size();
    }

    public long getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    public void forEach(Consumer<Connection> consumer) {
        connections.values().forEach(consumer);
    }

    private void evictOldest() {
        connections.entrySet().stream()
            .min(Comparator.comparingLong(e -> e.getValue().lastSeenNanos))
            .map(Map.Entry::getKey)
            .ifPresent(connections::remove);
    }
}
