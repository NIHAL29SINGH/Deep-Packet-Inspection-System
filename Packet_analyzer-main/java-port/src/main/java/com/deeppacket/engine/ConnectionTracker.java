package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.ConnectionState;
import com.deeppacket.model.FiveTuple;
import com.deeppacket.model.PacketAction;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Per-worker flow table.
 *
 * <p>Only the owning worker thread mutates flows; reports and metrics read them from other threads, so
 * the map is concurrent. Flows that close, go idle or are evicted are <em>retired</em> into a bounded
 * history instead of being discarded, so they still appear in reports.
 */
public class ConnectionTracker {
    /** Upper bound on bytes held for TLS record reassembly across all flows of one worker. */
    static final long REASSEMBLY_BUDGET_BYTES = 16L * 1024 * 1024;

    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections = new ConcurrentHashMap<>();
    private final ConcurrentLinkedQueue<Connection> retired = new ConcurrentLinkedQueue<>();
    private final AtomicInteger retiredCount = new AtomicInteger();
    private final AtomicLong retiredDropped = new AtomicLong();
    private final AtomicLong reassemblyBytes = new AtomicLong();
    private final AtomicLong totalSeen = new AtomicLong();
    private final AtomicLong classifiedCount = new AtomicLong();
    private final AtomicLong blockedCount = new AtomicLong();

    public record TrackerStats(long activeConnections, long totalConnectionsSeen,
                               long classifiedConnections, long blockedConnections,
                               long retiredConnections, long retiredDropped) {}

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = Math.max(1, maxConnections);
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        // The reply direction of an existing flow maps to the same Connection.
        conn = connections.get(tuple.reverse());
        if (conn != null) return conn;
        if (connections.size() >= maxConnections) evictOldestBatch();
        Connection created = new Connection(tuple);
        connections.put(tuple, created);
        totalSeen.incrementAndGet();
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
        classifyConnection(conn, app, sni, "");
    }

    /** Classifies a flow and records what the decision is based on ("TLS SNI", "QUIC Initial", ...). */
    public void classifyConnection(Connection conn, AppType app, String sni, String evidence) {
        if (conn.state != ConnectionState.CLASSIFIED) classifiedCount.incrementAndGet();
        conn.appType = app;
        conn.sni = sni;
        conn.classifiedBy = evidence;
        conn.state = ConnectionState.CLASSIFIED;
        releaseReassemblyBuffer(conn);
    }

    public void blockConnection(Connection conn) {
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount.incrementAndGet();
        releaseReassemblyBuffer(conn);
    }

    /** Moves a flow out of the active table into the bounded history used by reports. */
    public void retire(Connection conn) {
        if (!connections.remove(conn.tuple, conn)) return;
        releaseReassemblyBuffer(conn);
        retired.add(conn);
        if (retiredCount.incrementAndGet() > maxConnections) {
            if (retired.poll() != null) {
                retiredCount.decrementAndGet();
                retiredDropped.incrementAndGet();
            }
        }
    }

    public long cleanupStale(long timeoutNanos) {
        long now = System.nanoTime();
        List<Connection> stale = new ArrayList<>();
        for (Connection c : connections.values()) {
            if (c.state == ConnectionState.CLOSED || now - c.lastSeenNanos > timeoutNanos) {
                stale.add(c);
            }
        }
        stale.forEach(this::retire);
        return stale.size();
    }

    /**
     * Reserves reassembly memory for one flow. Returns false when the per-worker budget is spent, so a
     * flood of half-open TLS handshakes cannot exhaust the heap.
     */
    boolean tryReserveReassembly(int bytes) {
        while (true) {
            long current = reassemblyBytes.get();
            if (current + bytes > REASSEMBLY_BUDGET_BYTES) return false;
            if (reassemblyBytes.compareAndSet(current, current + bytes)) return true;
        }
    }

    void releaseReassemblyBuffer(Connection conn) {
        byte[] buffer = conn.tlsBuffer;
        if (buffer != null) {
            conn.tlsBuffer = null;
            conn.tlsFilled = 0;
            reassemblyBytes.addAndGet(-buffer.length);
        }
        var quic = conn.quicCrypto;
        if (quic != null) {
            conn.quicCrypto = null;
            reassemblyBytes.addAndGet(-quic.capacity());
        }
    }

    long reassemblyBytesInUse() {
        return reassemblyBytes.get();
    }

    public long getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen.get(), classifiedCount.get(), blockedCount.get(),
            retiredCount.get(), retiredDropped.get());
    }

    /** Visits active and retired flows. */
    public void forEach(Consumer<Connection> consumer) {
        connections.values().forEach(consumer);
        retired.forEach(consumer);
    }

    /**
     * Retires the least recently seen ~1% of flows in one pass. Evicting a batch keeps insertion cost
     * amortised O(log n) instead of scanning the whole table for every new flow under a flood.
     */
    private void evictOldestBatch() {
        int batch = Math.max(1, maxConnections / 100);
        PriorityQueue<Connection> oldest = new PriorityQueue<>(batch + 1,
            Comparator.comparingLong((Connection c) -> c.lastSeenNanos).reversed());
        for (Connection c : connections.values()) {
            oldest.add(c);
            if (oldest.size() > batch) oldest.poll();
        }
        oldest.forEach(this::retire);
    }
}
