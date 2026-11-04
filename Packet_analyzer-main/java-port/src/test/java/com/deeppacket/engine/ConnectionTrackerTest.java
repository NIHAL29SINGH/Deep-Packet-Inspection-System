package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;
import com.deeppacket.model.ConnectionState;
import com.deeppacket.model.FiveTuple;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConnectionTrackerTest {
    private static FiveTuple flow(int n) {
        return new FiveTuple(0x0a000001, 0x0a000002, 10_000 + n, 443, 6);
    }

    private static List<Connection> all(ConnectionTracker tracker) {
        List<Connection> out = new ArrayList<>();
        tracker.forEach(out::add);
        return out;
    }

    @Test
    void retiredFlowsRemainVisibleToReports() {
        ConnectionTracker tracker = new ConnectionTracker(0, 100);
        Connection conn = tracker.getOrCreateConnection(flow(1));
        conn.state = ConnectionState.CLOSED;
        assertEquals(1, tracker.cleanupStale(Long.MAX_VALUE));
        assertEquals(0, tracker.getActiveCount());
        assertEquals(1, all(tracker).size());
        assertEquals(1, tracker.getStats().retiredConnections());
    }

    @Test
    void idleFlowsAreRetiredAfterTheTimeout() throws Exception {
        ConnectionTracker tracker = new ConnectionTracker(0, 100);
        tracker.getOrCreateConnection(flow(1));
        Thread.sleep(5);
        assertEquals(0, tracker.cleanupStale(60_000_000_000L));
        assertEquals(1, tracker.cleanupStale(1_000_000L));
    }

    @Test
    void evictionRetiresTheOldestFlowsInABatch() throws Exception {
        ConnectionTracker tracker = new ConnectionTracker(0, 200);
        for (int i = 0; i < 200; i++) {
            tracker.getOrCreateConnection(flow(i));
            if (i % 50 == 0) Thread.sleep(1);
        }
        tracker.getOrCreateConnection(flow(1000)); // table full -> evict ~1% (2 flows)
        assertEquals(200 - 2 + 1, tracker.getActiveCount());
        assertEquals(2, tracker.getStats().retiredConnections());
        assertEquals(201, all(tracker).size(), "no flow may disappear from reports");
    }

    @Test
    void retiredHistoryIsBoundedAndCountsDrops() {
        ConnectionTracker tracker = new ConnectionTracker(0, 10);
        for (int i = 0; i < 30; i++) {
            Connection c = tracker.getOrCreateConnection(flow(i));
            tracker.retire(c);
        }
        assertEquals(10, tracker.getStats().retiredConnections());
        assertEquals(20, tracker.getStats().retiredDropped());
    }

    @Test
    void reassemblyBudgetIsEnforcedAndReleased() {
        ConnectionTracker tracker = new ConnectionTracker(0, 10);
        int chunk = 1024 * 1024;
        int reserved = 0;
        while (tracker.tryReserveReassembly(chunk)) reserved++;
        assertEquals(ConnectionTracker.REASSEMBLY_BUDGET_BYTES / chunk, reserved);

        Connection conn = tracker.getOrCreateConnection(flow(1));
        conn.tlsBuffer = new byte[chunk];
        tracker.releaseReassemblyBuffer(conn);
        assertNull(conn.tlsBuffer);
        assertTrue(tracker.tryReserveReassembly(chunk));
    }

    @Test
    void classifyingAFlowFreesItsReassemblyBuffer() {
        ConnectionTracker tracker = new ConnectionTracker(0, 10);
        Connection conn = tracker.getOrCreateConnection(flow(1));
        assertTrue(tracker.tryReserveReassembly(2000));
        conn.tlsBuffer = new byte[2000];
        tracker.classifyConnection(conn, AppType.GITHUB, "github.com");
        assertNull(conn.tlsBuffer);
        assertEquals(0, tracker.reassemblyBytesInUse());
        assertEquals(1, tracker.getStats().classifiedConnections());
    }

    @Test
    void lookupFindsEitherDirection() {
        ConnectionTracker tracker = new ConnectionTracker(0, 10);
        FiveTuple request = flow(1);
        Connection conn = tracker.getOrCreateConnection(request);
        assertSame(conn, tracker.getConnection(request));
        assertSame(conn, tracker.getConnection(request.reverse()));
        assertNull(tracker.getConnection(flow(2)));
    }
}
