package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.Connection;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class GlobalConnectionTable {
    private final ConnectionTracker[] trackers;

    public record GlobalStats(long totalActiveConnections, long totalConnectionsSeen,
                              Map<AppType, Long> appDistribution,
                              List<Map.Entry<String, Long>> topDomains) {}

    public GlobalConnectionTable(int count) {
        this.trackers = new ConnectionTracker[count];
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        trackers[fpId] = tracker;
    }

    public GlobalStats getGlobalStats() {
        long active = 0;
        long seen = 0;
        Map<AppType, Long> app = new HashMap<>();
        Map<String, Long> domains = new HashMap<>();

        for (ConnectionTracker tracker : trackers) {
            if (tracker == null) continue;
            var st = tracker.getStats();
            active += st.activeConnections();
            seen += st.totalConnectionsSeen();
            tracker.forEach(c -> {
                app.merge(c.appType, 1L, Long::sum);
                if (c.sni != null && !c.sni.isEmpty()) domains.merge(c.sni, 1L, Long::sum);
            });
        }
        List<Map.Entry<String, Long>> top = new ArrayList<>(domains.entrySet());
        top.sort(Comparator.comparingLong((Map.Entry<String, Long> e) -> e.getValue()).reversed());
        if (top.size() > 20) top = top.subList(0, 20);
        return new GlobalStats(active, seen, app, top);
    }

    public List<Connection> snapshotConnections() {
        List<Connection> all = new ArrayList<>();
        forEachConnection(all::add);
        return all;
    }

    public void forEachConnection(Consumer<Connection> consumer) {
        for (ConnectionTracker tracker : trackers) {
            if (tracker == null) continue;
            tracker.forEach(consumer);
        }
    }
}
