package com.deeppacket.engine;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Remembers which name DNS answers in the capture gave for each IPv4 address, so flows with no visible SNI
 * (ECH, encrypted-only QUIC, a capture that starts mid-conversation) can still be tied to a name.
 *
 * <p>Several workers write concurrently, so entries keep the answer with the <em>latest capture timestamp</em>
 * (ties broken by name order). That makes the result independent of thread scheduling. The cache is bounded.
 */
public final class DnsCache {
    public static final int DEFAULT_CAPACITY = 100_000;

    private record Entry(String name, long timestampMicros) {}

    private final ConcurrentHashMap<Integer, Entry> entries = new ConcurrentHashMap<>();
    private final int capacity;
    private final AtomicLong dropped = new AtomicLong();

    public DnsCache() {
        this(DEFAULT_CAPACITY);
    }

    public DnsCache(int capacity) {
        this.capacity = Math.max(1, capacity);
    }

    public void observe(int address, String name, long timestampMicros) {
        if (!entries.containsKey(address) && entries.size() >= capacity) {
            dropped.incrementAndGet();
            return;
        }
        entries.merge(address, new Entry(name, timestampMicros), (old, fresh) -> {
            if (fresh.timestampMicros() != old.timestampMicros()) {
                return fresh.timestampMicros() > old.timestampMicros() ? fresh : old;
            }
            return fresh.name().compareTo(old.name()) < 0 ? fresh : old;
        });
    }

    public Optional<String> lookup(int address) {
        Entry e = entries.get(address);
        return e == null ? Optional.empty() : Optional.of(e.name());
    }

    public int size() {
        return entries.size();
    }

    public long dropped() {
        return dropped.get();
    }
}
