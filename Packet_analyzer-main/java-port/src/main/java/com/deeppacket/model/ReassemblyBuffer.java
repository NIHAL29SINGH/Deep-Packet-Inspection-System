package com.deeppacket.model;

import java.util.Arrays;
import java.util.BitSet;

/**
 * Fixed-size buffer that reassembles a byte stream from fragments that may arrive in any order and may
 * overlap or repeat. Used for QUIC CRYPTO data, where a ClientHello is split across several Initial packets.
 *
 * <p>Only bytes inside {@code [0, capacity)} are accepted, so a hostile sender cannot make it grow. The first
 * {@link #contiguousLength()} bytes are the longest gap-free prefix received so far.
 */
public final class ReassemblyBuffer {
    private final byte[] data;
    private final BitSet have;

    public ReassemblyBuffer(int capacity) {
        if (capacity <= 0) throw new IllegalArgumentException("capacity must be positive");
        this.data = new byte[capacity];
        this.have = new BitSet(capacity);
    }

    public int capacity() {
        return data.length;
    }

    /** Stores a fragment; bytes beyond the capacity are ignored. Returns the number of new bytes stored. */
    public int add(long offset, byte[] fragment, int from, int length) {
        if (offset < 0 || length <= 0 || offset >= data.length) return 0;
        int start = (int) offset;
        int n = (int) Math.min(length, (long) data.length - start);
        int before = have.cardinality();
        System.arraycopy(fragment, from, data, start, n);
        have.set(start, start + n);
        return have.cardinality() - before;
    }

    /** Length of the gap-free prefix starting at offset 0. */
    public int contiguousLength() {
        int firstGap = have.nextClearBit(0);
        return Math.min(firstGap, data.length);
    }

    /** Copy of the gap-free prefix. */
    public byte[] contiguousBytes() {
        return Arrays.copyOf(data, contiguousLength());
    }
}
