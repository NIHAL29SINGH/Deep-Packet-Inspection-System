package com.deeppacket.model;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class FiveTupleTest {
    @Test
    void symmetricHashIsSameForBothDirections() {
        Random random = new Random(42);
        for (int i = 0; i < 1_000; i++) {
            FiveTuple forward = new FiveTuple(random.nextInt(), random.nextInt(),
                random.nextInt(65536), random.nextInt(65536), random.nextBoolean() ? 6 : 17);
            assertEquals(forward.symmetricHash(), forward.reverse().symmetricHash());
            assertEquals(forward.fastPathHash(), forward.reverse().fastPathHash());
        }
    }

    @Test
    void everyWorkerReceivesTrafficWhenLoadBalancerAndWorkerCountsMatch() {
        // Regression: when the same hash chose both the load balancer and the worker,
        // (hash % 2) was identical at both stages and half of the workers stayed idle.
        int lbs = 2;
        int fps = 2;
        Set<String> used = new HashSet<>();
        Random random = new Random(7);
        for (int i = 0; i < 2_000; i++) {
            FiveTuple tuple = new FiveTuple(random.nextInt(), random.nextInt(),
                1024 + random.nextInt(60000), 443, 6);
            int lb = Math.floorMod(tuple.symmetricHash(), lbs);
            int fp = Math.floorMod(tuple.fastPathHash(), fps);
            used.add(lb + ":" + fp);
        }
        assertEquals(lbs * fps, used.size());
    }

    @Test
    void differentFlowsUsuallyHashDifferently() {
        FiveTuple a = new FiveTuple(0x0a000001, 0x0a000002, 1234, 443, 6);
        FiveTuple b = new FiveTuple(0x0a000001, 0x0a000002, 1235, 443, 6);
        assertNotEquals(a.symmetricHash(), b.symmetricHash());
    }
}
