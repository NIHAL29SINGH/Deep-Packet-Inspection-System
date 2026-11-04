package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class RuleFilesTest {
    @Test
    void blockingRulesSurviveASaveAndLoadRoundTrip() throws IOException {
        Path file = Files.createTempFile("dpi-rules", ".txt");
        try {
            RuleManager original = new RuleManager();
            original.blockIP("203.0.113.9");
            original.blockApp(AppType.YOUTUBE);
            original.blockDomain("tracker.example");
            original.blockPort(23);
            original.blockJa3("E7D705A3286E19EA42F587B344EE6865");
            assertTrue(original.saveRules(file.toString()));

            RuleManager loaded = new RuleManager();
            assertTrue(loaded.loadRules(file.toString()));
            assertTrue(loaded.isAppBlocked(AppType.YOUTUBE));
            assertTrue(loaded.isDomainBlocked("cdn.tracker.example"));
            assertTrue(loaded.isPortBlocked(23));
            assertTrue(loaded.isJa3Blocked("e7d705a3286e19ea42f587b344ee6865"));
            assertFalse(loaded.isAppBlocked(AppType.GITHUB));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void bareKeywordMatchesWholeLabelsOnly() {
        RuleManager rules = new RuleManager();
        rules.blockDomain("facebook");
        assertTrue(rules.isDomainBlocked("www.facebook.com"));
        assertTrue(rules.isDomainBlocked("facebook.com"));
        assertFalse(rules.isDomainBlocked("notfacebookish.example"));
    }

    @Test
    void wildcardPatternsStillWork() {
        RuleManager rules = new RuleManager();
        rules.blockDomain("*.ads.example");
        assertTrue(rules.isDomainBlocked("a.ads.example"));
        assertFalse(rules.isDomainBlocked("ads.other.example"));
    }

    @Test
    void missingRuleFileIsReportedNotThrown() {
        assertFalse(new RuleManager().loadRules("/definitely/not/here.rules"));
    }

    @Test
    void riskRulesLoadFromPropertiesAndRejectInvalidValues() throws IOException {
        Path good = Files.createTempFile("risk-good", ".properties");
        Path bad = Files.createTempFile("risk-bad", ".properties");
        try {
            Files.writeString(good, "missing_sni_score=40\ncleartext_ports=21,23\noutbound_asymmetry_bytes=5000\n");
            RiskRules rules = RiskRules.load(good.toString());
            assertEquals(40, rules.missingSniScore);
            assertTrue(rules.cleartextPorts.contains(21));
            assertEquals(5000, rules.outboundAsymmetryBytes);

            Files.writeString(bad, "missing_sni_score=250\n");
            assertThrows(IllegalArgumentException.class, () -> RiskRules.load(bad.toString()));
            assertEquals(25, RiskRules.load("").missingSniScore, "blank path means defaults");
        } finally {
            Files.deleteIfExists(good);
            Files.deleteIfExists(bad);
        }
    }

    @Test
    void queueDeliversItemsInOrderAndStopsAfterShutdown() {
        ThreadSafeQueue<Integer> queue = new ThreadSafeQueue<>(4);
        queue.push(1);
        queue.push(2);
        assertEquals(2, queue.size());
        assertEquals(Integer.valueOf(1), queue.popWithTimeout(10));
        assertEquals(Integer.valueOf(2), queue.popWithTimeout(10));
        assertNull(queue.popWithTimeout(5));
        queue.shutdown();
        assertTrue(queue.isShutdown());
        assertTrue(queue.empty());
    }
}
