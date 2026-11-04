package com.deeppacket.engine;

import com.deeppacket.model.AppType;
import com.deeppacket.model.NetUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RuleManagerTest {
    @Test
    void domainRuleMatchesExactAndSubdomainsOnly() {
        RuleManager rules = new RuleManager();
        rules.blockDomain("x.com");
        assertTrue(rules.isDomainBlocked("x.com"));
        assertTrue(rules.isDomainBlocked("api.x.com"));
        assertTrue(rules.isDomainBlocked("API.X.COM"));
        assertFalse(rules.isDomainBlocked("dropbox.com"));
        assertFalse(rules.isDomainBlocked("x.com.evil.example"));
    }

    @Test
    void blockedIpMatchesSourceAndDestination() {
        RuleManager rules = new RuleManager();
        int blocked = NetUtil.parseIpv4ToInt("203.0.113.9");
        int other = NetUtil.parseIpv4ToInt("10.0.0.5");
        rules.blockIP(blocked);
        assertTrue(rules.shouldBlock(blocked, other, 443, AppType.UNKNOWN, "").isPresent());
        assertTrue(rules.shouldBlock(other, blocked, 443, AppType.UNKNOWN, "").isPresent());
        assertTrue(rules.shouldBlock(other, other, 443, AppType.UNKNOWN, "").isEmpty());
    }

    @Test
    void blockedPortIsReported() {
        RuleManager rules = new RuleManager();
        rules.blockPort(23);
        var reason = rules.shouldBlock(1, 2, 23, AppType.UNKNOWN, "");
        assertTrue(reason.isPresent());
        assertEquals(RuleManager.BlockType.PORT, reason.get().type);
    }
}
