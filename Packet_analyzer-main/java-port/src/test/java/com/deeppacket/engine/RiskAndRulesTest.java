package com.deeppacket.engine;

import com.deeppacket.model.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;

class RiskAndRulesTest {
    @Test
    void customRiskRulesChangeAssessmentScores() throws Exception {
        Path file = Files.createTempFile("risk-rules", ".properties");
        Files.writeString(file, "cleartext_port_score=10\ncleartext_ports=23\n");
        var rules = RiskRules.load(file.toString());
        Connection connection = new Connection(new FiveTuple(0x0a000001, 0x0a000002, 1234, 23, 6));
        connection.appType = AppType.UNKNOWN;
        assertEquals(20, RiskAnalyzer.assess(connection, rules).score());
        Files.deleteIfExists(file);
    }

    @Test
    void policyMatchProducesCriticalExplainableAssessment() {
        Connection connection = new Connection(new FiveTuple(0x0a000001, 0x0a000002, 1234, 443, 6));
        connection.action = PacketAction.DROP;
        connection.appType = AppType.YOUTUBE;
        var assessment = RiskAnalyzer.assess(connection);
        assertEquals("CRITICAL", assessment.severity());
        assertEquals(100, assessment.score());
        assertTrue(assessment.findings().get(0).contains("policy"));
        assertTrue(RiskAnalyzer.evidenceId(connection).startsWith("flow-"));
    }

    @Test
    void wildcardDomainRuleMatchesSubdomains() {
        RuleManager rules = new RuleManager();
        rules.blockDomain("*.example.test");
        assertTrue(rules.isDomainBlocked("api.example.test"));
        assertFalse(rules.isDomainBlocked("example.invalid"));
    }

    @Test
    void asymmetryFindingRequiresRealInboundVersusOutboundImbalance() {
        Connection balanced = new Connection(new FiveTuple(0x0a000001, 0x0a000002, 1234, 443, 6));
        balanced.appType = AppType.YOUTUBE;
        balanced.sni = "www.youtube.com";
        balanced.bytesOut = 500_000;
        balanced.bytesIn = 400_000;
        assertFalse(RiskAnalyzer.assess(balanced).findings().stream().anyMatch(f -> f.contains("asymmetry")));

        Connection upload = new Connection(new FiveTuple(0x0a000001, 0x0a000002, 1234, 443, 6));
        upload.appType = AppType.YOUTUBE;
        upload.sni = "www.youtube.com";
        upload.bytesOut = 5_000_000;
        upload.bytesIn = 1_000;
        assertTrue(RiskAnalyzer.assess(upload).findings().stream().anyMatch(f -> f.contains("asymmetry")));
    }
}
