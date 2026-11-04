package com.deeppacket.monitoring;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PrometheusMetricsTest {
    @Test
    void rendersGaugesInExpositionFormat() {
        PrometheusMetrics pm = PrometheusMetrics.getInstance();
        pm.setGauge("unit_test_gauge", 42);
        pm.setGauge("unit_test_fraction", 1.5);
        String text = pm.render();
        assertTrue(text.contains("# TYPE unit_test_gauge gauge\nunit_test_gauge 42\n"));
        assertTrue(text.contains("unit_test_fraction 1.500000"));
    }

    @Test
    void sanitisesNamesAndEscapesLabelValues() {
        PrometheusMetrics pm = PrometheusMetrics.getInstance();
        pm.setLabeledGauge("unit test-labeled", Map.of("domain", "a\"b\\c"), 3);
        String text = pm.render();
        assertTrue(text.contains("unit_test_labeled{domain=\"a\\\"b\\\\c\"} 3"), text);
        pm.clearLabeledMetric("unit test-labeled");
        assertFalse(pm.render().contains("unit_test_labeled"));
    }

    @Test
    void ignoresNonFiniteValues() {
        PrometheusMetrics pm = PrometheusMetrics.getInstance();
        pm.setGauge("unit_test_nan", Double.NaN);
        pm.setGauge("unit_test_inf", Double.POSITIVE_INFINITY);
        String text = pm.render();
        assertFalse(text.contains("unit_test_nan"));
        assertFalse(text.contains("unit_test_inf"));
    }

    @Test
    void clearGaugeRemovesIt() {
        PrometheusMetrics pm = PrometheusMetrics.getInstance();
        pm.setGauge("unit_test_clear", 1);
        pm.clearGauge("unit_test_clear");
        assertFalse(pm.render().contains("unit_test_clear"));
    }
}
