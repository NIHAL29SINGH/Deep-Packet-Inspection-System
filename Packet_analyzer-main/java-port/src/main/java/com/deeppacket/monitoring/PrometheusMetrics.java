package com.deeppacket.monitoring;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class PrometheusMetrics {
    private static final PrometheusMetrics INSTANCE = new PrometheusMetrics();

    private final ConcurrentMap<String, Double> scalars = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ConcurrentMap<String, Double>> labeled = new ConcurrentHashMap<>();

    private PrometheusMetrics() {}

    public static PrometheusMetrics getInstance() {
        return INSTANCE;
    }

    public void setGauge(String name, double value) {
        if (Double.isFinite(value)) {
            scalars.put(sanitizeName(name), value);
        }
    }

    public void clearGauge(String name) {
        scalars.remove(sanitizeName(name));
    }

    public void setLabeledGauge(String name, Map<String, String> labels, double value) {
        if (!Double.isFinite(value)) return;
        String metric = sanitizeName(name);
        String labelKey = labelsToKey(labels);
        labeled.computeIfAbsent(metric, k -> new ConcurrentHashMap<>()).put(labelKey, value);
    }

    public void clearLabeledMetric(String name) {
        labeled.remove(sanitizeName(name));
    }

    public String render() {
        StringBuilder sb = new StringBuilder();
        List<String> scalarNames = new ArrayList<>(scalars.keySet());
        Collections.sort(scalarNames);
        for (String metric : scalarNames) {
            sb.append("# TYPE ").append(metric).append(" gauge\n");
            sb.append(metric).append(" ").append(formatValue(scalars.get(metric))).append('\n');
        }

        List<String> labeledNames = new ArrayList<>(labeled.keySet());
        Collections.sort(labeledNames);
        for (String metric : labeledNames) {
            sb.append("# TYPE ").append(metric).append(" gauge\n");
            ConcurrentMap<String, Double> entries = labeled.get(metric);
            if (entries == null) continue;

            List<Map.Entry<String, Double>> rows = new ArrayList<>(entries.entrySet());
            rows.sort(Comparator.comparing(Map.Entry::getKey));
            for (Map.Entry<String, Double> row : rows) {
                sb.append(metric).append('{').append(row.getKey()).append("} ").append(formatValue(row.getValue())).append('\n');
            }
        }
        return sb.toString();
    }

    public boolean writeToFile(Path output) {
        try {
            Path parent = output.getParent();
            if (parent != null) Files.createDirectories(parent);
            Files.writeString(output, render(), StandardCharsets.UTF_8);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static String sanitizeName(String name) {
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if ((c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '_' || c == ':') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        return sb.toString();
    }

    private static String labelsToKey(Map<String, String> labels) {
        List<Map.Entry<String, String>> entries = new ArrayList<>(labels.entrySet());
        entries.sort(Comparator.comparing(Map.Entry::getKey));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < entries.size(); i++) {
            Map.Entry<String, String> e = entries.get(i);
            if (i > 0) sb.append(',');
            sb.append(sanitizeName(e.getKey())).append("=\"").append(escapeLabelValue(e.getValue())).append('"');
        }
        return sb.toString();
    }

    private static String escapeLabelValue(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String formatValue(Double value) {
        if (value == null || !Double.isFinite(value)) return "0";
        long asLong = value.longValue();
        if (Math.abs(value - asLong) < 1e-9) return Long.toString(asLong);
        return String.format(java.util.Locale.US, "%.6f", value);
    }
}

