package com.deeppacket.app;

import com.deeppacket.engine.DPIEngine;
import com.deeppacket.monitoring.PrometheusMetrics;
import com.deeppacket.monitoring.PrometheusMetricsServer;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line entry point. DPI Sentinel analyses packet capture files offline; it never captures live traffic.
 */
public class DpiMain {
    private static void usage(String program) {
        System.out.println("""
            Usage: %1$s <input.pcap|input.pcapng> <output.pcap> [options]

            Reads a capture file (classic pcap or pcapng, Ethernet), classifies flows, applies rules,
            and writes the forwarded packets to <output.pcap>. Offline analysis only.

            Rules:
              --block-ip <ip>            block traffic to or from an IPv4 address
              --block-app <app>          block an application (for example YouTube)
              --block-domain <domain>    block a domain, its subdomains, or a bare keyword label
              --block-port <port>        block a destination port
              --block-ja3 <md5>          block TLS clients by JA3 fingerprint (32 hex characters)
              --rules <file>             load rules from a file
              --save-rules <file>        save the effective rules to a file
              --risk-rules <file>        load risk-scoring weights (properties file)

            Reports:
              --report-csv <file>
              --report-json <file>
              --report-html <file>

            Engine:
              --lbs <n>                  load-balancer threads (default 2)
              --fps <n>                  workers per load balancer (default 2)
              --verbose

            Metrics:
              --no-metrics
              --metrics-bind <addr>      default 127.0.0.1
              --metrics-port <port>      default 9400
              --metrics-hold <sec>       keep the endpoint up after the run for scraping
              --metrics-file <file>

              --help, -h

            Examples:
              %1$s sample_traffic.pcap out.pcap
              %1$s sample_traffic.pcap out.pcap --block-app YouTube --block-domain facebook
              %1$s capture.pcapng out.pcap --report-html report.html --report-json report.json
              %1$s sample_traffic.pcap out.pcap --block-ja3 e7d705a3286e19ea42f587b344ee6865
            """.formatted(program));
    }

    public static void main(String[] args) {
        String program = "java com.deeppacket.app.DpiMain";
        if (args.length == 0) {
            usage(program);
            System.exit(1);
        }
        if ("--help".equals(args[0]) || "-h".equals(args[0])) {
            usage(program);
            return;
        }
        if (args.length < 2 || args[0].startsWith("--") || args[1].startsWith("--")) {
            System.err.println("Error: expected <input> <output> before any option.");
            usage(program);
            System.exit(1);
        }

        String input = args[0];
        String output = args[1];
        boolean metricsEnabled = true;
        String metricsBind = "127.0.0.1"; // loopback by default; see docs/THREAT_MODEL.md
        int metricsPort = 9400;
        int metricsHoldSec = 0;
        String metricsFile = "./outputs/prometheus_metrics.prom";

        DPIEngine.Config cfg = new DPIEngine.Config();
        String saveRulesFile = "";
        String reportCsvFile = "";
        String reportJsonFile = "";
        String reportHtmlFile = "";
        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        List<String> blockPorts = new ArrayList<>();
        List<String> blockJa3 = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            boolean hasValue = i + 1 < args.length;
            try {
                if ("--rules".equals(arg) && hasValue) cfg.rulesFile = args[++i];
                else if ("--risk-rules".equals(arg) && hasValue) cfg.riskRulesFile = args[++i];
                else if ("--save-rules".equals(arg) && hasValue) saveRulesFile = args[++i];
                else if ("--report-csv".equals(arg) && hasValue) reportCsvFile = args[++i];
                else if ("--report-json".equals(arg) && hasValue) reportJsonFile = args[++i];
                else if ("--report-html".equals(arg) && hasValue) reportHtmlFile = args[++i];
                else if ("--lbs".equals(arg) && hasValue) cfg.numLoadBalancers = Integer.parseInt(args[++i]);
                else if ("--fps".equals(arg) && hasValue) cfg.fpsPerLb = Integer.parseInt(args[++i]);
                else if ("--no-metrics".equals(arg)) metricsEnabled = false;
                else if ("--metrics-bind".equals(arg) && hasValue) metricsBind = args[++i];
                else if ("--metrics-port".equals(arg) && hasValue) metricsPort = Integer.parseInt(args[++i]);
                else if ("--metrics-hold".equals(arg) && hasValue) metricsHoldSec = Integer.parseInt(args[++i]);
                else if ("--metrics-file".equals(arg) && hasValue) metricsFile = args[++i];
                else if ("--block-ip".equals(arg) && hasValue) blockIps.add(args[++i]);
                else if ("--block-app".equals(arg) && hasValue) blockApps.add(args[++i]);
                else if ("--block-domain".equals(arg) && hasValue) blockDomains.add(args[++i]);
                else if ("--block-port".equals(arg) && hasValue) blockPorts.add(args[++i]);
                else if ("--block-ja3".equals(arg) && hasValue) blockJa3.add(args[++i]);
                else if ("--verbose".equals(arg)) cfg.verbose = true;
                else if ("--help".equals(arg) || "-h".equals(arg)) {
                    usage(program);
                    return;
                } else {
                    System.err.println(arg.startsWith("--")
                        ? (hasValue ? "Unknown option: " + arg : "Option needs a value: " + arg)
                        : "Unexpected argument: " + arg + " (the capture and output files must come first)");
                    usage(program);
                    System.exit(1);
                }
            } catch (NumberFormatException e) {
                System.err.println("Error: option " + arg + " needs a number, got '" + args[i] + "'.");
                System.exit(1);
            }
        }

        if (cfg.numLoadBalancers <= 0 || cfg.fpsPerLb <= 0) {
            System.err.println("Error: --lbs and --fps must be positive integers.");
            System.exit(1);
        }
        if (metricsPort <= 0 || metricsPort > 65535) {
            System.err.println("Error: --metrics-port must be in range 1..65535.");
            System.exit(1);
        }
        if (metricsHoldSec < 0) {
            System.err.println("Error: --metrics-hold must be >= 0.");
            System.exit(1);
        }

        DPIEngine engine = new DPIEngine(cfg);
        if (!engine.initialize()) {
            System.err.println("Failed to initialize DPI engine");
            System.exit(1);
        }

        try {
            for (String ip : blockIps) engine.blockIP(ip);
            for (String app : blockApps) engine.blockApp(app);
            for (String domain : blockDomains) engine.blockDomain(domain);
            for (String port : blockPorts) engine.blockPort(Integer.parseInt(port));
            for (String ja3 : blockJa3) engine.blockJa3(ja3);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid rule: " + e.getMessage());
            System.exit(1);
        }

        PrometheusMetricsServer metricsServer = null;
        if (metricsEnabled) {
            metricsServer = new PrometheusMetricsServer();
            if (metricsServer.start(metricsBind, metricsPort)) {
                System.out.println("[Metrics] Prometheus endpoint: http://" + metricsBind + ":" + metricsPort + "/metrics");
            } else {
                System.err.println("[Metrics] Failed to start metrics endpoint on " + metricsBind + ":" + metricsPort);
            }
        }

        boolean ok = engine.processFile(input, output);
        System.out.println(engine.generateReport());

        if (metricsEnabled && !metricsFile.isEmpty()) {
            if (PrometheusMetrics.getInstance().writeToFile(Paths.get(metricsFile))) {
                System.out.println("[Metrics] Prometheus file: " + metricsFile);
            } else {
                System.err.println("[Metrics] Failed to write metrics file: " + metricsFile);
            }
        }
        if (!saveRulesFile.isEmpty()) {
            if (!engine.saveRules(saveRulesFile)) {
                System.err.println("Failed to save rules to: " + saveRulesFile);
                System.exit(1);
            }
            System.out.println("Rules saved to: " + saveRulesFile);
        }
        if (!reportCsvFile.isEmpty()) {
            if (!engine.exportConnectionCsv(reportCsvFile)) {
                System.err.println("Failed to write CSV report to: " + reportCsvFile);
                System.exit(1);
            }
            System.out.println("CSV report written to: " + reportCsvFile);
        }
        if (!reportJsonFile.isEmpty()) {
            if (!engine.exportReportJson(reportJsonFile)) {
                System.err.println("Failed to write JSON report to: " + reportJsonFile);
                System.exit(1);
            }
            System.out.println("JSON report written to: " + reportJsonFile);
        }
        if (!reportHtmlFile.isEmpty()) {
            if (!engine.exportReportHtml(reportHtmlFile)) {
                System.err.println("Failed to write HTML report to: " + reportHtmlFile);
                System.exit(1);
            }
            System.out.println("HTML analyst report written to: " + reportHtmlFile);
        }
        if (metricsEnabled && metricsHoldSec > 0) {
            System.out.println("[Metrics] Holding for " + metricsHoldSec + "s for scraping...");
            try {
                Thread.sleep(metricsHoldSec * 1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (metricsServer != null) {
            metricsServer.stop();
        }
        if (!ok) System.exit(1);
        System.out.println("Output written to: " + output);
    }
}
