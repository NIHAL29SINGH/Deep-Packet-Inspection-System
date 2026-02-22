package com.deeppacket.app;

import com.deeppacket.engine.DPIEngine;
import com.deeppacket.engine.LiveCaptureService;
import com.deeppacket.monitoring.PrometheusMetrics;
import com.deeppacket.monitoring.PrometheusMetricsServer;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class DpiMain {
    private static void usage(String program) {
        System.out.println("""
            Usage (pcap mode): %s <input.pcap> <output.pcap> [options]
            Usage (live mode): %s --live <output.pcap> [options]

            Options:
              --block-ip <ip>
              --block-app <app>
              --block-domain <domain>
              --report-csv <file>
              --report-json <file>
              --rules <file>
              --save-rules <file>
              --lbs <n>
              --fps <n>
              --verbose
              --live
              --iface <name>
              --duration <sec>
              --capture-out <input_live.pcap>
              --bpf <filter>
              --no-metrics
              --metrics-bind <addr>
              --metrics-port <port>
              --metrics-hold <sec>
              --metrics-file <file>
              --list-ifaces
              --help, -h

            Examples:
              %s ../test_dpi.pcap ../output.pcap
              %s ../test_dpi.pcap ../output.pcap --block-app YouTube --block-domain facebook
              %s ../test_dpi.pcap ../output.pcap --report-csv ../report.csv
              %s ../test_dpi.pcap ../output.pcap --report-csv ../report.csv --report-json ../report.json
              %s ../test_dpi.pcap ../output.pcap --rules rules.txt --save-rules rules_out.txt
              %s ../test_dpi.pcap ../output.pcap --metrics-port 9400 --metrics-hold 30
              %s --live ../output_live_filtered.pcap --iface Ethernet --duration 20 --capture-out ../live_input.pcap
            """.formatted(program, program, program, program, program, program, program, program, program));
    }

    public static void main(String[] args) {
        String program = "java com.deeppacket.app.DpiMain";
        if (args.length == 0) {
            usage(program);
            System.exit(1);
        }
        if ("--list-ifaces".equals(args[0])) {
            try {
                LiveCaptureService.listInterfaces();
                return;
            } catch (Exception e) {
                System.err.println("Failed to list interfaces: " + e.getMessage());
                System.exit(1);
            }
        }
        if ("--help".equals(args[0]) || "-h".equals(args[0])) {
            usage(program);
            return;
        }

        boolean liveMode = "--live".equals(args[0]);
        String input;
        String output;
        int optionStart;
        String iface = "";
        int durationSec = 15;
        String captureOut = "../live_capture_input.pcap";
        String bpf = "ip and tcp or ip and udp";
        boolean metricsEnabled = true;
        String metricsBind = "0.0.0.0";
        int metricsPort = 9400;
        int metricsHoldSec = 0;
        String metricsFile = "./outputs/prometheus_metrics.prom";

        if (liveMode) {
            if (args.length < 2) {
                usage(program);
                System.exit(1);
                return;
            }
            output = args[1];
            optionStart = 2;
            input = "";
        } else {
            if (args.length < 2) {
                usage(program);
                System.exit(1);
                return;
            }
            input = args[0];
            output = args[1];
            optionStart = 2;
        }

        DPIEngine.Config cfg = new DPIEngine.Config();
        String saveRulesFile = "";
        String reportCsvFile = "";
        String reportJsonFile = "";
        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();

        for (int i = optionStart; i < args.length; i++) {
            String arg = args[i];
            if ("--rules".equals(arg) && i + 1 < args.length) cfg.rulesFile = args[++i];
            else if ("--save-rules".equals(arg) && i + 1 < args.length) saveRulesFile = args[++i];
            else if ("--report-csv".equals(arg) && i + 1 < args.length) reportCsvFile = args[++i];
            else if ("--report-json".equals(arg) && i + 1 < args.length) reportJsonFile = args[++i];
            else if ("--lbs".equals(arg) && i + 1 < args.length) cfg.numLoadBalancers = Integer.parseInt(args[++i]);
            else if ("--fps".equals(arg) && i + 1 < args.length) cfg.fpsPerLb = Integer.parseInt(args[++i]);
            else if ("--iface".equals(arg) && i + 1 < args.length) iface = args[++i];
            else if ("--duration".equals(arg) && i + 1 < args.length) durationSec = Integer.parseInt(args[++i]);
            else if ("--capture-out".equals(arg) && i + 1 < args.length) captureOut = args[++i];
            else if ("--bpf".equals(arg) && i + 1 < args.length) bpf = args[++i];
            else if ("--no-metrics".equals(arg)) metricsEnabled = false;
            else if ("--metrics-bind".equals(arg) && i + 1 < args.length) metricsBind = args[++i];
            else if ("--metrics-port".equals(arg) && i + 1 < args.length) metricsPort = Integer.parseInt(args[++i]);
            else if ("--metrics-hold".equals(arg) && i + 1 < args.length) metricsHoldSec = Integer.parseInt(args[++i]);
            else if ("--metrics-file".equals(arg) && i + 1 < args.length) metricsFile = args[++i];
            else if ("--block-ip".equals(arg) && i + 1 < args.length) blockIps.add(args[++i]);
            else if ("--block-app".equals(arg) && i + 1 < args.length) blockApps.add(args[++i]);
            else if ("--block-domain".equals(arg) && i + 1 < args.length) blockDomains.add(args[++i]);
            else if ("--live".equals(arg)) {}
            else if ("--verbose".equals(arg)) cfg.verbose = true;
            else if ("--list-ifaces".equals(arg)) {}
            else if ("--help".equals(arg) || "-h".equals(arg)) {
                usage(program);
                return;
            } else if (arg.startsWith("--")) {
                System.err.println("Unknown option: " + arg);
                usage(program);
                System.exit(1);
            }
        }

        if (cfg.numLoadBalancers <= 0 || cfg.fpsPerLb <= 0) {
            System.err.println("Error: --lbs and --fps must be positive integers.");
            System.exit(1);
        }
        if (durationSec <= 0) {
            System.err.println("Error: --duration must be positive.");
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

        if (liveMode) {
            try {
                var cap = LiveCaptureService.capture(iface, durationSec, captureOut, bpf, cfg.verbose);
                input = cap.captureFile();
                System.out.println("[Live] Capture complete. Starting DPI processing...");
            } catch (Exception e) {
                System.err.println("Live capture failed: " + e.getMessage());
                System.exit(1);
            }
        }

        DPIEngine engine = new DPIEngine(cfg);
        if (!engine.initialize()) {
            System.err.println("Failed to initialize DPI engine");
            System.exit(1);
        }

        for (String ip : blockIps) engine.blockIP(ip);
        for (String app : blockApps) {
            try {
                engine.blockApp(app);
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                System.exit(1);
            }
        }
        for (String domain : blockDomains) engine.blockDomain(domain);

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
