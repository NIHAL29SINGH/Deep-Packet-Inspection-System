package com.deeppacket.monitoring;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class PrometheusMetricsServer {
    private HttpServer server;
    private ExecutorService executor;

    public synchronized boolean start(String bindAddress, int port) {
        if (server != null) return true;
        try {
            server = HttpServer.create(new InetSocketAddress(bindAddress, port), 0);
            executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "prometheus-metrics-http");
                t.setDaemon(true);
                return t;
            });
            server.setExecutor(executor);
            server.createContext("/metrics", new MetricsHandler());
            server.start();
            return true;
        } catch (IOException e) {
            server = null;
            if (executor != null) {
                executor.shutdownNow();
                executor = null;
            }
            return false;
        }
    }

    public synchronized void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    private static final class MetricsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String body = PrometheusMetrics.getInstance().render();
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
            exchange.sendResponseHeaders(200, payload.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(payload);
            }
        }
    }
}

