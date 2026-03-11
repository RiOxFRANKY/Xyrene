package com.mitm.ids.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mitm.ids.capture.Pcap4jCapture;
import com.mitm.ids.util.FirewallService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import okhttp3.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class ApiServer {
    private final HttpServer server;
    private final String pythonApiUrl;
    private final IApiClient apiClient;
    private final FirewallService firewallService;
    private final Pcap4jCapture capture;
    private final VerdictHandler verdictHandler;
    private final OkHttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

    public ApiServer(int port, String pythonApiUrl, IApiClient apiClient, FirewallService firewallService, Pcap4jCapture capture, VerdictHandler verdictHandler) throws IOException {
        this.pythonApiUrl = pythonApiUrl;
        this.apiClient = apiClient;
        this.firewallService = firewallService;
        this.capture = capture;
        this.verdictHandler = verdictHandler;
        this.httpClient = new OkHttpClient();

        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // CORS and Proxy handler for all /api/
        this.server.createContext("/api", new ApiHandler());
        this.server.setExecutor(null); // default executor
    }

    public int getPort() {
        return server.getAddress().getPort();
    }

    public void start() {
        server.start();
        System.out.println("[ApiServer] Started Java Reverse Proxy on port " + server.getAddress().getPort());
    }

    public void stop() {
        server.stop(0);
        System.out.println("[ApiServer] Stopped Java Reverse Proxy");
    }

    private class ApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                // Add CORS headers
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");

                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                String path = exchange.getRequestURI().getPath();
                String method = exchange.getRequestMethod();

                // 1. CAPTURE CONTROL ENDPOINTS
                if ("POST".equalsIgnoreCase(method) && "/api/capture/start".equals(path)) {
                    handleStartCapture(exchange);
                    return;
                }
                if ("POST".equalsIgnoreCase(method) && "/api/capture/stop".equals(path)) {
                    handleStopCapture(exchange);
                    return;
                }

                // 2. BLOCKLIST INTERCEPTION ENDPOINTS
                if ("POST".equalsIgnoreCase(method) && "/api/blocklist/add".equals(path)) {
                    handleBlock(exchange);
                    return;
                }
                if ("POST".equalsIgnoreCase(method) && "/api/blocklist/remove".equals(path)) {
                    handleUnblock(exchange);
                    return;
                }

                // 3. FALLBACK PROXY (Stats, Logs, Packets, etc)
                proxyRequest(exchange);

            } catch (Exception e) {
                e.printStackTrace();
                sendError(exchange, 500, "Internal Server Error: " + e.getMessage());
            }
        }

        private void handleStartCapture(HttpExchange exchange) throws IOException {
            if (capture.isRunning()) {
                sendJsonResponse(exchange, 400, "{\"error\": \"Capture is already running\"}");
                return;
            }
            try {
                capture.start(null); // Will auto-select best interface as per CLI logic
                sendJsonResponse(exchange, 200, "{\"success\": true, \"message\": \"Capture started\"}");
            } catch (Exception e) {
                sendJsonResponse(exchange, 500, "{\"error\": \"" + e.getMessage() + "\"}");
            }
        }

        private void handleStopCapture(HttpExchange exchange) throws IOException {
            if (!capture.isRunning()) {
                sendJsonResponse(exchange, 400, "{\"error\": \"Capture is not running\"}");
                return;
            }
            capture.stop();
            sendJsonResponse(exchange, 200, "{\"success\": true, \"message\": \"Capture stopped\"}");
        }

        private void handleBlock(HttpExchange exchange) throws IOException {
            InputStream is = exchange.getRequestBody();
            JsonNode body = mapper.readTree(is);
            String ip = body.has("ip") ? body.get("ip").asText() : null;
            Integer duration = body.has("duration_sec") && !body.get("duration_sec").isNull() ? body.get("duration_sec").asInt() : null;

            if (ip == null || ip.isEmpty()) {
                sendJsonResponse(exchange, 400, "{\"error\": \"IP is required\"}");
                return;
            }

            // A. Windows Firewall (Java side)
            try {
                firewallService.blockIp(ip);
            } catch (Exception e) {
                System.err.println("[ApiServer] Firewall error: " + e.getMessage());
            }

            // B. Python Policy (Remote side)
            boolean success = apiClient.blockIp(ip);
            if (success) {
                sendJsonResponse(exchange, 200, "{\"success\": true, \"message\": \"IP blocked at OS and Engine level\"}");
            } else {
                sendJsonResponse(exchange, 500, "{\"error\": \"Failed to sync block with Python Engine\"}");
            }
        }

        private void handleUnblock(HttpExchange exchange) throws IOException {
            InputStream is = exchange.getRequestBody();
            JsonNode body = mapper.readTree(is);
            String ip = body.has("ip") ? body.get("ip").asText() : null;

            if (ip == null || ip.isEmpty()) {
                sendJsonResponse(exchange, 400, "{\"error\": \"IP is required\"}");
                return;
            }

            // A. Windows Firewall (Java side)
            try {
                firewallService.unblockIp(ip);
            } catch (Exception e) {
                System.err.println("[ApiServer] Firewall error: " + e.getMessage());
            }

            // B. Python Policy (Remote side)
            boolean success = apiClient.unblockIp(ip);
            if (success) {
                sendJsonResponse(exchange, 200, "{\"success\": true, \"message\": \"IP unblocked at OS and Engine level\"}");
            } else {
                sendJsonResponse(exchange, 500, "{\"error\": \"Failed to sync unblock with Python Engine\"}");
            }
        }

        private void proxyRequest(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            String query = exchange.getRequestURI().getRawQuery();
            String path = exchange.getRequestURI().getPath();
            
            String targetUrl = pythonApiUrl + path.replace("/api", "");
            if (query != null && !query.isEmpty()) {
                targetUrl += "?" + query;
            }

            Request.Builder reqBuilder = new Request.Builder().url(targetUrl);
            
            if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) {
                InputStream is = exchange.getRequestBody();
                byte[] bodyBytes = is.readAllBytes();
                RequestBody reqBody = RequestBody.create(bodyBytes, MediaType.parse("application/json"));
                reqBuilder.method(method, reqBody);
            } else {
                reqBuilder.method(method, null);
            }

            try (Response response = httpClient.newCall(reqBuilder.build()).execute()) {
                int code = response.code();
                ResponseBody body = response.body();
                byte[] respBytes = body != null ? body.bytes() : new byte[0];

                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(code, respBytes.length == 0 ? -1 : respBytes.length);

                if (respBytes.length > 0) {
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                }
            }
        }

        private void sendJsonResponse(HttpExchange exchange, int statusCode, String json) throws IOException {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
            sendJsonResponse(exchange, statusCode, "{\"error\": \"" + message + "\"}");
        }
    }
}
