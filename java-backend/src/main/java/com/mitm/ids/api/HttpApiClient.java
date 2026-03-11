
package com.mitm.ids.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mitm.ids.model.PacketData;
import com.mitm.ids.model.Verdict;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Production HTTP client using OkHttp for all Python backend communication.
 * Thread-safe — backed by OkHttp's connection pool.
 */
public class HttpApiClient implements IApiClient {
    private static final Logger logger = LoggerFactory.getLogger(HttpApiClient.class);
    private static final MediaType JSON_TYPE = MediaType.get("application/json; charset=utf-8");

    private final OkHttpClient httpClient;
    private final ObjectMapper mapper;
    private final String baseUrl;

    /**
     * @param baseUrl   Python backend base URL (e.g. "http://127.0.0.1:8000")
     * @param connectTimeoutMs  Connection timeout in milliseconds
     * @param readTimeoutMs     Read timeout in milliseconds
     */
    public HttpApiClient(String baseUrl, int connectTimeoutMs, int readTimeoutMs) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.mapper = new ObjectMapper();
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(connectTimeoutMs, TimeUnit.MILLISECONDS)
                .readTimeout(readTimeoutMs, TimeUnit.MILLISECONDS)
                .writeTimeout(readTimeoutMs, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(false)
                .build();
    }

    @Override
    public Verdict analyze(PacketData data) {
        try {
            String json = mapper.writeValueAsString(data);
            RequestBody body = RequestBody.create(json, JSON_TYPE);
            Request request = new Request.Builder()
                    .url(baseUrl + "/api/analyze")
                    .post(body)
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    return mapper.readValue(response.body().string(), Verdict.class);
                }
                logger.warn("Analyze call returned HTTP {}", response.code());
                return Verdict.unknown("HTTP " + response.code());
            }
        } catch (IOException e) {
            logger.error("Analyze API call failed: {}", e.getMessage());
            return Verdict.unknown("Connection failed: " + e.getMessage());
        }
    }

    @Override
    public boolean isHealthy() {
        try {
            Request request = new Request.Builder()
                    .url(baseUrl + "/health")
                    .get()
                    .build();
            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    JsonNode node = mapper.readTree(response.body().string());
                    return "ok".equalsIgnoreCase(node.path("status").asText());
                }
            }
        } catch (IOException e) {
            logger.debug("Health check failed: {}", e.getMessage());
        }
        return false;
    }

    @Override
    public List<String> getBlocklist() {
        try {
            Request request = new Request.Builder()
                    .url(baseUrl + "/api/blocklist")
                    .get()
                    .build();
            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    JsonNode node = mapper.readTree(response.body().string());
                    List<String> ips = new ArrayList<>();
                    JsonNode blockedArray = node.path("blocked_ips");
                    if (blockedArray.isArray()) {
                        for (JsonNode entry : blockedArray) {
                            String ip = entry.path("ip").asText(entry.asText());
                            if (!ip.isEmpty()) ips.add(ip);
                        }
                    }
                    return ips;
                }
            }
        } catch (IOException e) {
            logger.error("Failed to fetch blocklist: {}", e.getMessage());
        }
        return List.of();
    }

    @Override
    public boolean blockIp(String ip) {
        return postIpAction("/api/blocklist/add", ip);
    }

    @Override
    public boolean unblockIp(String ip) {
        return postIpAction("/api/blocklist/remove", ip);
    }

    private boolean postIpAction(String endpoint, String ip) {
        try {
            String json = mapper.writeValueAsString(Map.of("ip", ip));
            RequestBody body = RequestBody.create(json, JSON_TYPE);
            Request request = new Request.Builder()
                    .url(baseUrl + endpoint)
                    .post(body)
                    .build();
            try (Response response = httpClient.newCall(request).execute()) {
                return response.isSuccessful();
            }
        } catch (IOException e) {
            logger.error("Failed to {} IP {}: {}", endpoint, ip, e.getMessage());
            return false;
        }
    }
}
