
package com.mitm.ids.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Singleton configuration loader for the IDS.
 * Reads config/config.json with hardcoded defaults for missing keys.
 */
public final class AppConfig {
    private static volatile AppConfig INSTANCE;
    private final Map<String, Object> props;

    private static final Map<String, Object> DEFAULTS = Map.ofEntries(
            Map.entry("ml.api.url", "http://127.0.0.1:8000"),
            Map.entry("ml.api.timeout.connect", 2000),
            Map.entry("ml.api.timeout.read", 5000),
            Map.entry("ml.api.retries", 3),
            Map.entry("ml.api.retry.delay", 500),
            Map.entry("pcap.device", ""),
            Map.entry("pcap.snaplen", 65536),
            Map.entry("pcap.timeout", 10),
            Map.entry("log.dir", "logs"),
            Map.entry("log.file", "ids.log"),
            Map.entry("whitelist.path", "config/whitelist.txt")
    );

    @SuppressWarnings("unchecked")
    private AppConfig(String path) {
        Map<String, Object> loaded = new HashMap<>(DEFAULTS);
        File file = new File(path);
        if (file.exists()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                Map<String, Object> userConfig = mapper.readValue(
                        file, new TypeReference<Map<String, Object>>() {});
                flattenAndMerge(loaded, userConfig, "");
            } catch (IOException e) {
                System.err.println("[AppConfig] Warning: could not parse " + path + ": " + e.getMessage());
            }
        } else {
            System.err.println("[AppConfig] Config file not found: " + path + " — using defaults");
        }
        this.props = Collections.unmodifiableMap(loaded);
    }

    /**
     * Flatten nested JSON into dot-notation keys and merge into target.
     */
    @SuppressWarnings("unchecked")
    private void flattenAndMerge(Map<String, Object> target, Map<String, Object> source, String prefix) {
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            Object val = entry.getValue();
            if (val instanceof Map) {
                flattenAndMerge(target, (Map<String, Object>) val, key);
            } else {
                target.put(key, val);
            }
        }
    }

    public static synchronized void load(String path) {
        INSTANCE = new AppConfig(path);
    }

    public static AppConfig get() {
        if (INSTANCE == null) {
            load("config/config.json");
        }
        return INSTANCE;
    }

    public String getString(String key, String defaultValue) {
        Object val = props.get(key);
        return val != null ? val.toString() : defaultValue;
    }

    public int getInt(String key, int defaultValue) {
        Object val = props.get(key);
        if (val instanceof Number) return ((Number) val).intValue();
        if (val instanceof String) {
            try { return Integer.parseInt((String) val); } catch (NumberFormatException ignored) {}
        }
        return defaultValue;
    }

    public long getLong(String key, long defaultValue) {
        Object val = props.get(key);
        if (val instanceof Number) return ((Number) val).longValue();
        if (val instanceof String) {
            try { return Long.parseLong((String) val); } catch (NumberFormatException ignored) {}
        }
        return defaultValue;
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        Object val = props.get(key);
        if (val instanceof Boolean) return (Boolean) val;
        if (val instanceof String) return Boolean.parseBoolean((String) val);
        return defaultValue;
    }

    /**
     * Load whitelisted IPs from the whitelist file.
     */
    public Set<String> loadWhitelist() {
        String path = getString("whitelist.path", "config/whitelist.txt");
        try {
            Path filePath = Path.of(path);
            if (Files.exists(filePath)) {
                return Files.readAllLines(filePath).stream()
                        .map(String::trim)
                        .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                        .collect(Collectors.toSet());
            }
        } catch (IOException e) {
            System.err.println("[AppConfig] Warning: could not read whitelist: " + e.getMessage());
        }
        return Set.of("127.0.0.1");
    }
}
