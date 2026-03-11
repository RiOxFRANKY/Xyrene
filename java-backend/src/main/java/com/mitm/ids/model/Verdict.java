
package com.mitm.ids.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Immutable verdict returned by the Python ML API.
 * Mirrors the VerdictResult structure from the Python backend.
 *
 * <p>Contains classification zone, confidence score, enforcement action,
 * and blocklist status. Provides safe factory methods for fallbacks.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Verdict(
    @JsonProperty("packet_id") String packetId,
    @JsonProperty("src_ip") String srcIp,
    @JsonProperty("verdict") Zone zone,
    @JsonProperty("confidence") float confidence,
    @JsonProperty("action") Action action,
    @JsonProperty("blocked") boolean blocked,
    @JsonProperty("ip_event_count") int ipEventCount,
    @JsonProperty("timestamp") String timestamp
) {

    /**
     * Classification zone — must match Python Zone enum.
     */
    public enum Zone {
        BENIGN, SUSPICIOUS, MALICIOUS, CRITICAL, BLOCKED;

        public boolean isDangerous() {
            return this == MALICIOUS || this == CRITICAL || this == BLOCKED;
        }
    }

    /**
     * Enforcement action — must match Python Action enum.
     */
    public enum Action {
        PASS, FLAG, DROP;

        public boolean isBlocking() {
            return this == DROP;
        }
    }

    /**
     * Create a safe fallback verdict when the API cannot be reached.
     */
    public static Verdict unknown(String errorMessage) {
        return new Verdict(
            "error", "0.0.0.0", Zone.BENIGN, 0.0f,
            Action.PASS, false, 0,
            errorMessage
        );
    }

    /**
     * Create a blocked verdict for locally-tracked blocked IPs.
     */
    public static Verdict blocked(String srcIp) {
        return new Verdict(
            "local-block", srcIp, Zone.BLOCKED, 1.0f,
            Action.DROP, true, 0,
            java.time.Instant.now().toString()
        );
    }

    /**
     * Check if this verdict represents a dangerous classification.
     */
    public boolean isDangerous() {
        return zone != null && zone.isDangerous();
    }

    /**
     * Check if this verdict resulted in the IP being blocked.
     */
    public boolean isDropped() {
        return action != null && action.isBlocking();
    }

    @Override
    public String toString() {
        return String.format("Verdict[%s | %s | conf=%.4f | action=%s | blocked=%s]",
                srcIp, zone, confidence, action, blocked);
    }
}
