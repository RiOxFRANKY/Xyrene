
package com.mitm.ids.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable domain model representing a captured packet's data
 * to be sent to the Python ML API for classification.
 *
 * <p>Uses the Builder pattern with validation.
 * Never exposes mutable internal state.</p>
 */
public final class PacketData {

    private final String srcIp;
    private final String dstIp;
    private final String protocol;
    private final int length;
    private final String payload;  // Base64-encoded
    private final String timestamp; // ISO-8601
    private final Map<String, Object> features;

    private PacketData(Builder builder) {
        this.srcIp = Objects.requireNonNull(builder.srcIp, "srcIp must not be null");
        this.dstIp = Objects.requireNonNull(builder.dstIp, "dstIp must not be null");
        this.protocol = Objects.requireNonNull(builder.protocol, "protocol must not be null");
        this.length = builder.length;
        this.payload = builder.payload != null ? builder.payload : "";
        this.timestamp = Objects.requireNonNull(builder.timestamp, "timestamp must not be null");
        this.features = Collections.unmodifiableMap(new HashMap<>(builder.features));
    }

    @JsonProperty("src_ip")
    public String getSrcIp() { return srcIp; }

    @JsonProperty("dst_ip")
    public String getDstIp() { return dstIp; }

    @JsonProperty("protocol")
    public String getProtocol() { return protocol; }

    @JsonProperty("length")
    public int getLength() { return length; }

    @JsonProperty("payload")
    public String getPayload() { return payload; }

    @JsonProperty("timestamp")
    public String getTimestamp() { return timestamp; }

    @JsonProperty("features")
    public Map<String, Object> getFeatures() { return features; }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        return String.format("PacketData[%s->%s, %s, %d bytes]",
                srcIp, dstIp, protocol, length);
    }

    public static final class Builder {
        private String srcIp;
        private String dstIp;
        private String protocol;
        private int length;
        private String payload;
        private String timestamp;
        private final Map<String, Object> features = new HashMap<>();

        public Builder srcIp(String srcIp) {
            this.srcIp = srcIp;
            return this;
        }

        public Builder dstIp(String dstIp) {
            this.dstIp = dstIp;
            return this;
        }

        public Builder protocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder length(int length) {
            if (length < 0) throw new IllegalArgumentException("length must be >= 0");
            this.length = length;
            return this;
        }

        public Builder payload(String payload) {
            this.payload = payload;
            return this;
        }

        public Builder timestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder feature(String key, Object value) {
            this.features.put(key, value);
            return this;
        }

        public Builder features(Map<String, Object> features) {
            this.features.putAll(features);
            return this;
        }

        public PacketData build() {
            return new PacketData(this);
        }
    }
}
