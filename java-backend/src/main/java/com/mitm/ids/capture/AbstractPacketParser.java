
package com.mitm.ids.capture;

import com.mitm.ids.model.PacketData;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Skeletal implementation of IPacketParser using the Template Method pattern.
 * Provides helper utilities for Base64 encoding and timestamps.
 */
public abstract class AbstractPacketParser implements IPacketParser {
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public final Optional<PacketData> parse(Packet packet) {
        if (!supports(packet)) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(doParse(packet));
        } catch (Exception e) {
            logger.warn("Parser {} failed on packet: {}", getClass().getSimpleName(), e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Subclass hook: extract fields from the packet.
     */
    protected abstract PacketData doParse(Packet packet);

    /**
     * Encode raw bytes to Base64 string with length limit.
     */
    protected String encodePayload(byte[] raw, int maxBytes) {
        if (raw == null || raw.length == 0) return "";
        int len = Math.min(raw.length, maxBytes);
        byte[] slice = new byte[len];
        System.arraycopy(raw, 0, slice, 0, len);
        return Base64.getEncoder().encodeToString(slice);
    }

    /**
     * Get current ISO-8601 timestamp.
     */
    protected String nowTimestamp() {
        return Instant.now().toString();
    }
}
