
package com.mitm.ids.capture;

import com.mitm.ids.model.PacketData;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Factory and registry for packet parsers.
 * Iterates through registered parsers and returns the first matching result.
 */
public class PacketParserFactory {
    private final List<IPacketParser> parsers = new ArrayList<>();

    public PacketParserFactory() {
        // Register default parsers
        parsers.add(new IPv4PacketParser());
    }

    /**
     * Parse a raw packet using the first matching parser.
     *
     * @return Optional containing parsed data, or empty if no parser matched
     */
    public Optional<PacketData> parse(Packet packet) {
        if (packet == null) return Optional.empty();

        for (IPacketParser parser : parsers) {
            Optional<PacketData> result = parser.parse(packet);
            if (result.isPresent()) {
                return result;
            }
        }
        return Optional.empty();
    }

    /**
     * Register a custom parser. Added to front for override priority.
     */
    public void registerParser(IPacketParser parser) {
        parsers.add(0, parser);
    }
}
