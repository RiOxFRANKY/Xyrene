
package com.mitm.ids.capture;

import com.mitm.ids.model.PacketData;
import org.pcap4j.packet.Packet;

import java.util.Optional;

/**
 * Interface for protocol-specific packet parsers.
 */
public interface IPacketParser {

    /**
     * Check if this parser can handle the given packet.
     */
    boolean supports(Packet packet);

    /**
     * Parse the packet into a PacketData model.
     * Returns empty if parsing fails.
     */
    Optional<PacketData> parse(Packet packet);
}
