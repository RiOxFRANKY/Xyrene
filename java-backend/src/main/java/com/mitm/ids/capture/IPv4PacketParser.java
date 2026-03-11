
package com.mitm.ids.capture;

import com.mitm.ids.model.PacketData;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

/**
 * Concrete parser for IPv4 traffic.
 * Extracts src/dst IPs, protocol, ports, length, payload, and timestamp.
 */
public class IPv4PacketParser extends AbstractPacketParser {

    private static final int MAX_PAYLOAD_BYTES = 8192;

    @Override
    public boolean supports(Packet packet) {
        return packet != null && packet.contains(IpV4Packet.class);
    }

    @Override
    protected PacketData doParse(Packet packet) {
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        if (ipv4 == null) return null;

        String srcIp = ipv4.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipv4.getHeader().getDstAddr().getHostAddress();
        int totalLength = packet.length();

        PacketData.Builder builder = PacketData.builder()
                .srcIp(srcIp)
                .dstIp(dstIp)
                .length(totalLength)
                .timestamp(nowTimestamp());

        // Extract transport layer info
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            builder.protocol("TCP")
                   .feature("src_port", tcp.getHeader().getSrcPort().valueAsInt())
                   .feature("dst_port", tcp.getHeader().getDstPort().valueAsInt())
                   .feature("tcp_flags_syn", tcp.getHeader().getSyn() ? 1 : 0)
                   .feature("tcp_flags_ack", tcp.getHeader().getAck() ? 1 : 0)
                   .feature("tcp_flags_fin", tcp.getHeader().getFin() ? 1 : 0)
                   .feature("tcp_flags_rst", tcp.getHeader().getRst() ? 1 : 0)
                   .feature("tcp_flags_psh", tcp.getHeader().getPsh() ? 1 : 0)
                   .feature("tcp_flags_urg", tcp.getHeader().getUrg() ? 1 : 0);

            // Encode TCP payload
            if (tcp.getPayload() != null) {
                builder.payload(encodePayload(tcp.getPayload().getRawData(), MAX_PAYLOAD_BYTES));
            }
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            builder.protocol("UDP")
                   .feature("src_port", udp.getHeader().getSrcPort().valueAsInt())
                   .feature("dst_port", udp.getHeader().getDstPort().valueAsInt());

            if (udp.getPayload() != null) {
                builder.payload(encodePayload(udp.getPayload().getRawData(), MAX_PAYLOAD_BYTES));
            }
        } else {
            builder.protocol("OTHER");
        }

        // IP-level features
        builder.feature("ip_ttl", ipv4.getHeader().getTtlAsInt())
               .feature("ip_header_length", ipv4.getHeader().getIhlAsInt() * 4)
               .feature("ip_total_length", totalLength);

        return builder.build();
    }
}
