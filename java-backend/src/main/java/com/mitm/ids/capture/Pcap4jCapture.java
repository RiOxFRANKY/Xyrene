
package com.mitm.ids.capture;

import com.mitm.ids.model.PacketData;
import com.mitm.ids.util.AppConfig;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.Optional;

/**
 * Concrete packet capture engine using Pcap4j.
 * Runs in the background thread managed by AbstractPacketCapture.
 */
public class Pcap4jCapture extends AbstractPacketCapture {
    private final PacketParserFactory parserFactory;
    private volatile PcapHandle handle;

    public Pcap4jCapture(PacketParserFactory parserFactory) {
        this.parserFactory = parserFactory;
    }

    @Override
    protected void runCaptureLoop(String interfaceName) {
        int snaplen = AppConfig.get().getInt("pcap.snaplen", 65536);
        int timeout = AppConfig.get().getInt("pcap.timeout", 10);

        try {
            PcapNetworkInterface nif = null;
            java.util.List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            
            // Try matching by 1-based index (e.g. "5" for MediaTek Wi-Fi)
            try {
                int idx = Integer.parseInt(interfaceName) - 1;
                if (idx >= 0 && idx < allDevs.size()) {
                    nif = allDevs.get(idx);
                }
            } catch (NumberFormatException e) {
                // If not an index, try exact name match
                for (PcapNetworkInterface dev : allDevs) {
                    if (dev.getName().equals(interfaceName)) {
                        nif = dev;
                        break;
                    }
                }
                // If STILL not found, try partial match on description (case-insensitive)
                if (nif == null) {
                    for (PcapNetworkInterface dev : allDevs) {
                        if (dev.getDescription() != null && dev.getDescription().toLowerCase().contains(interfaceName.toLowerCase())) {
                            nif = dev;
                            break;
                        }
                    }
                }
            }

            if (nif == null) {
                // Formatting available interfaces nicely
                StringBuilder sb = new StringBuilder("Interface not found: " + interfaceName + "\nAvailable:");
                for (int i = 0; i < allDevs.size(); i++) {
                    PcapNetworkInterface dev = allDevs.get(i);
                    sb.append("\n  [").append(i + 1).append("] ").append(dev.getName());
                    if (dev.getDescription() != null) sb.append(" (").append(dev.getDescription()).append(")");
                }
                logger.error(sb.toString());
                notifyError("Interface not found: " + interfaceName, null);
                return;
            }

            // Update the active interface logic with the actual selected name and description
            String displayName = nif.getDescription() != null ? nif.getDescription() : nif.getName();
            handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
            logger.info("Opened Pcap handle on {} (snaplen={}, timeout={}ms)", displayName, snaplen, timeout);

            while (isRunning()) {
                try {
                    Packet packet = handle.getNextPacket();
                    if (packet != null) {
                        Optional<PacketData> data = parserFactory.parse(packet);
                        data.ifPresent(this::notifyListeners);
                    }
                } catch (NotOpenException e) {
                    if (isRunning()) {
                        logger.error("Pcap handle closed unexpectedly: {}", e.getMessage());
                        notifyError("Pcap handle closed", e);
                    }
                    break;
                }
            }
        } catch (PcapNativeException e) {
            logger.error("Pcap native error: {}", e.getMessage());
            notifyError("Pcap native error: " + e.getMessage(), e);
        } finally {
            closeHandle();
        }
    }

    @Override
    protected void onStop() {
        closeHandle();
    }

    private void closeHandle() {
        PcapHandle h = handle;
        if (h != null && h.isOpen()) {
            try {
                h.close();
            } catch (Exception e) {
                logger.warn("Error closing pcap handle: {}", e.getMessage());
            }
            handle = null;
        }
    }

    /**
     * List available network interfaces for the CLI.
     */
    public static String listInterfaces() {
        try {
            StringBuilder sb = new StringBuilder();
            java.util.List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            for (int i = 0; i < allDevs.size(); i++) {
                PcapNetworkInterface nif = allDevs.get(i);
                sb.append("  [").append(i + 1).append("] ").append(nif.getName());
                if (nif.getDescription() != null) {
                    sb.append(" — ").append(nif.getDescription());
                }
                sb.append("\n");
            }
            return sb.toString();
        } catch (PcapNativeException e) {
            return "  ERROR: Cannot enumerate interfaces: " + e.getMessage();
        }
    }
}
