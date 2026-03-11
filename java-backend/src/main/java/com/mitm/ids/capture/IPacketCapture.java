
package com.mitm.ids.capture;

/**
 * Interface for packet capture engines (Pcap4j, mock, etc.).
 */
public interface IPacketCapture {

    /**
     * Start capturing on the specified network interface.
     *
     * @param interfaceName the network interface name (e.g. "eth0", "\\Device\\NPF_{...}")
     */
    void start(String interfaceName);

    /**
     * Stop the capture engine and release resources.
     */
    void stop();

    /**
     * Check if the engine is currently capturing.
     */
    boolean isRunning();

    /**
     * Register a listener for parsed packet events.
     */
    void addListener(IPacketListener listener);
}
