
package com.mitm.ids.capture;

import com.mitm.ids.model.PacketData;

/**
 * Observer interface for parsed packet events.
 */
public interface IPacketListener {

    /**
     * Called when a valid packet has been parsed.
     */
    void onPacket(PacketData data);

    /**
     * Called when a capture error occurs. Default is no-op.
     */
    default void onCaptureError(String message, Throwable cause) {
        // No-op by default
    }
}
