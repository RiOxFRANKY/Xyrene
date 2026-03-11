
package com.mitm.ids.api;

import com.mitm.ids.model.PacketData;
import com.mitm.ids.model.Verdict;

/**
 * Observer interface for entities interested in verdict results.
 */
@FunctionalInterface
public interface VerdictListener {
    /**
     * Called when a packet has been analyzed and a verdict is available.
     *
     * @param packet the original packet data
     * @param verdict the classification result
     */
    void onVerdict(PacketData packet, Verdict verdict);
}
