
package com.mitm.ids.api;

import com.mitm.ids.model.PacketData;
import com.mitm.ids.model.Verdict;

import java.util.List;

/**
 * Interface for all API clients communicating with the Python ML Engine.
 * Supports the full set of backend endpoints.
 */
public interface IApiClient {

    /**
     * Send packet data for ML classification.
     * Must never throw — returns Verdict.unknown() on failure.
     */
    Verdict analyze(PacketData data);

    /**
     * Check if the Python backend is reachable.
     */
    boolean isHealthy();

    /**
     * Retrieve the current blocklist from the Python backend.
     */
    List<String> getBlocklist();

    /**
     * Manually block an IP via the Python backend.
     */
    boolean blockIp(String ip);

    /**
     * Manually unblock an IP via the Python backend.
     */
    boolean unblockIp(String ip);
}
