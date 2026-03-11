
package com.mitm.ids.api;

import com.mitm.ids.capture.IPacketListener;
import com.mitm.ids.model.PacketData;
import com.mitm.ids.model.Verdict;
import com.mitm.ids.util.FirewallService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Central handler in the packet processing pipeline:
 *   Captured Packet → API Analysis → Notify Listeners
 *
 * <p>Thread-safe. Isolates listener errors so no single listener
 * can break the pipeline.</p>
 */
public class VerdictHandler implements IPacketListener {
    private static final Logger logger = LoggerFactory.getLogger(VerdictHandler.class);

    private final IApiClient apiClient;
    private final FirewallService firewallService;
    private final List<VerdictListener> listeners = new CopyOnWriteArrayList<>();

    // Statistics
    private final AtomicLong totalAnalyzed = new AtomicLong();
    private final AtomicLong totalBlocked = new AtomicLong();
    private final AtomicLong totalErrors = new AtomicLong();

    public VerdictHandler(IApiClient apiClient, FirewallService firewallService) {
        this.apiClient = apiClient;
        this.firewallService = firewallService;
    }

    public void addListener(VerdictListener listener) {
        listeners.add(listener);
    }

    public void removeListener(VerdictListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void onPacket(PacketData data) {
        totalAnalyzed.incrementAndGet();

        // 1. Analyze via the API client chain
        Verdict verdict = apiClient.analyze(data);

        if (verdict.isDropped()) {
            totalBlocked.incrementAndGet();
            
            // 2. Trigger OS-level firewall block
            if (firewallService != null) {
                firewallService.blockIp(data.getSrcIp());
            }
        }

        // 3. Notify all result observers with error isolation
        for (VerdictListener listener : listeners) {
            try {
                listener.onVerdict(data, verdict);
            } catch (Exception e) {
                totalErrors.incrementAndGet();
                logger.error("VerdictListener {} threw exception: {}",
                        listener.getClass().getSimpleName(), e.getMessage(), e);
            }
        }
    }

    // ── Stats ────────────────────────────────────────────────────────

    public long getTotalAnalyzed() { return totalAnalyzed.get(); }
    public long getTotalBlocked() { return totalBlocked.get(); }
    public long getTotalErrors() { return totalErrors.get(); }
}
