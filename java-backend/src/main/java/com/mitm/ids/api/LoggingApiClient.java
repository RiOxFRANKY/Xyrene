
package com.mitm.ids.api;

import com.mitm.ids.model.PacketData;
import com.mitm.ids.model.Verdict;
import com.mitm.ids.util.IDSLogger;

import java.util.List;

/**
 * Decorator: logs the duration and result of every API operation.
 */
public class LoggingApiClient implements IApiClient {
    private final IApiClient delegate;
    private final IDSLogger logger;

    public LoggingApiClient(IApiClient delegate, IDSLogger logger) {
        this.delegate = delegate;
        this.logger = logger;
    }

    @Override
    public Verdict analyze(PacketData data) {
        long start = System.nanoTime();
        Verdict verdict = delegate.analyze(data);
        long durationMs = (System.nanoTime() - start) / 1_000_000;

        logger.logVerdict(
                data.getSrcIp(),
                verdict.zone() != null ? verdict.zone().name() : "UNKNOWN",
                verdict.confidence(),
                verdict.action() != null ? verdict.action().name() : "PASS",
                verdict.blocked()
        );

        if (durationMs > 1000) {
            logger.warn(String.format("Slow API call: %dms for %s", durationMs, data.getSrcIp()));
        }

        return verdict;
    }

    @Override
    public boolean isHealthy() {
        boolean healthy = delegate.isHealthy();
        logger.info("Health check: " + (healthy ? "OK" : "FAILED"));
        return healthy;
    }

    @Override
    public List<String> getBlocklist() {
        List<String> list = delegate.getBlocklist();
        logger.info("Fetched blocklist: " + list.size() + " entries");
        return list;
    }

    @Override
    public boolean blockIp(String ip) {
        boolean ok = delegate.blockIp(ip);
        logger.logBlock(ip, "MANUAL", ok ? "Blocked successfully" : "Block failed");
        return ok;
    }

    @Override
    public boolean unblockIp(String ip) {
        boolean ok = delegate.unblockIp(ip);
        logger.info("Unblock IP " + ip + ": " + (ok ? "OK" : "FAILED"));
        return ok;
    }
}
