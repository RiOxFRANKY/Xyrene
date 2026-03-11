
package com.mitm.ids.api;

import com.mitm.ids.model.PacketData;
import com.mitm.ids.model.Verdict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Decorator: adds retry logic with exponential backoff to any IApiClient.
 * Only retries on UNKNOWN verdicts (which indicates a network/API failure).
 */
public class RetryApiClient implements IApiClient {
    private static final Logger logger = LoggerFactory.getLogger(RetryApiClient.class);
    private final IApiClient delegate;
    private final int maxRetries;
    private final long baseDelayMs;

    public RetryApiClient(IApiClient delegate, int maxRetries, long baseDelayMs) {
        this.delegate = delegate;
        this.maxRetries = maxRetries;
        this.baseDelayMs = baseDelayMs;
    }

    @Override
    public Verdict analyze(PacketData data) {
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            Verdict verdict = delegate.analyze(data);

            // If we got a real verdict (not an error), return immediately
            if (!"error".equals(verdict.packetId())) {
                return verdict;
            }

            if (attempt < maxRetries) {
                long delay = baseDelayMs * attempt;
                logger.warn("API call failed for {}. Retrying in {}ms (attempt {}/{})",
                        data.getSrcIp(), delay, attempt, maxRetries);
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Verdict.unknown("Interrupted during retry");
                }
            }
        }
        logger.error("All {} retries exhausted for {}", maxRetries, data.getSrcIp());
        return Verdict.unknown("Max retries (" + maxRetries + ") exhausted");
    }

    @Override
    public boolean isHealthy() {
        return delegate.isHealthy();
    }

    @Override
    public List<String> getBlocklist() {
        return delegate.getBlocklist();
    }

    @Override
    public boolean blockIp(String ip) {
        return delegate.blockIp(ip);
    }

    @Override
    public boolean unblockIp(String ip) {
        return delegate.unblockIp(ip);
    }
}
