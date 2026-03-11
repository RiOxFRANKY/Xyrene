
package com.mitm.ids.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Production-grade IDSLogger using SLF4J/Logback.
 * Writes structured log entries for verdicts and blocks.
 */
public final class FileIDSLogger implements IDSLogger {
    private final Logger verdictLog;
    private final Logger blockLog;
    private final Logger appLog;

    public FileIDSLogger() {
        this.verdictLog = LoggerFactory.getLogger("ids.verdicts");
        this.blockLog = LoggerFactory.getLogger("ids.blocks");
        this.appLog = LoggerFactory.getLogger("ids.app");
    }

    @Override
    public void logVerdict(String srcIp, String zone, float confidence, String action, boolean blocked) {
        verdictLog.info("VERDICT | IP: {} | Zone: {} | Conf: {} | Action: {} | Blocked: {}",
                srcIp, zone, String.format("%.4f", confidence), action, blocked);
    }

    @Override
    public void logBlock(String srcIp, String zone, String reason) {
        blockLog.info("BLOCK | IP: {} | Zone: {} | Reason: {}", srcIp, zone, reason);
    }

    @Override
    public void info(String message) {
        appLog.info(message);
    }

    @Override
    public void warn(String message) {
        appLog.warn(message);
    }

    @Override
    public void error(String message, Throwable cause) {
        if (cause != null) {
            appLog.error(message, cause);
        } else {
            appLog.error(message);
        }
    }
}
