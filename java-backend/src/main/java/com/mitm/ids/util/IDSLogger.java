
package com.mitm.ids.util;

/**
 * Interface for IDS-specific logging.
 * Abstracts logging so implementations can write to files, console, or external systems.
 */
public interface IDSLogger {

    /**
     * Log a verdict event.
     */
    void logVerdict(String srcIp, String zone, float confidence, String action, boolean blocked);

    /**
     * Log an IP blocking event.
     */
    void logBlock(String srcIp, String zone, String reason);

    /**
     * Log a general info message.
     */
    void info(String message);

    /**
     * Log a warning.
     */
    void warn(String message);

    /**
     * Log an error.
     */
    void error(String message, Throwable cause);
}
