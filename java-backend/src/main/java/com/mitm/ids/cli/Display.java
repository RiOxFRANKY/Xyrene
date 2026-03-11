
package com.mitm.ids.cli;

import com.mitm.ids.model.Verdict;
import org.fusesource.jansi.Ansi;

import java.util.List;

import static org.fusesource.jansi.Ansi.ansi;

/**
 * Utility for formatted, ANSI-colored console output.
 */
public final class Display {

    private static volatile boolean verboseMode = false;

    private Display() {}

    public static void setVerbose(boolean verbose) {
        verboseMode = verbose;
    }

    public static boolean isVerbose() {
        return verboseMode;
    }

    // ── Banner ──────────────────────────────────────────────────────

    public static void printBanner() {
        System.out.println(ansi().fgCyan().bold()
                .a("╔══════════════════════════════════════════════╗\n")
                .a("║        XYRENE Professional Edition v2.0      ║\n")
                .a("║     Network Intrusion Detection System       ║\n")
                .a("╚══════════════════════════════════════════════╝")
                .reset());
    }

    // ── Headers ─────────────────────────────────────────────────────

    public static void printHeader(String title) {
        System.out.println(ansi().fgCyan().bold().a("═══ " + title + " ═══").reset());
    }

    // ── Verdict Display ─────────────────────────────────────────────

    public static void printVerdict(String srcIp, Verdict verdict) {
        Ansi a = ansi()
                .a("[").bold().a(srcIp).reset().a("] ");

        // Color by zone
        switch (verdict.zone()) {
            case CRITICAL -> a.fgRed().bold().a("⚠ CRITICAL");
            case MALICIOUS -> a.fgRed().a("✗ MALICIOUS");
            case SUSPICIOUS -> a.fgYellow().a("? SUSPICIOUS");
            case BLOCKED -> a.fgMagenta().bold().a("⊘ BLOCKED");
            case BENIGN -> a.fgGreen().a("✓ BENIGN");
            default -> a.fgBrightBlack().a("? UNKNOWN");
        }

        a.reset()
                .a(" | conf=")
                .a(String.format("%.4f", verdict.confidence()))
                .a(" | action=");

        // Color action
        switch (verdict.action()) {
            case DROP -> a.fgRed().bold().a("DROP").reset();
            case FLAG -> a.fgYellow().a("FLAG").reset();
            case PASS -> a.fgGreen().a("PASS").reset();
        }

        if (verdict.blocked()) {
            a.a(" | ").fgRed().bold().a("[BLOCKED]").reset();
        }

        System.out.println(a);

        if (verboseMode) {
            System.out.println(ansi().fgBrightBlack()
                    .a("    └─ ID: " + verdict.packetId() + " | Events: " + verdict.ipEventCount())
                    .reset());
        }
    }

    // ── Stats Display ───────────────────────────────────────────────

    public static void printStats(long analyzed, long blocked, long errors, boolean captureRunning) {
        printHeader("Detection Statistics");
        System.out.printf("  Packets Analyzed:  %d%n", analyzed);
        System.out.printf("  IPs Blocked:       %d%n", blocked);
        System.out.printf("  Listener Errors:   %d%n", errors);
        System.out.printf("  Capture Running:   %s%n",
                captureRunning ? ansi().fgGreen().a("YES").reset() : ansi().fgRed().a("NO").reset());
    }

    // ── Blocklist Display ───────────────────────────────────────────

    public static void printBlocklist(List<String> ips) {
        printHeader("Blocked IPs (" + ips.size() + ")");
        if (ips.isEmpty()) {
            System.out.println("  (none)");
        } else {
            for (String ip : ips) {
                System.out.println(ansi().a("  ").fgRed().a("⊘ ").reset().a(ip));
            }
        }
    }

    // ── Error / Info ────────────────────────────────────────────────

    public static void printError(String msg) {
        System.out.println(ansi().fgRed().bold().a("ERROR: ").reset().a(msg));
    }

    public static void printSuccess(String msg) {
        System.out.println(ansi().fgGreen().a("✓ ").reset().a(msg));
    }

    public static void printInfo(String msg) {
        System.out.println(ansi().fgBrightBlack().a("  ").a(msg).reset());
    }
}
