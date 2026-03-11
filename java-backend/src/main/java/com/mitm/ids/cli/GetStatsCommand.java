
package com.mitm.ids.cli;

import com.mitm.ids.api.VerdictHandler;
import com.mitm.ids.capture.Pcap4jCapture;

/**
 * Command: display detection statistics.
 */
public class GetStatsCommand implements ICommand {
    private final VerdictHandler handler;
    private final Pcap4jCapture capture;

    public GetStatsCommand(VerdictHandler handler, Pcap4jCapture capture) {
        this.handler = handler;
        this.capture = capture;
    }

    @Override
    public String getName() { return "stats"; }

    @Override
    public String getDescription() { return "Show detection statistics"; }

    @Override
    public String getUsage() { return "stats"; }

    @Override
    public void execute(String[] args) {
        Display.printStats(
                handler.getTotalAnalyzed(),
                handler.getTotalBlocked(),
                handler.getTotalErrors(),
                capture.isRunning()
        );
    }
}
