
package com.mitm.ids.cli;

import com.mitm.ids.capture.Pcap4jCapture;

/**
 * Command: stop the active packet capture.
 */
public class StopCaptureCommand implements ICommand {
    private final Pcap4jCapture capture;

    public StopCaptureCommand(Pcap4jCapture capture) {
        this.capture = capture;
    }

    @Override
    public String getName() { return "stop"; }

    @Override
    public String getDescription() { return "Stop the active packet capture"; }

    @Override
    public String getUsage() { return "stop"; }

    @Override
    public void execute(String[] args) {
        if (!capture.isRunning()) {
            Display.printError("No capture is currently running.");
            return;
        }
        capture.stop();
        Display.printSuccess("Capture stopped.");
    }
}
