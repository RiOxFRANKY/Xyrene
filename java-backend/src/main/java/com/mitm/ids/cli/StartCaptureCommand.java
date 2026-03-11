
package com.mitm.ids.cli;

import com.mitm.ids.api.IApiClient;
import com.mitm.ids.api.VerdictHandler;
import com.mitm.ids.capture.Pcap4jCapture;

/**
 * Command: start capture on a network interface.
 */
public class StartCaptureCommand implements ICommand {
    private final Pcap4jCapture capture;
    private final VerdictHandler handler;

    public StartCaptureCommand(Pcap4jCapture capture, VerdictHandler handler) {
        this.capture = capture;
        this.handler = handler;
    }

    @Override
    public String getName() { return "start"; }

    @Override
    public String getDescription() { return "Start packet capture on a network interface"; }

    @Override
    public String getUsage() { return "start [interface_name]"; }

    @Override
    public void execute(String[] args) {
        if (capture.isRunning()) {
            Display.printError("Capture is already running on " + capture.getActiveInterface());
            return;
        }

        String iface;
        if (args.length > 0) {
            iface = args[0];
        } else {
            Display.printInfo("Available interfaces:");
            System.out.println(Pcap4jCapture.listInterfaces());
            Display.printError("Usage: start <interface_name>");
            return;
        }

        capture.start(iface);
        Display.printSuccess("Capture started on " + iface);
    }
}
