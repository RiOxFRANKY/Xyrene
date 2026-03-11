
package com.mitm.ids.cli;

import com.mitm.ids.api.IApiClient;
import com.mitm.ids.util.FirewallService;

/**
 * Command: manually block an IP address.
 */
public class BlockCommand implements ICommand {
    private final IApiClient apiClient;
    private final FirewallService firewallService;

    public BlockCommand(IApiClient apiClient, FirewallService firewallService) {
        this.apiClient = apiClient;
        this.firewallService = firewallService;
    }

    @Override
    public String getName() { return "block"; }

    @Override
    public String getDescription() { return "Manually block an IP address"; }

    @Override
    public String getUsage() { return "block <ip>"; }

    @Override
    public void execute(String[] args) {
        if (args.length < 1) {
            Display.printError("Usage: " + getUsage());
            return;
        }
        
        String ip = args[0];
        
        // Block on ML API
        if (apiClient.blockIp(ip)) {
            Display.printSuccess("Sent block request to ML Engine for " + ip);
        } else {
            Display.printError("Failed to block " + ip + " on ML Engine");
        }
        
        // Block at OS Level
        if (firewallService != null) {
            firewallService.blockIp(ip);
        }
    }
}
