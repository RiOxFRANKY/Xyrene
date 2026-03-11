
package com.mitm.ids.cli;

import com.mitm.ids.api.IApiClient;
import com.mitm.ids.util.FirewallService;

/**
 * Command: manually unblock an IP address.
 */
public class UnblockCommand implements ICommand {
    private final IApiClient apiClient;
    private final FirewallService firewallService;

    public UnblockCommand(IApiClient apiClient, FirewallService firewallService) {
        this.apiClient = apiClient;
        this.firewallService = firewallService;
    }

    @Override
    public String getName() { return "unblock"; }

    @Override
    public String getDescription() { return "Unblock an IP address"; }

    @Override
    public String getUsage() { return "unblock <ip>"; }

    @Override
    public void execute(String[] args) {
        if (args.length < 1) {
            Display.printError("Usage: " + getUsage());
            return;
        }
        
        String ip = args[0];
        
        // Unblock from ML API
        if (apiClient.unblockIp(ip)) {
            Display.printSuccess("Sent unblock request to ML Engine for " + ip);
        } else {
            Display.printError("Failed to unblock " + ip + " on ML Engine");
        }
        
        // Unblock at OS Level
        if (firewallService != null) {
            firewallService.unblockIp(ip);
        }
    }
}
