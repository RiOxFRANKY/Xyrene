
package com.mitm.ids.cli;

import com.mitm.ids.api.IApiClient;

import java.util.List;

/**
 * Command: display the current IP blocklist.
 */
public class GetBlocklistCommand implements ICommand {
    private final IApiClient apiClient;

    public GetBlocklistCommand(IApiClient apiClient) {
        this.apiClient = apiClient;
    }

    @Override
    public String getName() { return "blocklist"; }

    @Override
    public String getDescription() { return "Show blocked IPs from the ML engine"; }

    @Override
    public String getUsage() { return "blocklist"; }

    @Override
    public void execute(String[] args) {
        List<String> ips = apiClient.getBlocklist();
        Display.printBlocklist(ips);
    }
}
