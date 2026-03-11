package com.mitm.ids.util;

import com.sun.jna.platform.win32.COM.COMException;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.platform.win32.COM.util.IUnknown;
import com.sun.jna.platform.win32.COM.util.ObjectFactory;
import com.sun.jna.platform.win32.COM.util.annotation.ComMethod;
import com.sun.jna.platform.win32.COM.util.annotation.ComObject;
import com.sun.jna.platform.win32.COM.util.annotation.ComProperty;
import com.sun.jna.platform.win32.Ole32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Service to execute Windows Firewall blocking natively using JNA COM Late-Binding.
 * This completely avoids executing external programs (like 'netsh' or 'powershell').
 */
public class FirewallService {
    private static final Logger logger = LoggerFactory.getLogger(FirewallService.class);

    // ──────────────────────────────────────────────────────────
    // JNA COM Interface Declarations
    // ──────────────────────────────────────────────────────────
    @ComObject(progId = "HNetCfg.FwPolicy2")
    public interface INetFwPolicy2 extends IUnknown {
        @ComProperty INetFwRules getRules();
    }

    public interface INetFwRules extends IUnknown {
        @ComMethod void Add(INetFwRule rule);
        @ComMethod void Remove(String name);
    }

    @ComObject(progId = "HNetCfg.FWRule")
    public interface INetFwRule extends IUnknown {
        @ComProperty void setName(String name);
        @ComProperty void setAction(int action);
        @ComProperty void setDirection(int dir);
        @ComProperty void setRemoteAddresses(String addr);
        @ComProperty void setEnabled(boolean enabled);
    }

    // Windows Firewall API Constants
    private static final int NET_FW_ACTION_BLOCK = 0;
    private static final int NET_FW_RULE_DIR_IN = 1;
    private static final int NET_FW_RULE_DIR_OUT = 2;

    private final ConcurrentHashMap<String, Boolean> activeBlocks = new ConcurrentHashMap<>();
    private final ObjectFactory factory;

    public FirewallService() {
        // Factory requires CoInitialize to be on the active thread when creating objects, 
        // but we can initialize the factory instance once.
        this.factory = new ObjectFactory();
    }

    /**
     * Executes the provided COM task wrapped in thread-safe CoInitializeEx / CoUninitialize.
     */
    private void runNativeCom(Runnable task) {
        Ole32.INSTANCE.CoInitializeEx(null, Ole32.COINIT_MULTITHREADED);
        try {
            task.run();
        } catch (COMException e) {
            String msg = e.getMessage();
            if (msg.contains("80020009") || msg.contains("80070005")) {
                logger.error("Native OS firewall COM exception: Access Denied. YOU MUST RUN AS ADMINISTRATOR.");
                System.out.println("\n[FW ERROR] Access Denied! You must open an Administrator terminal to manage firewall rules.");
            } else {
                logger.error("Native OS firewall COM exception: {}", msg);
            }
            logger.error("Native OS firewall error: {}", e.getMessage());
        } finally {
            Ole32.INSTANCE.CoUninitialize();
        }
    }

    public void blockIp(String ip) {
        if (ip == null || ip.isEmpty() || activeBlocks.containsKey(ip)) {
            return;
        }

        String ruleName = "XYRENE_BLOCK_" + ip;

        runNativeCom(() -> {
            // Instantiate Firewall Policy
            INetFwPolicy2 policy = factory.createObject(INetFwPolicy2.class);
            INetFwRules rules = policy.getRules();

            // Create INBOUND Block Rule
            INetFwRule ruleIn = factory.createObject(INetFwRule.class);
            ruleIn.setName(ruleName + "_IN");
            ruleIn.setAction(NET_FW_ACTION_BLOCK);
            ruleIn.setDirection(NET_FW_RULE_DIR_IN);
            ruleIn.setRemoteAddresses(ip);
            ruleIn.setEnabled(true);
            rules.Add(ruleIn);

            // Create OUTBOUND Block Rule
            INetFwRule ruleOut = factory.createObject(INetFwRule.class);
            ruleOut.setName(ruleName + "_OUT");
            ruleOut.setAction(NET_FW_ACTION_BLOCK);
            ruleOut.setDirection(NET_FW_RULE_DIR_OUT);
            ruleOut.setRemoteAddresses(ip);
            ruleOut.setEnabled(true);
            rules.Add(ruleOut);

            activeBlocks.put(ip, true);
            logger.info("Created native COM firewall rules for IP: {}", ip);
            System.out.println("\n[FW] Successfully blocked " + ip + " natively via Windows API.");
        });
    }

    public void unblockIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return;
        }

        String ruleName = "XYRENE_BLOCK_" + ip;

        runNativeCom(() -> {
            INetFwPolicy2 policy = factory.createObject(INetFwPolicy2.class);
            INetFwRules rules = policy.getRules();

            // Remove rules gracefully (COM wrapper will throw if rule doesn't exist, so catch it)
            try { rules.Remove(ruleName + "_IN"); } catch (Exception ignored) {}
            try { rules.Remove(ruleName + "_OUT"); } catch (Exception ignored) {}

            activeBlocks.remove(ip);
            logger.info("Removed native COM firewall rules for IP: {}", ip);
            System.out.println("\n[FW] Successfully unblocked " + ip + " natively via Windows API.");
        });
    }

    public void cleanupAllBlocks() {
        if (activeBlocks.isEmpty()) return;
        
        logger.info("Cleaning up {} native firewall rules created this session...", activeBlocks.size());
        for (String ip : activeBlocks.keySet()) {
            unblockIp(ip);
        }
        activeBlocks.clear();
    }
}
