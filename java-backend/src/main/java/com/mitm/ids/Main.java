
package com.mitm.ids;

import com.mitm.ids.api.*;
import com.mitm.ids.capture.PacketParserFactory;
import com.mitm.ids.capture.Pcap4jCapture;
import com.mitm.ids.cli.*;
import com.mitm.ids.util.AppConfig;
import com.mitm.ids.util.FileIDSLogger;
import com.mitm.ids.util.FirewallService;
import com.mitm.ids.util.IDSLogger;

/**
 * Main entry point for the MITM-IDS Professional Edition.
 *
 * <p>Performs manual dependency injection (no Spring):</p>
 * <ol>
 *   <li>Load configuration</li>
 *   <li>Initialize logger</li>
 *   <li>Build API client chain (HttpApiClient → RetryApiClient → LoggingApiClient)</li>
 *   <li>Create verdict handler with display listener</li>
 *   <li>Set up packet capture engine</li>
 *   <li>Wire CLI commands</li>
 *   <li>Health check the Python backend</li>
 *   <li>Register shutdown hook</li>
 *   <li>Start CLI REPL</li>
 * </ol>
 */
public class Main {

    public static void main(String[] args) {
        try {
            // ──────────────────────────────────────────────────────────
            // 1. Load Configuration
            // ──────────────────────────────────────────────────────────
            String configPath = args.length > 0 ? args[0] : "config/config.json";
            AppConfig.load(configPath);
            AppConfig cfg = AppConfig.get();

            // ──────────────────────────────────────────────────────────
            // 2. Initialize Logger
            // ──────────────────────────────────────────────────────────
            IDSLogger logger = new FileIDSLogger();

            // ──────────────────────────────────────────────────────────
            // 3. Build API Client Chain (Decorator pattern)
            //    HttpApiClient → RetryApiClient → LoggingApiClient
            // ──────────────────────────────────────────────────────────
            String apiUrl = cfg.getString("ml.api.url", "http://127.0.0.1:8000");
            int connectTimeout = cfg.getInt("ml.api.timeout.connect", 2000);
            int readTimeout = cfg.getInt("ml.api.timeout.read", 5000);
            int retries = cfg.getInt("ml.api.retries", 3);
            long retryDelay = cfg.getLong("ml.api.retry.delay", 500);

            IApiClient baseClient = new HttpApiClient(apiUrl, connectTimeout, readTimeout);
            IApiClient retryClient = new RetryApiClient(baseClient, retries, retryDelay);
            IApiClient apiClient = new LoggingApiClient(retryClient, logger);

            // ──────────────────────────────────────────────────────────
            // 4. Create Firewall Service and Verdict Handler
            // ──────────────────────────────────────────────────────────
            FirewallService firewallService = new FirewallService();
            VerdictHandler verdictHandler = new VerdictHandler(apiClient, firewallService);

            // Real-time console output
            verdictHandler.addListener((packet, verdict) ->
                    Display.printVerdict(packet.getSrcIp(), verdict)
            );

            // ──────────────────────────────────────────────────────────
            // 5. Set up Packet Capture Engine
            // ──────────────────────────────────────────────────────────
            PacketParserFactory parserFactory = new PacketParserFactory();
            Pcap4jCapture capture = new Pcap4jCapture(parserFactory);
            capture.addListener(verdictHandler);

            // ──────────────────────────────────────────────────────────
            // 6. Wire CLI Commands
            // ──────────────────────────────────────────────────────────
            CLI cli = new CLI();
            cli.registerCommand(new StartCaptureCommand(capture, verdictHandler));
            cli.registerCommand(new StopCaptureCommand(capture));
            cli.registerCommand(new GetStatsCommand(verdictHandler, capture));
            cli.registerCommand(new GetBlocklistCommand(apiClient));
            
            // Pass the firewall service to block/unblock commands as well
            cli.registerCommand(new BlockCommand(apiClient, firewallService));
            cli.registerCommand(new UnblockCommand(apiClient, firewallService));
            cli.registerCommand(new VerboseCommand());
            cli.registerCommand(new ClearCommand());

            // ──────────────────────────────────────────────────────────
            // 7. Health Check the Python Backend
            // ──────────────────────────────────────────────────────────
            Display.printInfo("Checking Python ML Engine connection...");
            if (apiClient.isHealthy()) {
                Display.printSuccess("Python ML Engine is online.");
            } else {
                Display.printError("Python ML Engine is not reachable at " + apiUrl);
                Display.printInfo("You can still use 'start' — packets will queue with retries.");
            }

            // ──────────────────────────────────────────────────────────
            // 8.5 Start ApiServer (Reverse Proxy)
            // ──────────────────────────────────────────────────────────
            // To avoid collisions, completely bypass the properties file and enforce Port 0.
            // This guarantees the OS will allocate a random free port every single time.
            ApiServer apiServer = new ApiServer(0, apiUrl, apiClient, firewallService, capture, verdictHandler);
            apiServer.start();
            
            // Print out exactly what random port was assigned so run.ps1 can find it
            System.out.println("[XYRENE_JAVA_PORT=" + apiServer.getPort() + "]");
            
            // ──────────────────────────────────────────────────────────
            // 8. Register Shutdown Hook
            // ──────────────────────────────────────────────────────────
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                if (capture.isRunning()) {
                    capture.stop();
                }
                if (firewallService != null) {
                    firewallService.cleanupAllBlocks();
                }
                apiServer.stop();
                logger.info("XYRENE shutdown complete.");
            }, "ShutdownHook"));

            // ──────────────────────────────────────────────────────────
            // 9. Start CLI (blocks until exit)
            // ──────────────────────────────────────────────────────────
            cli.start();

            // ──────────────────────────────────────────────────────────
            // 10. Cleanup
            // ──────────────────────────────────────────────────────────
            if (capture.isRunning()) {
                capture.stop();
            }
            if (firewallService != null) {
                firewallService.cleanupAllBlocks();
            }
            apiServer.stop();
            logger.info("XYRENE Professional Edition exited cleanly.");

        } catch (Exception e) {
            Display.printError("System boot failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
