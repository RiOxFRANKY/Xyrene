
package com.mitm.ids.cli;

import java.util.*;

/**
 * REPL interface for the IDS system.
 * Supports command registration, help, and shutdown hooks.
 */
public class CLI {
    private final Map<String, ICommand> commands = new LinkedHashMap<>();
    private volatile boolean running = true;

    public void registerCommand(ICommand cmd) {
        commands.put(cmd.getName().toLowerCase(), cmd);
    }

    /**
     * Start the CLI REPL loop.
     * Blocks until user types 'exit'/'quit' or input ends.
     */
    public void start() {
        Display.printBanner();
        System.out.println("Type 'help' for available commands.\n");

        Scanner scanner = new Scanner(System.in);
        while (running) {
            System.out.print("xyrene> ");
            System.out.flush();
            if (!scanner.hasNextLine()) break;

            String line = scanner.nextLine().trim();
            if (line.isEmpty()) continue;

            String[] parts = line.split("\\s+");
            String cmdName = parts[0].toLowerCase();
            String[] args = Arrays.copyOfRange(parts, 1, parts.length);

            switch (cmdName) {
                case "exit", "quit" -> {
                    running = false;
                    continue;
                }
                case "help" -> {
                    printHelp();
                    continue;
                }
            }

            ICommand cmd = commands.get(cmdName);
            if (cmd != null) {
                try {
                    cmd.execute(args);
                } catch (Exception e) {
                    Display.printError(e.getMessage());
                }
            } else {
                Display.printError("Unknown command: " + cmdName + ". Type 'help' for available commands.");
            }
        }

        System.out.println("\nShutting down...");
    }

    private void printHelp() {
        Display.printHeader("Commands");
        for (ICommand cmd : commands.values()) {
            System.out.printf("  %-12s %s%n", cmd.getName(), cmd.getDescription());
            if (cmd.getUsage() != null && !cmd.getUsage().equals(cmd.getName())) {
                System.out.printf("  %-12s Usage: %s%n", "", cmd.getUsage());
            }
        }
        System.out.printf("  %-12s %s%n", "help", "Show this help message");
        System.out.printf("  %-12s %s%n", "exit", "Exit the application");
    }

    public void stop() {
        this.running = false;
    }
}
