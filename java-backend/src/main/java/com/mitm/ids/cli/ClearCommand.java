package com.mitm.ids.cli;

import static org.fusesource.jansi.Ansi.ansi;

/**
 * Command: clear the terminal screen.
 */
public class ClearCommand implements ICommand {

    @Override
    public String getName() { return "clear"; }

    @Override
    public String getDescription() { return "Clear the terminal screen"; }

    @Override
    public String getUsage() { return "clear"; }

    @Override
    public void execute(String[] args) {
        System.out.print(ansi().eraseScreen().cursor(1, 1));
        System.out.flush();
    }
}
