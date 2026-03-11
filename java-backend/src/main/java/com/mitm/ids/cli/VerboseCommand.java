
package com.mitm.ids.cli;

/**
 * Command: toggle verbose output mode.
 */
public class VerboseCommand implements ICommand {

    @Override
    public String getName() { return "verbose"; }

    @Override
    public String getDescription() { return "Toggle verbose output mode"; }

    @Override
    public String getUsage() { return "verbose"; }

    @Override
    public void execute(String[] args) {
        boolean newState = !Display.isVerbose();
        Display.setVerbose(newState);
        Display.printSuccess("Verbose mode: " + (newState ? "ON" : "OFF"));
    }
}
