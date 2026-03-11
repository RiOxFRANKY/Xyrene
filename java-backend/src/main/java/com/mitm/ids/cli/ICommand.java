
package com.mitm.ids.cli;

/**
 * Interface for CLI commands.
 */
public interface ICommand {

    /** Command name (typed by user). */
    String getName();

    /** Short description for help text. */
    String getDescription();

    /** Usage string showing arguments. */
    String getUsage();

    /** Execute the command with given arguments. */
    void execute(String[] args);
}
