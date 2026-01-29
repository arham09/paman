// Package cli provides all command-line interface commands for paman.
// This file contains the root command that registers all subcommands.
//
// CLI Framework: Cobra (github.com/spf13/cobra)
//
//	Cobra provides:
//	- Command parsing and routing
//	- Flag handling (e.g., --title, --username)
//	- Auto-generated help text
//	- Command completion support
//	- Subcommand nesting
//
// Command Structure:
//
//	paman [--private-key <path>] [command] [flags]
//	├── init       (Initialize: generate keys, create database)
//	├── add        (Add a new credential)
//	├── get        (Get a credential by ID)
//	├── list       (List all credentials)
//	├── search     (Search credentials)
//	├── update     (Update a credential)
//	└── delete     (Delete a credential)
//
// Usage Examples:
//
//	paman init                                    # First-time setup
//	paman add --title "GitHub" --username "..."   # Add credential
//	paman --private-key /path/to/key.pem list      # List all (with private key)
//	paman --private-key /path/to/key.pem get 1 --show-password  # View with password
//
// NEW DESIGN: Private key is provided via --private-key flag
//   - Private key is NOT stored in ~/.paman/ anymore
//   - User provides private key path via --private-key flag
//   - Public key is stored in ~/.paman/public_key.pem for encryption
//   - Commands that need decryption (get --show-password) require --private-key
package cli

import (
	"github.com/spf13/cobra"
)

// Global flag for private key path
// Used by commands that need to decrypt passwords
var privateKeyPath string

// RootCmd is the root command for the paman CLI application.
//
// Purpose: Serves as the entry point for all CLI operations.
// When users run "paman" without subcommands, this command executes.
//
// NEW: --private-key flag added for providing private key location
//
// Cobra Command Structure:
//   - Use: The command name (how users invoke it)
//   - Short: Short description (shown in command lists)
//   - Long: Long description (shown in help text)
//   - Run: Function to execute when command is run (nil for root = shows help)
//   - PersistentFlags: Flags available to all subcommands
//
// This root command doesn't have a Run function, so executing "paman"
// without subcommands will display help text and available commands.
var RootCmd = &cobra.Command{
	// Use is the command name and basic usage
	// "paman" is how users invoke this command from the terminal
	Use: "paman",

	// Short is a one-line description shown in:
	// - Command lists
	// - Error messages
	// - Brief help output
	Short: "A CLI password manager with RSA encryption",

	// Long is the detailed description shown in:
	// - "paman --help" output
	// - Generated documentation
	// Explains the key security features to users
	Long: `paman is a secure CLI password manager that uses 4096-bit RSA encryption
to store your credentials in an SQLite database. Your private key is protected
by a passphrase using AES-256-GCM encryption.

NEW: Private key is provided via --private-key flag for all operations.
The private key is printed during 'paman init' and must be saved securely.`,
}

// Execute runs the root command and all subcommands.
//
// Purpose: This is the main entry point called from main().
// It parses command-line arguments and executes the appropriate command.
//
// Returns:
//   - error: Error if command execution fails
//
// What it does:
//  1. Parses os.Args (command-line arguments)
//  2. Matches arguments to registered commands
//  3. Executes the matching command's Run function
//  4. Returns any errors that occur
//
// Error Handling:
//   - If command not found: Shows error and help
//   - If flags are invalid: Shows error and usage
//   - If command fails: Shows error message
//
// Called From:
//   - cmd/paman/main.go in the main() function
//
// Example Flow:
//
//	User runs: "paman --private-key /mnt/usb/key.pem add --title 'GitHub' --username 'user@test.com'"
//	1. Execute() parses arguments
//	2. Finds "add" subcommand
//	3. Binds --private-key flag to global variable
//	4. Executes addCmd with provided flags
//	5. Returns result (success or error)
func Execute() error {
	// Execute the root command
	// Cobra handles:
	// - Argument parsing
	// - Command routing
	// - Flag binding
	// - Help generation
	// - Error formatting
	return RootCmd.Execute()
}

// init() is a special Go function that runs automatically when the package is imported.
//
// Purpose: Registers all subcommands with the root command.
// This ensures all commands are available before Execute() is called.
//
// Execution Order:
//  1. Package imported (by main.go)
//  2. init() runs automatically
//  3. Commands are registered
//  4. main() calls Execute()
//  5. Commands are available for use
//
// Why init()?
//   - Guarantees commands are registered before execution
//   - Runs automatically without explicit call
//   - Standard Go pattern for package setup
//
// Adding New Commands:
//
//	To add a new command:
//	1. Create the command variable in another file (e.g., var fooCmd)
//	2. Add RootCmd.AddCommand(fooCmd) here
//	3. Implement the Run function for the command
func init() {
	// Add --private-key flag as a persistent flag (available to all subcommands)
	// This flag specifies the path to the user's private key file
	// The private key is needed for decrypting passwords
	RootCmd.PersistentFlags().StringVar(&privateKeyPath, "private-key", "", "Path to private key file (required for password decryption)")

	// Register each subcommand with the root command
	// Order here affects the order in help text

	// init: Initialize paman (generate keys, create database)
	// This should be run first before using any other commands
	RootCmd.AddCommand(initCmd)

	// add: Add a new credential to the database
	// Encrypts password with public key before storing
	RootCmd.AddCommand(addCmd)

	// get: Retrieve and display a credential by ID
	// Optionally decrypts and shows the password (requires --private-key)
	RootCmd.AddCommand(getCmd)

	// list: List all credentials (without passwords)
	// Shows a summary of all stored credentials
	RootCmd.AddCommand(listCmd)

	// search: Search credentials using full-text search
	// Searches across title, address, and username fields
	RootCmd.AddCommand(searchCmd)

	// update: Update an existing credential
	// Can update individual fields or entire credential
	RootCmd.AddCommand(updateCmd)

	// delete: Delete a credential by ID
	// Permanently removes the credential (cannot be undone)
	RootCmd.AddCommand(deleteCmd)
}
