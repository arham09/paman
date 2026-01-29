// Package main is the entry point for the paman CLI application.
//
// This file contains the main() function which:
//  1. Executes the CLI command parser
//  2. Handles errors gracefully
//  3. Sets appropriate exit codes
//
// Build:
//
//	go build -o paman ./cmd/paman
//
// Usage:
//
//	./paman [command] [flags]
//
// Project Structure:
//
//	cmd/paman/main.go          - This file (entry point)
//	internal/cli/              - CLI command implementations
//	internal/crypto/           - Cryptographic functions
//	internal/db/               - Database operations
//	internal/models/           - Data structures
//	pkg/config/                - Configuration management
package main

import (
	"fmt"
	"os"

	"github.com/arham09/paman/internal/cli"
)

// main is the entry point of the paman application.
//
// Purpose: Serves as the starting point when the binary is executed.
// Initializes and runs the CLI command parser.
//
// Execution Flow:
//  1. Program starts here (operating system calls main())
//  2. cli.Execute() is called to parse and run commands
//  3. If successful, program exits with code 0
//  4. If error occurs, error is printed and program exits with code 1
//
// Exit Codes:
//   - 0: Success (no errors)
//   - 1: Error occurred (user mistake, system error, etc.)
//
// Error Handling:
//   - Errors are written to stderr (standard error stream)
//   - Error messages include context about what went wrong
//   - Exit code 1 signals failure to calling processes/scripts
//
// When main() is called:
//   - User runs: ./paman [command] [flags]
//   - Operating system loads the binary and calls main()
//   - This function delegates to cli.Execute() for actual work
//
// Thread Safety:
//   - Single-threaded execution (CLI applications are typically single-threaded)
//   - No goroutines are spawned
//   - No concurrent access to shared resources
func main() {
	// Execute the CLI command parser and executor
	// cli.Execute() is defined in internal/cli/root.go
	// It parses os.Args (command-line arguments) and runs the appropriate command
	//
	// If err != nil, something went wrong:
	//   - Invalid command syntax
	//   - Missing required flags
	//   - File system errors
	//   - Cryptographic errors
	//   - Database errors
	if err := cli.Execute(); err != nil {
		// Write error message to stderr (not stdout)
		// stderr is used for errors and diagnostics
		// stdout is used for normal output (command results)
		// This allows error messages to be separated from data
		//
		// %v formats the error using its Error() method
		// \n adds a newline at the end
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		// Exit with status code 1 to indicate failure
		// Exit code 0 = success
		// Exit code 1 = failure (standard Unix convention)
		// This allows scripts to check if paman succeeded
		//
		// Example in bash:
		//   if paman add ...; then
		//     echo "Success!"
		//   fi
		os.Exit(1)
	}

	// If we reach here, cli.Execute() returned nil (no error)
	// Go automatically calls os.Exit(0) when main() returns normally
	// No explicit os.Exit(0) needed here
}
