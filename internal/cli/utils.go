// Package cli helper functions for common CLI operations.
// This file contains utility functions used across multiple CLI commands.
//
// Purpose:
//   - Centralize common functionality (passphrase input, validation)
//   - Reduce code duplication across commands
//   - Provide consistent user experience
//
// Security:
//   - Uses term.ReadPassword() for secure password input (no echo)
//   - Limits passphrase attempts to prevent brute-force attacks
//   - Validates passphrase length before attempting operations
package cli

import (
	"fmt"
	"os"

	domainerror "github.com/arham09/paman/internal/domain/error"
	"golang.org/x/term"
)

// maxAttempts is the maximum number of passphrase entry attempts allowed.
//
// Security Rationale:
//   - 3 attempts provides a balance between usability and security
//   - Each attempt for wrong passphrase requires 100k PBKDF2 iterations
//   - This makes brute-force attacks very slow and expensive
//   - Prevents unlimited automated guessing attempts
//
// User Experience:
//   - Allows for typos (user can make a mistake twice and still try again)
//   - Clear feedback about remaining attempts
//   - Final attempt message is clear about failure
const maxAttempts = 3

// getPassphrase prompts the user to enter their passphrase with retry logic.
//
// Purpose: Securely collects passphrase input from the user with validation.
// This function only validates length, not correctness (for new passphrase scenarios).
//
// Returns:
//   - string: The entered passphrase (if valid)
//   - error: models.ErrTooManyAttempts if user fails 3 times, other errors for I/O issues
//
// Validation:
//   - Checks minimum length (12 characters)
//   - Does NOT validate correctness (passphrase could be wrong)
//   - Allows retries up to maxAttempts
//
// Security Features:
//   - Uses term.ReadPassword() for secure input (no echo to terminal)
//   - Disables terminal echo during input (password not visible on screen)
//   - Limits attempts to prevent brute-force attacks
//   - Clear feedback about remaining attempts
//
// User Experience:
//   - Prompts: "Enter passphrase: "
//   - No echo: Characters don't appear on screen
//   - Error feedback: "Passphrase too short (min 12 characters). Attempt X/3"
//   - Final failure: "Too many failed attempts."
//
// When to use:
//   - Use this for collecting NEW passphrases (during init)
//   - Use getPassphraseWithValidation() for EXISTING passphrases (validates against key)
//
// Example Flow:
//
//	Attempt 1: User enters "short" (6 chars)
//	→ Error: "Passphrase too short (min 12 characters). Attempt 1/3"
//	Attempt 2: User enters "my-secure-passphrase" (20 chars)
//	→ Success: Returns "my-secure-passphrase"
func getPassphrase() (string, error) {
	// Retry loop allows user to make mistakes and try again
	// Loops from 1 to maxAttempts (inclusive)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Prompt user for passphrase
		// No newline at end (user types on same line)
		fmt.Print("Enter passphrase: ")

		// Read passphrase from terminal without echo
		// term.ReadPassword() reads input but doesn't display characters
		// This prevents shoulder surfing and screen recording
		// int(os.Stdin.Fd()) gets the file descriptor for standard input
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			// ReadPassword can fail if:
			// - stdin is not a terminal (piped input)
			// - Terminal doesn't support password mode
			return "", fmt.Errorf("failed to read passphrase: %w", err)
		}

		// Print newline after passphrase entry
		// ReadPassword doesn't print newline, so we add it
		// This moves cursor to next line for next prompt or output
		fmt.Println()

		// Validate passphrase length (minimum 12 characters)
		// This is a basic security requirement
		// Longer passphrases are exponentially harder to brute-force
		if len(passphrase) >= 12 {
			// Passphrase meets minimum requirements
			// Convert []byte to string and return
			return string(passphrase), nil
		}

		// Passphrase too short - provide feedback and allow retry
		// Show which attempt this is and how many total attempts allowed
		if attempt < maxAttempts {
			fmt.Printf("Passphrase too short (min 12 characters). Attempt %d/%d\n", attempt, maxAttempts)
		} else {
			// Last attempt failed - no more retries
			fmt.Println("Too many failed attempts.")
			return "", domainerror.ErrTooManyAttempts
		}
	}

	// Should not reach here (loop handles all cases)
	// But Go requires a return statement
	return "", domainerror.ErrTooManyAttempts
}

// getPassphraseWithValidation prompts for passphrase and validates against the encrypted private key.
//
// Purpose: Collects passphrase and verifies it can actually decrypt the private key.
// This is used when the user needs to access existing encrypted data.
//
// Parameters:
//   - privateKeyPath: Path to the encrypted private key file
//
// Returns:
//   - string: The validated passphrase (can decrypt the private key)
//   - error: models.ErrTooManyAttempts if validation fails 3 times
//
// Validation:
//   - Attempts to decrypt the private key with the provided passphrase
//   - Only succeeds if passphrase is correct
//   - Allows retries up to maxAttempts
//
// Security Features:
//   - Uses term.ReadPassword() for secure input
//   - Actually validates passphrase correctness (not just length)
//   - Each attempt requires 100k PBKDF2 iterations (slow)
//   - Limits attempts to prevent brute-force attacks
//
// User Experience:
//   - Prompts: "Enter passphrase: "
//   - No echo during input
//   - Error feedback: "Invalid passphrase. Attempt X/3"
//   - Final failure: "Too many failed attempts."
//
// When to use:
//   - Use this for EXISTING passphrases (when accessing stored data)
//   - Use getPassphrase() for NEW passphrases (no validation against key)
//
// Difference from getPassphrase():
//   - getPassphrase(): Only checks length (for new passphrases)
//   - getPassphraseWithValidation(): Checks length AND correctness (validates against key)
//
// Example Flow:
//
//	Attempt 1: User enters "wrong-passphrase"
//	→ PBKDF2 derivation → Attempt decryption → Fails
//	→ Error: "Invalid passphrase. Attempt 1/3"
//	Attempt 2: User enters "correct-passphrase"
//	→ PBKDF2 derivation → Attempt decryption → Succeeds
//	→ Success: Returns "correct-passphrase"
//
// Note: This function currently uses a placeholder (loadPrivateKeyWithPath)
// In the updated design, this would load the private key from a user-provided path
func getPassphraseWithValidation(privateKeyPath string) (string, error) {
	// Retry loop allows user to make mistakes and try again
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Prompt user for passphrase
		fmt.Print("Enter passphrase: ")

		// Read passphrase from terminal without echo
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase: %w", err)
		}

		// Print newline after passphrase entry
		fmt.Println()

		// Validate passphrase by attempting to decrypt the private key
		// This is the REAL validation - checks if passphrase is correct
		// loadPrivateKeyWithPath will:
		//   1. Read the encrypted private key file
		//   2. Derive AES key from passphrase using PBKDF2
		//   3. Attempt to decrypt the private key
		//   4. Return nil on success, error on failure
		_, err = loadPrivateKeyWithPath(privateKeyPath, string(passphrase))
		if err == nil {
			// Passphrase successfully decrypted the private key
			// Passphrase is correct - return it to caller
			return string(passphrase), nil
		}

		// Decryption failed - passphrase is incorrect
		// Provide feedback and allow retry
		if attempt < maxAttempts {
			fmt.Printf("Invalid passphrase. Attempt %d/%d\n", attempt, maxAttempts)
		} else {
			// Last attempt failed - no more retries
			fmt.Println("Too many failed attempts.")
			return "", domainerror.ErrTooManyAttempts
		}
	}

	// Should not reach here (loop handles all cases)
	return "", domainerror.ErrTooManyAttempts
}

// loadPrivateKeyWithPath is a placeholder function for loading and validating a private key.
//
// Purpose: This function is intended to load the private key from the given path
// using the provided passphrase, validating that the passphrase is correct.
//
// Parameters:
//   - privateKeyPath: Path to the encrypted private key file
//   - passphrase: User-provided passphrase to decrypt the key
//
// Returns:
//   - interface{}: The loaded private key (currently returns nil)
//   - error: Error if passphrase is wrong or key file is corrupted
//
// Current Implementation:
//   - This is a PLACEHOLDER that always succeeds (returns nil, nil)
//   - Used for development/testing before full implementation
//
// Future Implementation (after design update):
//
//	Should call crypto.LoadPrivateKey() to:
//	1. Read the private key file from privateKeyPath
//	2. Derive AES key from passphrase using PBKDF2
//	3. Decrypt the private key using AES-256-GCM
//	4. Parse the decrypted key into RSA private key structure
//	5. Return the private key on success
//	6. Return error on failure (wrong passphrase or corrupted key)
//
// Design Note:
//
//	After the design update, the private key will NOT be in ~/.paman/
//	Instead, users will provide the private key path via CLI flag
//	This function will then load the key from the user-specified location
//
// When this is called:
//   - From getPassphraseWithValidation() to validate passphrase correctness
//   - During any operation that needs the private key (decrypt passwords)
func loadPrivateKeyWithPath(privateKeyPath, passphrase string) (interface{}, error) {
	// Placeholder implementation
	// TODO: Implement after design update
	// Should call: crypto.LoadPrivateKey(passphrase, privateKeyPath)
	// This will:
	//   - Read encrypted key from file
	//   - Derive AES key from passphrase (PBKDF2, 100k iterations)
	//   - Decrypt private key (AES-256-GCM)
	//   - Return decrypted RSA private key
	//
	// For now, this always succeeds (nil, nil)
	// This allows the code to compile and run during development
	// In production, this would actually validate the passphrase
	return nil, nil
}
