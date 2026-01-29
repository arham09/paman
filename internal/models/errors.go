// Package models defines the core data structures used throughout the paman application.
// This file contains all error constants used across the application.
//
// Purpose: Centralized error definitions allow for consistent error handling
// and make it easy to check for specific error conditions using errors.Is().
//
// Usage Example:
//
//	if err == models.ErrNotFound {
//	    // Handle not found case
//	}
package models

import "errors"

var (
	// ErrNotFound is returned when a requested credential does not exist in the database.
	//
	// When this is returned:
	//   - "paman get <id>" when the ID doesn't exist
	//   - "paman update <id>" when the ID doesn't exist
	//   - "paman delete <id>" when the ID doesn't exist
	//
	// User Action: Verify the credential ID is correct (use "paman list" to see all IDs)
	ErrNotFound = errors.New("credential not found")

	// ErrInvalidPassphrase is returned when the user enters an incorrect passphrase.
	//
	// When this is returned:
	//   - "paman init" if passphrase verification fails
	//   - Any command that needs to decrypt the private key (get, list with decrypt, etc.)
	//
	// Security: This error is returned after PBKDF2 key derivation fails to produce
	// a valid AES key that can decrypt the private key. This prevents brute-force attacks
	// because each attempt requires 100k PBKDF2 iterations.
	//
	// User Action: Re-enter the correct passphrase. After 3 failed attempts, the operation aborts.
	ErrInvalidPassphrase = errors.New("invalid passphrase")

	// ErrPassphraseTooWeak is returned when the passphrase doesn't meet security requirements.
	//
	// Security Requirements:
	//   - Minimum 12 characters length
	//   - No other restrictions (user can use spaces, special chars, etc.)
	//
	// When this is returned:
	//   - "paman init" when creating new keys
	//
	// Security Rationale: Longer passphrases are exponentially harder to brute force.
	// 12 characters provides a good balance of security and usability.
	//
	// User Action: Choose a longer passphrase (12+ characters).
	// Recommendation: Use a passphrase with multiple words for memorability.
	ErrPassphraseTooWeak = errors.New("passphrase must be at least 12 characters")

	// ErrKeysExist is returned when trying to initialize but RSA keys already exist.
	//
	// When this is returned:
	//   - "paman init" when ~/.paman/private_key.pem and public_key.pem already exist
	//
	// Purpose: Prevents accidental overwriting of existing keys, which would make
	// all previously stored credentials permanently undecryptable.
	//
	// User Action: If you want to start fresh, manually delete ~/.paman/ directory
	// WARNING: This will permanently lose access to all existing credentials!
	ErrKeysExist = errors.New("keys already exist")

	// ErrKeysNotFound is returned when the RSA keys don't exist but are required.
	//
	// When this is returned:
	//   - Any command except "paman init" when keys haven't been created yet
	//
	// Purpose: Indicates that paman hasn't been initialized yet.
	//
	// User Action: Run "paman init" first to create keys and database.
	ErrKeysNotFound = errors.New("keys not found")

	// ErrDatabaseExists is returned when trying to initialize but database already exists.
	//
	// When this is returned:
	//   - "paman init" when ~/.paman/credentials.db already exists
	//
	// Purpose: Prevents accidental overwriting of the existing database and all credentials.
	// This is checked during "paman init" along with key existence.
	//
	// User Action: If you want to start fresh, manually delete ~/.paman/ directory
	// WARNING: This will permanently lose all existing credentials!
	ErrDatabaseExists = errors.New("database already exists")

	// ErrDatabaseNotFound is returned when the database doesn't exist but is required.
	//
	// When this is returned:
	//   - Any command except "paman init" when database hasn't been created yet
	//
	// Purpose: Indicates that paman hasn't been initialized yet.
	//
	// User Action: Run "paman init" first to create database and keys.
	ErrDatabaseNotFound = errors.New("database not found")

	// ErrTooManyAttempts is returned when the user exceeds maximum passphrase attempts.
	//
	// When this is returned:
	//   - After 3 failed passphrase attempts in a single operation
	//
	// Security Purpose: Limits brute-force attempts. Each failed attempt requires
	// 100k PBKDF2 iterations, so 3 attempts already imposes a significant delay.
	// Prevents unlimited automated attempts.
	//
	// User Action: Wait and try again with the correct passphrase.
	// If you forgot your passphrase, your data is permanently inaccessible (by design).
	ErrTooManyAttempts = errors.New("too many failed attempts")

	// ErrInvalidInput is returned when provided parameters don't meet validation requirements.
	//
	// When this is returned:
	//   - Adding/Updating credential with empty title or username
	//   - Providing empty password when encryption is required
	//   - Other input validation failures
	//
	// Purpose: Indicates malformed or incomplete user input before attempting operations.
	//
	// User Action: Provide valid, non-empty values for required fields.
	ErrInvalidInput = errors.New("invalid input")

	// ErrEncryptionFailed is returned when the encryption operation fails.
	//
	// When this is returned:
	//   - RSA encryption fails during password encryption
	//   - Random number generation fails (entropy exhaustion)
	//   - Other cryptographic errors during encryption
	//
	// Security Implications: If this occurs, DO NOT store the password. The operation
	// should be aborted and retried.
	//
	// User Action: Try the operation again. If it persists, may indicate system issues.
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed is returned when the decryption operation fails.
	//
	// When this is returned:
	//   - RSA decryption fails during password decryption
	//   - Private key corruption
	//   - Encrypted data corruption
	//
	// Security Implications: This could indicate:
	//   - Wrong private key (key mismatch)
	//   - Corrupted private key
	//   - Corrupted encrypted data in database
	//
	// User Action: Verify database and key integrity. Data may be permanently lost
	// if the private key or encrypted data is corrupted.
	ErrDecryptionFailed = errors.New("decryption failed")
)
