// Package config provides configuration management for paman.
// It handles path resolution for all application data stored in the user's home directory.
// All data is stored in ~/.paman/ with appropriate permissions for security.
package config

import (
	"os"
	"path/filepath"
)

// GetConfigDir returns the paman configuration directory path (~/.paman).
//
// Purpose: Centralizes the config directory location so it can be easily changed
// and consistently used across the application.
//
// Returns:
//   - string: The absolute path to ~/.paman
//   - error: An error if the home directory cannot be determined
//
// Security: The config directory should be created with 0700 permissions (owner only)
// to prevent other users from accessing sensitive data.
func GetConfigDir() (string, error) {
	// Get the user's home directory (e.g., /home/user, /Users/user)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Append .paman to create the config directory path
	configDir := filepath.Join(homeDir, ".paman")
	return configDir, nil
}

// EnsureConfigDir creates the config directory if it doesn't exist.
//
// Purpose: Ensures the config directory exists before attempting to read/write files.
// This should be called during initialization (e.g., in the 'init' command).
//
// Returns:
//   - string: The absolute path to the config directory
//   - error: An error if the directory cannot be created
//
// Security: Creates directory with 0700 permissions (read/write/execute for owner only).
// This is critical for security as it prevents other users from accessing:
// - The encrypted private key
// - The database containing encrypted passwords
func EnsureConfigDir() (string, error) {
	// Get the config directory path
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	// Create the directory with 0700 permissions (owner only)
	// MkdirAll creates parent directories if they don't exist
	// Permission 0700 means: rwx for owner, nothing for group/others
	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		return "", err
	}

	return configDir, nil
}

// GetPrivateKeyPath returns the full path to the private key file.
//
// Purpose: Provides a consistent way to reference the private key file location.
// The private key is encrypted with the user's passphrase and contains
// the RSA private key needed to decrypt passwords.
//
// Returns:
//   - string: The absolute path to ~/.paman/private_key.pem
//   - error: An error if the config directory path cannot be determined
//
// Security: The private key file should always have 0600 permissions.
// It is encrypted with AES-256-GCM using a key derived from the user's passphrase.
func GetPrivateKeyPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	// Private key is stored as private_key.pem in PEM format
	return filepath.Join(configDir, "private_key.pem"), nil
}

// GetPublicKeyPath returns the full path to the public key file.
//
// Purpose: Provides a consistent way to reference the public key file location.
// The public key is used to encrypt passwords before storing them in the database.
//
// Returns:
//   - string: The absolute path to ~/.paman/public_key.pem
//   - error: An error if the config directory path cannot be determined
//
// Security: The public key can be stored with 0644 permissions as it is not sensitive.
// It is used for encryption only and cannot decrypt data.
func GetPublicKeyPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	// Public key is stored as public_key.pem in PEM format
	return filepath.Join(configDir, "public_key.pem"), nil
}

// GetDatabasePath returns the full path to the SQLite database file.
//
// Purpose: Provides a consistent way to reference the database file location.
// The database stores all credentials with encrypted passwords.
//
// Returns:
//   - string: The absolute path to ~/.paman/credentials.db
//   - error: An error if the config directory path cannot be determined
//
// Security: The database file should always have 0600 permissions.
// Passwords are encrypted with RSA-4096 before storage, so even if someone
// gains access to the database, they cannot read the passwords without the private key.
func GetDatabasePath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	// SQLite database file
	return filepath.Join(configDir, "credentials.db"), nil
}
