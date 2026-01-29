// Package config provides filesystem-based configuration management for paman.
// This adapter implements the ConfigService port defined in the domain layer.
//
// Purpose: Provides configuration and path management using the filesystem.
// This adapter implements the ConfigService interface using standard OS file operations.
//
// Design:
//   - Stores config in ~/.paman/ directory
//   - Uses OS-specific home directory resolution
//   - Creates directories with secure permissions (0700)
//   - Files are stored with appropriate permissions
//
// Security:
//   - Config directory: 0700 permissions (owner only)
//   - Database file: 0600 permissions (owner read/write)
//   - Public key: 0644 permissions (readable by all)
//   - Private key: 0600 permissions (owner read/write)
package config

import (
	"os"
	"path/filepath"
)

// FilesystemConfig implements the ConfigService port using filesystem operations.
//
// Purpose: Provides filesystem-based configuration management.
// This adapter implements the domain's ConfigService interface.
//
// Design: Stateless service - all methods are pure functions.
// No constructor needed as there's no state to initialize.
type FilesystemConfig struct{}

// NewFilesystemConfig creates a new filesystem config service.
//
// Purpose: Constructor that creates a config service instance.
// Since the service is stateless, this just returns an empty struct.
//
// Returns:
//   - *FilesystemConfig: Config service instance ready for use
func NewFilesystemConfig() *FilesystemConfig {
	return &FilesystemConfig{}
}

// GetConfigDir returns the paman configuration directory path (~/.paman).
//
// Purpose: Centralizes the config directory location so it can be easily changed
// and consistently used across the application.
// Implements the ConfigService.GetConfigDir() method.
func (c *FilesystemConfig) GetConfigDir() (string, error) {
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
// Implements the ConfigService.EnsureConfigDir() method.
func (c *FilesystemConfig) EnsureConfigDir() (string, error) {
	// Get the config directory path
	configDir, err := c.GetConfigDir()
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

// GetPublicKeyPath returns the full path to the public key file.
//
// Purpose: Provides a consistent way to reference the public key file location.
// The public key is used to encrypt passwords before storing them in the database.
// Implements the ConfigService.GetPublicKeyPath() method.
func (c *FilesystemConfig) GetPublicKeyPath() (string, error) {
	configDir, err := c.GetConfigDir()
	if err != nil {
		return "", err
	}

	// Public key is stored as public_key.pem in PEM format
	return filepath.Join(configDir, "public_key.pem"), nil
}

// GetPrivateKeyPath returns the full path to the private key file.
//
// Purpose: Provides a consistent way to reference the private key file location.
// The private key is encrypted with the user's passphrase and contains
// the RSA private key needed to decrypt passwords.
// Implements the ConfigService.GetPrivateKeyPath() method.
//
// Note: In the current design, private keys are NOT stored in ~/.paman/
// Users provide the private key path via --private-key flag.
// This method is kept for compatibility and potential future use.
func (c *FilesystemConfig) GetPrivateKeyPath() (string, error) {
	configDir, err := c.GetConfigDir()
	if err != nil {
		return "", err
	}

	// Private key is stored as private_key.pem in PEM format
	return filepath.Join(configDir, "private_key.pem"), nil
}

// GetDatabasePath returns the full path to the SQLite database file.
//
// Purpose: Provides a consistent way to reference the database file location.
// The database stores all credentials with encrypted passwords.
// Implements the ConfigService.GetDatabasePath() method.
func (c *FilesystemConfig) GetDatabasePath() (string, error) {
	configDir, err := c.GetConfigDir()
	if err != nil {
		return "", err
	}

	// SQLite database file
	return filepath.Join(configDir, "credentials.db"), nil
}
