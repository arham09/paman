// Package port defines the interfaces that the domain layer requires.
package port

// ConfigService defines the contract for configuration and path management.
//
// Purpose: This is a primary port interface that defines how the domain layer
// retrieves configuration values and file paths. It's implemented by adapters
// like FilesystemConfig.
//
// Design Principles:
//   - Abstracts file system operations from domain logic
//   - Centralizes path management logic
//   - Ensures config directory exists with proper permissions
//
// Security:
//   - Config directory (~/.paman/) uses 0700 permissions (owner only)
//   - Database file uses 0600 permissions (owner read/write)
//   - Public key uses 0644 permissions (readable by all)
//   - Private key uses 0600 permissions (owner read/write)
//
// Benefits:
//   - Domain logic doesn't depend on specific file system implementations
//   - Easy to change config directory structure
//   - Can mock for testing without real file system operations
type ConfigService interface {
	// GetConfigDir returns the paman configuration directory path.
	//
	// Returns:
	//   - string: Absolute path to ~/.paman/
	//   - error: Domain error if path cannot be determined
	//
	// Security: Directory should have 0700 permissions.
	GetConfigDir() (string, error)

	// EnsureConfigDir creates the config directory if it doesn't exist.
	//
	// Returns:
	//   - string: Absolute path to ~/.paman/
	//   - error: Domain error if directory cannot be created
	//
	// Security: Creates directory with 0700 permissions (owner only).
	// This prevents other users from accessing sensitive data.
	EnsureConfigDir() (string, error)

	// GetPublicKeyPath returns the full path to the public key file.
	//
	// Returns:
	//   - string: Absolute path to ~/.paman/public_key.pem
	//   - error: Domain error if path cannot be determined
	//
	// Security: Public key file should have 0644 permissions.
	// The public key is used for encryption only and cannot decrypt data.
	GetPublicKeyPath() (string, error)

	// GetPrivateKeyPath returns the full path to the private key file.
	//
	// Returns:
	//   - string: Absolute path to ~/.paman/private_key.pem
	//   - error: Domain error if path cannot be determined
	//
	// Security: Private key file should have 0600 permissions.
	// The private key is encrypted with a passphrase.
	//
	// Note: In the current design, private keys are NOT stored in ~/.paman/
	// Users provide the private key path via --private-key flag.
	// This method is kept for compatibility and potential future use.
	GetPrivateKeyPath() (string, error)

	// GetDatabasePath returns the full path to the SQLite database file.
	//
	// Returns:
	//   - string: Absolute path to ~/.paman/credentials.db
	//   - error: Domain error if path cannot be determined
	//
	// Security: Database file should have 0600 permissions.
	// Passwords are encrypted with RSA-4096 before storage.
	GetDatabasePath() (string, error)
}
