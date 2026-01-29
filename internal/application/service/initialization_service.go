// Package service provides application-level business logic orchestration for paman.
// This file handles the initialization use case.
package service

import (
	"fmt"
	"os"

	"github.com/arham09/paman/internal/domain/port"
)

// InitializationService orchestrates the initialization use case.
//
// Purpose: Coordinates key generation, database creation, and initial setup.
// This is the application service for the "paman init" command.
//
// Design: Constructor injection - all dependencies are provided externally.
// Depends on ports (interfaces), not concrete implementations.
type InitializationService struct {
	crypto port.CryptoService
	config port.ConfigService
}

// NewInitializationService creates a new initialization service.
//
// Purpose: Constructor that wires all dependencies.
// Uses constructor injection pattern.
//
// Parameters:
//   - crypto: Crypto service port (for key generation)
//   - config: Config service port (for path resolution)
//
// Returns:
//   - *InitializationService: Service instance ready for use
func NewInitializationService(
	crypto port.CryptoService,
	config port.ConfigService,
) *InitializationService {
	return &InitializationService{
		crypto: crypto,
		config: config,
	}
}

// Initialize performs the complete initialization workflow.
//
// Purpose: Use case for initializing paman for the first time.
// Generates RSA keys, creates database, and sets up the directory structure.
//
// Parameters:
//   - passphrase: User's passphrase for encrypting the private key (min 12 chars)
//
// Returns:
//   - *rsa.PrivateKey: The generated private key (printed to stdout, not stored)
//   - *rsa.PublicKey: The generated public key (stored in ~/.paman/public_key.pem)
//   - error: Domain error if initialization fails
//
// Workflow:
//   1. Ensure config directory exists
//   2. Get paths for keys and database
//   3. Check if keys/database already exist (prevent overwrites)
//   4. Generate RSA key pair
//   5. Save public key to disk
//   6. Return private key to caller (for printing to stdout)
//
// Security:
//   - Private key is NOT stored in ~/.paman/
//   - Private key is returned to caller for printing to stdout
//   - User must save the private key manually in a secure location
//   - Public key is stored in ~/.paman/public_key.pem
//
// Important: The caller is responsible for printing the private key to stdout
// and instructing the user to save it securely.
func (s *InitializationService) Initialize(passphrase string) (*GeneratedKeys, error) {
	// Ensure config directory exists
	configDir, err := s.config.EnsureConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Get paths for keys
	publicKeyPath, err := s.config.GetPublicKeyPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key path: %w", err)
	}

	privateKeyPath, err := s.config.GetPrivateKeyPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key path: %w", err)
	}

	// Check if keys already exist (prevent overwrites)
	if s.crypto.KeyFilesExist(privateKeyPath, publicKeyPath) {
		return nil, fmt.Errorf("keys already exist in %s", configDir)
	}

	// Generate RSA key pair
	privateKey, publicKey, err := s.crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Save public key to disk
	if err := s.crypto.SavePublicKey(publicKey, publicKeyPath); err != nil {
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}

	// Return the keys to the caller
	// The private key should be printed to stdout for the user to save manually
	// The public key has been saved to disk
	return &GeneratedKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// GeneratedKeys holds the generated RSA key pair.
//
// Purpose: Simple data structure to return both keys from Initialize().
// The private key should be printed to stdout (not stored).
// The public key is stored in ~/.paman/public_key.pem.
type GeneratedKeys struct {
	PrivateKey interface{} // *rsa.PrivateKey
	PublicKey  interface{} // *rsa.PublicKey
}

// EnsureInitialized checks if paman has been initialized.
//
// Purpose: Use case for verifying initialization status.
// Checks if required files exist.
//
// Returns:
//   - bool: true if initialized, false otherwise
//   - error: Domain error if check fails
//
// Workflow:
//   1. Get public key path
//   2. Get database path
//   3. Check if both exist
func (s *InitializationService) EnsureInitialized() (bool, error) {
	// Get public key path
	publicKeyPath, err := s.config.GetPublicKeyPath()
	if err != nil {
		return false, fmt.Errorf("failed to get public key path: %w", err)
	}

	// Get database path
	databasePath, err := s.config.GetDatabasePath()
	if err != nil {
		return false, fmt.Errorf("failed to get database path: %w", err)
	}

	// Check if public key exists
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return false, nil
	}

	// Check if database exists
	if _, err := os.Stat(databasePath); os.IsNotExist(err) {
		return false, nil
	}

	// Both exist
	return true, nil
}
