// Package service provides application-level business logic orchestration for paman.
// This layer coordinates between ports to implement use cases.
//
// Purpose: Application services orchestrate business logic by coordinating
// between domain ports. They don't contain business rules themselves - that's
// in the domain layer. Instead, they coordinate workflow between entities.
//
// Design:
//   - Constructor injection of all dependencies
//   - Depends on ports (interfaces), not concrete adapters
//   - Implements use cases (add, get, list, search, update, delete)
//   - Returns domain errors
//
// Benefits:
//   - Testable: Can mock ports for unit testing
//   - Flexible: Can swap implementations without changing business logic
//   - Clean separation: Business logic isolated from infrastructure
package service

import (
	"fmt"
	"time"

	"github.com/arham09/paman/internal/domain/entity"
	"github.com/arham09/paman/internal/domain/port"
)

// CredentialService orchestrates credential-related use cases.
//
// Purpose: Coordinates between repository, crypto, and config ports
// to implement credential management operations.
//
// Design: Constructor injection - all dependencies are provided externally.
// Depends on ports (interfaces), not concrete implementations.
type CredentialService struct {
	repo   port.CredentialRepository
	crypto port.CryptoService
	config port.ConfigService
}

// NewCredentialService creates a new credential service.
//
// Purpose: Constructor that wires all dependencies.
// Uses constructor injection pattern - dependencies are required parameters.
//
// Parameters:
//   - repo: Credential repository port (for persistence)
//   - crypto: Crypto service port (for encryption/decryption)
//   - config: Config service port (for path resolution)
//
// Returns:
//   - *CredentialService: Service instance ready for use
func NewCredentialService(
	repo port.CredentialRepository,
	crypto port.CryptoService,
	config port.ConfigService,
) *CredentialService {
	return &CredentialService{
		repo:   repo,
		crypto: crypto,
		config: config,
	}
}

// AddCredential adds a new credential with encrypted password.
//
// Purpose: Use case for adding a new credential to the password manager.
// Encrypts the password and persists the credential.
//
// Parameters:
//   - title: Credential title/name (e.g., "GitHub", "Gmail")
//   - address: Optional URL/address (e.g., "https://github.com")
//   - username: User's email or username
//   - password: Plaintext password to encrypt
//
// Returns:
//   - int64: Auto-generated ID of the new credential
//   - error: Domain error if operation fails
//
// Workflow:
//   1. Get public key path from config
//   2. Load public key
//   3. Encrypt password with public key
//   4. Create credential entity
//   5. Validate credential
//   6. Persist to repository
func (s *CredentialService) AddCredential(title, address, username, password string) (int64, error) {
	// Get public key path
	publicKeyPath, err := s.config.GetPublicKeyPath()
	if err != nil {
		return 0, fmt.Errorf("failed to get public key path: %w", err)
	}

	// Load public key for encryption
	publicKey, err := s.crypto.LoadPublicKey(publicKeyPath)
	if err != nil {
		return 0, fmt.Errorf("failed to load public key: %w", err)
	}

	// Encrypt password with public key
	encryptedPassword, err := s.crypto.EncryptPassword(password, publicKey)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt password: %w", err)
	}

	// Create credential entity
	cred := &entity.Credential{
		Title:             title,
		Address:           address,
		Username:          username,
		EncryptedPassword: []byte(encryptedPassword),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	// Validate credential
	if err := cred.Validate(); err != nil {
		return 0, fmt.Errorf("invalid credential: %w", err)
	}

	// Persist to repository
	id, err := s.repo.Create(cred)
	if err != nil {
		return 0, fmt.Errorf("failed to create credential: %w", err)
	}

	return id, nil
}

// GetCredential retrieves a credential by ID, optionally decrypting the password.
//
// Purpose: Use case for retrieving a credential from the password manager.
// Optionally decrypts the password if requested.
//
// Parameters:
//   - id: Unique credential identifier
//   - showPassword: If true, decrypt and return the password
//   - privateKeyPath: Path to private key (required if showPassword is true)
//   - privateKeyPassphrase: Passphrase for private key (required if showPassword is true)
//
// Returns:
//   - *entity.Credential: The credential (with password if requested)
//   - string: The plaintext password (empty if showPassword is false)
//   - error: Domain error if operation fails
//
// Workflow:
//   1. Retrieve credential from repository
//   2. If showPassword is true:
//      a. Load private key from provided path with passphrase
//      b. Decrypt password
//   3. Return credential and password
func (s *CredentialService) GetCredential(id int, showPassword bool, privateKeyPath, privateKeyPassphrase string) (*entity.Credential, string, error) {
	// Retrieve credential from repository
	cred, err := s.repo.GetByID(id)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get credential: %w", err)
	}

	// If password decryption not requested, return as-is
	if !showPassword {
		return cred, "", nil
	}

	// Decrypt password
	password, err := s.decryptCredentialPassword(cred, privateKeyPath, privateKeyPassphrase)
	if err != nil {
		return nil, "", err
	}

	return cred, password, nil
}

// ListCredentials retrieves all credentials (without passwords).
//
// Purpose: Use case for listing all stored credentials.
// Returns credentials without decrypted passwords for security.
//
// Returns:
//   - []*entity.CredentialDisplay: All credentials (without passwords)
//   - error: Domain error if operation fails
//
// Workflow:
//   1. Retrieve all credentials from repository
//   2. Convert each to CredentialDisplay (removes encrypted password)
//   3. Return display list
func (s *CredentialService) ListCredentials() ([]*entity.CredentialDisplay, error) {
	// Retrieve all credentials from repository
	credentials, err := s.repo.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	// Convert to display format (removes encrypted passwords)
	displays := make([]*entity.CredentialDisplay, len(credentials))
	for i, cred := range credentials {
		display := cred.ToDisplay()
		displays[i] = &display
	}

	return displays, nil
}

// SearchCredentials searches credentials by query string.
//
// Purpose: Use case for searching stored credentials.
// Returns matching credentials without decrypted passwords.
//
// Parameters:
//   - query: Search query string
//
// Returns:
//   - []*entity.CredentialDisplay: Matching credentials (without passwords)
//   - error: Domain error if operation fails
//
// Workflow:
//   1. Search repository
//   2. Convert results to display format
//   3. Return display list
func (s *CredentialService) SearchCredentials(query string) ([]*entity.CredentialDisplay, error) {
	// Search repository
	credentials, err := s.repo.Search(query)
	if err != nil {
		return nil, fmt.Errorf("failed to search credentials: %w", err)
	}

	// Convert to display format
	displays := make([]*entity.CredentialDisplay, len(credentials))
	for i, cred := range credentials {
		display := cred.ToDisplay()
		displays[i] = &display
	}

	return displays, nil
}

// UpdateCredential updates an existing credential.
//
// Purpose: Use case for updating credential fields.
// Can update individual fields or entire credential.
//
// Parameters:
//   - id: Unique credential identifier
//   - title: New title (optional)
//   - address: New address (optional)
//   - username: New username (optional)
//   - password: New password (optional, encrypted if provided)
//   - privateKeyPath: Path to private key for re-encryption (only if password provided)
//
// Returns:
//   - error: Domain error if operation fails
//
// Workflow:
//   1. Verify credential exists
//   2. Build updates map with provided fields
//   3. If password provided, encrypt it
//   4. Apply partial update
func (s *CredentialService) UpdateCredential(id int, title, address, username, password, privateKeyPath string) error {
	// Verify credential exists
	exists, err := s.repo.Exists(id)
	if err != nil {
		return fmt.Errorf("failed to check credential existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("credential not found")
	}

	// Build updates map
	updates := make(map[string]interface{})

	if title != "" {
		updates["title"] = title
	}
	if address != "" {
		updates["address"] = address
	}
	if username != "" {
		updates["username"] = username
	}

	// If password provided, encrypt it
	if password != "" {
		publicKeyPath, err := s.config.GetPublicKeyPath()
		if err != nil {
			return fmt.Errorf("failed to get public key path: %w", err)
		}

		publicKey, err := s.crypto.LoadPublicKey(publicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load public key: %w", err)
		}

		encryptedPassword, err := s.crypto.EncryptPassword(password, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt password: %w", err)
		}

		updates["encrypted_password"] = encryptedPassword
	}

	// Apply partial update
	if err := s.repo.UpdatePartial(id, updates); err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	return nil
}

// DeleteCredential deletes a credential by ID.
//
// Purpose: Use case for removing a credential from the password manager.
// This operation is irreversible.
//
// Parameters:
//   - id: Unique credential identifier
//
// Returns:
//   - error: Domain error if operation fails
//
// Workflow:
//   1. Delete from repository
//   2. Return result
func (s *CredentialService) DeleteCredential(id int) error {
	if err := s.repo.Delete(id); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

// decryptCredentialPassword is a helper to decrypt a credential's password.
//
// Purpose: Centralizes password decryption logic.
// Loads private key and decrypts the password.
func (s *CredentialService) decryptCredentialPassword(cred *entity.Credential, privateKeyPath, privateKeyPassphrase string) (string, error) {
	// Note: Private key path is provided by user via --private-key flag
	// In the new design, private keys are NOT stored in ~/.paman/

	// Load private key with passphrase
	privateKey, err := s.crypto.LoadPrivateKey(privateKeyPassphrase, privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %w", err)
	}

	// Decrypt password
	password, err := s.crypto.DecryptPassword(string(cred.EncryptedPassword), privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password: %w", err)
	}

	return password, nil
}
