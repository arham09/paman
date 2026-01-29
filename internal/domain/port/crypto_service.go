// Package port defines the interfaces that the domain layer requires.
package port

import (
	"crypto/rsa"
)

// CryptoService defines the contract for cryptographic operations.
//
// Purpose: This is a primary port interface that defines how the domain layer
// performs encryption and decryption operations. It's implemented by adapters
// like RSACryptoService.
//
// Design Principles:
//   - Interface depends only on crypto/rsa types, not implementations
//   - Separates key management from encryption/decryption
//   - Supports both key generation and key loading
//   - Encrypted data is Base64-encoded for storage
//
// Security:
//   - Encryption uses RSA-4096-OAEP with SHA-256
//   - Private keys are encrypted with AES-256-GCM
//   - Passphrase-based key derivation uses PBKDF2 (100k iterations)
//
// Benefits:
//   - Domain logic doesn't depend on specific crypto implementations
//   - Easy to swap crypto algorithms (if needed in future)
//   - Can mock for testing without real cryptographic operations
type CryptoService interface {
	// GenerateKeyPair creates a new RSA key pair for encryption/decryption.
	//
	// Returns:
	//   - *rsa.PrivateKey: The private key (keep secret!)
	//   - *rsa.PublicKey: The public key (used for encryption)
	//   - error: Domain error if generation fails
	//
	// Security: Uses RSA-4096-bit keys with cryptographically secure random numbers.
	GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error)

	// EncryptPassword encrypts a plaintext password using the public key.
	//
	// Parameters:
	//   - password: The plaintext password to encrypt
	//   - publicKey: The RSA public key for encryption
	//
	// Returns:
	//   - string: Base64-encoded encrypted password (ready for storage)
	//   - error: Domain error if encryption fails
	//
	// Process:
	//   1. Encrypt with RSA-OAEP-SHA256
	//   2. Encode result to Base64
	//
	// Security: Password can only be decrypted with the matching private key.
	EncryptPassword(password string, publicKey *rsa.PublicKey) (string, error)

	// DecryptPassword decrypts an encrypted password using the private key.
	//
	// Parameters:
	//   - encryptedPassword: Base64-encoded encrypted password (from storage)
	//   - privateKey: The RSA private key for decryption
	//
	// Returns:
	//   - string: The plaintext password
	//   - error: Domain error if decryption fails
	//
	// Process:
	//   1. Decode Base64 to binary
	//   2. Decrypt with RSA-OAEP-SHA256
	//
	// Security: Only the holder of the private key can decrypt.
	DecryptPassword(encryptedPassword string, privateKey *rsa.PrivateKey) (string, error)

	// SavePrivateKey encrypts and saves the private key to disk.
	//
	// Parameters:
	//   - privateKey: The RSA private key to encrypt and save
	//   - passphrase: User's passphrase for encryption (min 12 chars)
	//   - path: File path where encrypted key will be saved
	//
	// Returns:
	//   - error: Domain error if save fails
	//
	// Process:
	//   1. Validate passphrase length
	//   2. Generate random salt (32 bytes)
	//   3. Derive AES-256 key using PBKDF2 (100k iterations)
	//   4. Encrypt private key with AES-256-GCM
	//   5. Write salt + nonce + encrypted_key to disk
	//
	// Security: File is written with 0600 permissions (owner only).
	SavePrivateKey(privateKey *rsa.PrivateKey, passphrase, path string) error

	// LoadPrivateKey loads, decrypts, and parses the private key from disk.
	//
	// Parameters:
	//   - passphrase: User's passphrase for decryption
	//   - path: File path to encrypted private key
	//
	// Returns:
	//   - *rsa.PrivateKey: The decrypted private key
	//   - error: Domain error if load fails
	//
	// Process:
	//   1. Read encrypted file
	//   2. Extract salt, nonce, encrypted key
	//   3. Derive AES key using PBKDF2
	//   4. Decrypt with AES-256-GCM
	//   5. Parse RSA private key
	//
	// Security: GCM authentication verifies data integrity.
	// Wrong passphrase → decryption failure.
	LoadPrivateKey(passphrase, path string) (*rsa.PrivateKey, error)

	// SavePublicKey saves the public key to disk in PEM format.
	//
	// Parameters:
	//   - publicKey: The RSA public key to save
	//   - path: File path where public key will be saved
	//
	// Returns:
	//   - error: Domain error if save fails
	//
	// Security: Public key doesn't need encryption. File uses 0644 permissions.
	SavePublicKey(publicKey *rsa.PublicKey, path string) error

	// LoadPublicKey loads and parses the public key from disk.
	//
	// Parameters:
	//   - path: File path to public key
	//
	// Returns:
	//   - *rsa.PublicKey: The loaded public key
	//   - error: Domain error if load fails
	//
	// File Format: PEM format (standard for cryptographic keys).
	LoadPublicKey(path string) (*rsa.PublicKey, error)

	// KeyFilesExist checks if both key files exist on disk.
	//
	// Parameters:
	//   - privateKeyPath: Path to private key file
	//   - publicKeyPath: Path to public key file
	//
	// Returns:
	//   - bool: true only if BOTH files exist
	//
	// Purpose: Quick check for initialization status.
	KeyFilesExist(privateKeyPath string, publicKeyPath string) bool
}
