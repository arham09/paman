// Package security provides cryptographic implementations for paman.
// This file implements the CryptoService port using RSA encryption.
//
// Security Architecture:
//   - RSA-4096 bit keys for asymmetric encryption
//   - RSA-OAEP (Optimal Asymmetric Encryption Padding) with SHA-256
//   - PBKDF2 (100k iterations) for key derivation from passphrase
//   - AES-256-GCM for encrypting the private key at rest
//
// Purpose: This adapter implements the CryptoService interface defined in the domain layer.
// It provides the actual cryptographic operations needed by the application.
package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	domainerror "github.com/arham09/paman/internal/domain/error"
)

// RSACryptoService implements the CryptoService port using RSA cryptography.
//
// Purpose: Provides RSA-based cryptographic operations for password encryption/decryption
// and key management. This is an adapter that implements the domain's CryptoService port.
//
// Design: Stateless service - all methods are pure functions that don't maintain state.
// Keys are provided as parameters and managed externally.
type RSACryptoService struct{}

// NewRSACryptoService creates a new RSA crypto service.
//
// Purpose: Constructor that creates a crypto service instance.
// Since the service is stateless, this just returns an empty struct.
//
// Returns:
//   - *RSACryptoService: Crypto service instance ready for use
func NewRSACryptoService() *RSACryptoService {
	return &RSACryptoService{}
}

// GenerateKeyPair generates a new 4096-bit RSA key pair for encryption/decryption.
//
// Purpose: Creates the cryptographic keys used to encrypt and decrypt passwords.
// Implements the CryptoService.GenerateKeyPair() method.
func (s *RSACryptoService) GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Generate a new RSA private key with 4096-bit modulus
	// rand.Reader provides cryptographically secure random numbers
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Extract the public key from the private key
	// In RSA, the public key is just the modulus (n) and public exponent (e)
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

// EncryptPassword encrypts a plaintext password using the public key.
//
// Purpose: Encrypts passwords before storing them in the database.
// Implements the CryptoService.EncryptPassword() method.
func (s *RSACryptoService) EncryptPassword(password string, publicKey *rsa.PublicKey) (string, error) {
	// Validate input - empty passwords are not allowed
	if password == "" {
		return "", domainerror.ErrInvalidInput
	}

	// Encrypt the password using RSA-OAEP with SHA-256
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(password), nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", domainerror.ErrEncryptionFailed, err)
	}

	// Encode the encrypted binary data to Base64
	encoded := base64.StdEncoding.EncodeToString(encrypted)
	return encoded, nil
}

// DecryptPassword decrypts an encrypted password using the private key.
//
// Purpose: Retrieves and decrypts a password that was encrypted with EncryptPassword().
// Implements the CryptoService.DecryptPassword() method.
func (s *RSACryptoService) DecryptPassword(encryptedPassword string, privateKey *rsa.PrivateKey) (string, error) {
	// Validate input
	if encryptedPassword == "" {
		return "", domainerror.ErrInvalidInput
	}

	// Decode the Base64-encoded encrypted password back to binary
	encrypted, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("%w: failed to decode base64", domainerror.ErrDecryptionFailed)
	}

	// Decrypt the encrypted password using RSA-OAEP
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", domainerror.ErrDecryptionFailed, err)
	}

	// Convert decrypted bytes back to string
	return string(decrypted), nil
}

// The remaining methods (key loading/saving) are delegated to the keyManager
// This separation keeps the crypto service focused on encryption/decryption
// while keyManager handles file I/O and key encryption

// SavePrivateKey encrypts and saves the private key to disk.
// Delegates to keyManager for implementation.
func (s *RSACryptoService) SavePrivateKey(privateKey *rsa.PrivateKey, passphrase, path string) error {
	return savePrivateKey(privateKey, passphrase, path)
}

// LoadPrivateKey loads, decrypts, and parses the private key from disk.
// Delegates to keyManager for implementation.
func (s *RSACryptoService) LoadPrivateKey(passphrase, path string) (*rsa.PrivateKey, error) {
	return loadPrivateKey(passphrase, path)
}

// SavePublicKey saves the public key to disk in PEM format.
// Delegates to keyManager for implementation.
func (s *RSACryptoService) SavePublicKey(publicKey *rsa.PublicKey, path string) error {
	return savePublicKey(publicKey, path)
}

// LoadPublicKey loads and parses the public key from disk.
// Delegates to keyManager for implementation.
func (s *RSACryptoService) LoadPublicKey(path string) (*rsa.PublicKey, error) {
	return loadPublicKey(path)
}

// KeyFilesExist checks if both key files exist on disk.
// Delegates to keyManager for implementation.
func (s *RSACryptoService) KeyFilesExist(privateKeyPath, publicKeyPath string) bool {
	return keyFilesExist(privateKeyPath, publicKeyPath)
}

// GenerateRandomBytes generates cryptographically secure random bytes.
// Helper function for key generation and testing.
func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}
