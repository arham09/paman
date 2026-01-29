// Package security provides key management utilities for paman.
// This file handles secure key storage and loading with passphrase protection.
//
// Security Architecture for Private Key Storage:
//  1. User enters a passphrase (min 12 characters)
//  2. Generate random salt (32 bytes)
//  3. Derive encryption key using PBKDF2-SHA256 (100,000 iterations)
//  4. Encrypt RSA private key with AES-256-GCM
//  5. Store: salt + nonce + encrypted_private_key
//
// Why this approach?
//   - PBKDF2 slows down brute-force attacks (100k iterations)
//   - Random salt prevents rainbow table attacks
//   - AES-256-GCM provides both encryption and authentication
//   - Nonce ensures unique encryption even with same passphrase
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	domainerror "github.com/arham09/paman/internal/domain/error"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// pbkdf2Iterations is the number of PBKDF2 iterations for key derivation.
	// 100,000 iterations is recommended by OWASP as of 2024 for PBKDF2-HMAC-SHA256.
	pbkdf2Iterations = 100000

	// saltSize is the size of the random salt in bytes (32 bytes = 256 bits).
	saltSize = 32

	// aesKeySize is the AES key size in bytes (32 bytes = 256 bits).
	aesKeySize = 32

	// gcmNonceSize is the size of the GCM nonce in bytes (12 bytes = 96 bits).
	gcmNonceSize = 12

	// minPassphraseLength is the minimum acceptable passphrase length in characters.
	minPassphraseLength = 12
)

// savePrivateKey encrypts and saves the RSA private key to disk using passphrase-based encryption.
//
// Purpose: Securely stores the private key by encrypting it with a user-provided passphrase.
// This is critical because anyone with access to the private key can decrypt all passwords.
func savePrivateKey(privateKey *rsa.PrivateKey, passphrase, path string) error {
	// Validate passphrase meets minimum security requirements
	if len(passphrase) < minPassphraseLength {
		return domainerror.ErrPassphraseTooWeak
	}

	// Generate a random salt for key derivation
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive a 256-bit AES key from the passphrase using PBKDF2
	derivedKey := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Encode the RSA private key to ASN.1 DER format (PKCS#1 standard)
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// Create an AES cipher block using the derived key
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM (Galois/Counter Mode) mode on top of AES
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce (number used once) for this encryption
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate the private key using GCM
	encryptedKey := gcm.Seal(nil, nonce, privateKeyBytes, nil)

	// Create the final encrypted file format: salt + nonce + encrypted_key
	encryptedData := append(salt, nonce...)
	encryptedData = append(encryptedData, encryptedKey...)

	// Write the encrypted data to disk with 0600 permissions
	if err := os.WriteFile(path, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// loadPrivateKey loads, decrypts, and parses the RSA private key from disk.
//
// Purpose: Retrieves and decrypts the private key using the user's passphrase.
// The private key is required to decrypt stored passwords.
func loadPrivateKey(passphrase, path string) (*rsa.PrivateKey, error) {
	// Read the entire encrypted private key file
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Validate the file has minimum required data: salt (32) + nonce (12) + at least 1 byte of data
	if len(encryptedData) < saltSize+gcmNonceSize+1 {
		return nil, domainerror.ErrDecryptionFailed
	}

	// Extract the salt (first 32 bytes)
	salt := encryptedData[:saltSize]

	// Extract the nonce (next 12 bytes after salt)
	nonce := encryptedData[saltSize : saltSize+gcmNonceSize]

	// Extract the encrypted private key (everything after salt and nonce)
	encryptedKey := encryptedData[saltSize+gcmNonceSize:]

	// Derive the AES key from the passphrase and salt using PBKDF2
	derivedKey := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Create an AES cipher block using the derived key
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode for authenticated decryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and authenticate the encrypted private key
	privateKeyBytes, err := gcm.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, domainerror.ErrInvalidPassphrase
	}

	// Parse the decrypted bytes into an RSA private key structure
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// savePublicKey saves the RSA public key to disk in PEM format.
//
// Purpose: Stores the public key which is used to encrypt passwords.
// The public key doesn't need encryption - it's meant to be public.
func savePublicKey(publicKey *rsa.PublicKey, path string) error {
	// Encode the RSA public key to ASN.1 DER format (PKCS#1 standard)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)

	// Create a PEM block containing the public key
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Create the public key file with 0644 permissions
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer file.Close()

	// Write the PEM-encoded public key to the file
	if err := pem.Encode(file, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// loadPublicKey loads and parses the RSA public key from disk.
//
// Purpose: Reads the public key from disk for use in password encryption.
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	// Read the entire public key file
	publicKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the DER-encoded public key into an RSA public key structure
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return publicKey, nil
}

// keyFilesExist checks if both the private and public key files exist on disk.
//
// Purpose: Quick check to determine if paman has been initialized.
func keyFilesExist(privateKeyPath, publicKeyPath string) bool {
	// Check if private key file exists
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return false
	}

	// Check if public key file exists
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return false
	}

	// Both files exist
	return true
}

// EnsureKeyDir creates the directory for storing keys if it doesn't exist.
//
// Purpose: Ensures the target directory exists before writing key files.
func EnsureKeyDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0700)
}
