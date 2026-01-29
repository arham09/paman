// Package crypto provides cryptographic functions for paman.
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
package crypto

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

	"github.com/arham09/paman/internal/models"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// pbkdf2Iterations is the number of PBKDF2 iterations for key derivation.
	// 100,000 iterations is recommended by OWASP as of 2024 for PBKDF2-HMAC-SHA256.
	// Each iteration adds computational cost, making brute-force attacks more expensive.
	// At 100k iterations, each passphrase attempt takes significant time.
	pbkdf2Iterations = 100000

	// saltSize is the size of the random salt in bytes (32 bytes = 256 bits).
	// Salt ensures that the same passphrase produces different encryption keys.
	// Prevents rainbow table attacks and ensures unique keys even with identical passphrases.
	// 32 bytes matches the SHA-256 output size for optimal security.
	saltSize = 32

	// aesKeySize is the AES key size in bytes (32 bytes = 256 bits).
	// AES-256 is the strongest AES variant, approved for TOP SECRET data.
	// The key is derived from the passphrase using PBKDF2.
	aesKeySize = 32

	// gcmNonceSize is the size of the GCM nonce in bytes (12 bytes = 96 bits).
	// GCM (Galois/Counter Mode) requires a unique nonce for each encryption operation.
	// 12 bytes is the recommended size for GCM nonces (NIST SP 800-38D).
	// The nonce is stored alongside the encrypted data.
	gcmNonceSize = 12

	// minPassphraseLength is the minimum acceptable passphrase length in characters.
	// 12 characters provides a good balance between security and usability.
	// Longer passphrases are exponentially harder to brute-force.
	// Users should be encouraged to use multi-word passphrases for memorability.
	minPassphraseLength = 12
)

// SavePrivateKey encrypts and saves the RSA private key to disk using passphrase-based encryption.
//
// Purpose: Securely stores the private key by encrypting it with a user-provided passphrase.
// This is critical because anyone with access to the private key can decrypt all passwords.
//
// Parameters:
//   - privateKey: The RSA private key to encrypt and save (4096-bit)
//   - passphrase: User's passphrase (must be >= 12 characters)
//   - path: File path where the encrypted key will be saved
//
// Returns:
//   - error: Error if passphrase is too weak or encryption/writing fails
//
// Encryption Process:
//  1. Validate passphrase is >= 12 characters
//  2. Generate random salt (32 bytes) using crypto/rand
//  3. Derive 256-bit key from passphrase + salt using PBKDF2 (100k iterations)
//  4. Encode RSA private key to ASN.1 DER format (PKCS#1)
//  5. Encrypt the key bytes with AES-256-GCM using derived key
//  6. Write to disk: salt (32) + nonce (12) + encrypted_key
//
// File Format:
//
//	[32 bytes salt][12 bytes nonce][N bytes encrypted private key]
//
// Security:
//   - File permissions are set to 0600 (owner read/write only)
//   - Encryption uses AES-256-GCM which provides both confidentiality and integrity
//   - PBKDF2 with 100k iterations slows down brute-force attacks
//   - Random salt prevents pre-computation attacks
//
// When this is called:
//   - During "paman init" when creating new keys
//
// IMPORTANT: If the passphrase is forgotten, the private key cannot be decrypted
// and ALL stored passwords become permanently inaccessible.
func SavePrivateKey(privateKey *rsa.PrivateKey, passphrase, path string) error {
	// Validate passphrase meets minimum security requirements
	// This prevents users from creating weakly protected keys
	if len(passphrase) < minPassphraseLength {
		return models.ErrPassphraseTooWeak
	}

	// Generate a random salt for key derivation
	// Salt ensures that identical passphrases produce different encryption keys
	// This prevents rainbow table attacks and ensures unique encryption
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive a 256-bit AES key from the passphrase using PBKDF2
	// PBKDF2 (Password-Based Key Derivation Function 2) applies a pseudo-random function
	// (SHA-256 in this case) many times (100,000 iterations) to slow down brute-force attacks
	derivedKey := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Encode the RSA private key to ASN.1 DER format (PKCS#1 standard)
	// This converts the Go rsa.PrivateKey structure to a byte array suitable for encryption
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// Create an AES cipher block using the derived key
	// AES (Advanced Encryption Standard) is a symmetric encryption algorithm
	// The cipher block is the core encryption/decryption engine
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM (Galois/Counter Mode) mode on top of AES
	// GCM provides both encryption and authentication (AEAD - Authenticated Encryption with Associated Data)
	// This ensures that any tampering with the encrypted file will be detected
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce (number used once) for this encryption
	// GCM requires a unique nonce for each encryption operation with the same key
	// The nonce doesn't need to be secret, but it must never be reused with the same key
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate the private key using GCM
	// Seal() encrypts the data and adds an authentication tag
	// The authentication tag allows detection of any tampering with the encrypted data
	encryptedKey := gcm.Seal(nil, nonce, privateKeyBytes, nil)

	// Create the final encrypted file format: salt + nonce + encrypted_key
	// We need to store the salt and nonce alongside the encrypted data
	// because they're required for decryption
	encryptedData := append(salt, nonce...)
	encryptedData = append(encryptedData, encryptedKey...)

	// Write the encrypted data to disk with 0600 permissions
	// 0600 means: read/write for owner only, no permissions for group or others
	// This is critical for security - the encrypted private key must not be accessible to other users
	if err := os.WriteFile(path, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// LoadPrivateKey loads, decrypts, and parses the RSA private key from disk.
//
// Purpose: Retrieves and decrypts the private key using the user's passphrase.
// The private key is required to decrypt stored passwords.
//
// Parameters:
//   - passphrase: User's passphrase (must match the one used during encryption)
//   - path: File path to the encrypted private key
//
// Returns:
//   - *rsa.PrivateKey: The decrypted RSA private key
//   - error: Error if file can't be read, passphrase is wrong, or decryption fails
//
// Decryption Process:
//  1. Read encrypted file from disk
//  2. Extract salt (first 32 bytes), nonce (next 12 bytes), encrypted key (remainder)
//  3. Derive AES key from passphrase + salt using PBKDF2 (same parameters as encryption)
//  4. Decrypt the encrypted key using AES-256-GCM
//  5. Parse the decrypted bytes into RSA private key structure
//
// Security:
//   - GCM authentication verifies the data hasn't been tampered with
//   - Wrong passphrase → wrong derived key → decryption failure → ErrInvalidPassphrase
//   - Each decryption attempt requires 100k PBKDF2 iterations (slow)
//   - This limits brute-force attack speed
//
// When this is called:
//   - Any command that needs to decrypt passwords (get, list with decrypt, etc.)
//
// Error Handling:
//   - models.ErrInvalidPassphrase: Wrong passphrase (most common)
//   - models.ErrDecryptionFailed: File corrupted or tampered with
//   - Other errors: File system issues, permission problems, etc.
func LoadPrivateKey(passphrase, path string) (*rsa.PrivateKey, error) {
	// Read the entire encrypted private key file
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Validate the file has minimum required data: salt (32) + nonce (12) + at least 1 byte of data
	// This catches truncated or corrupted files early
	if len(encryptedData) < saltSize+gcmNonceSize+1 {
		return nil, models.ErrDecryptionFailed
	}

	// Extract the salt (first 32 bytes)
	// The salt was randomly generated during encryption and must be the same for decryption
	salt := encryptedData[:saltSize]

	// Extract the nonce (next 12 bytes after salt)
	// The nonce was randomly generated during encryption and must be the same for decryption
	nonce := encryptedData[saltSize : saltSize+gcmNonceSize]

	// Extract the encrypted private key (everything after salt and nonce)
	encryptedKey := encryptedData[saltSize+gcmNonceSize:]

	// Derive the AES key from the passphrase and salt using PBKDF2
	// This must use the exact same parameters as encryption (salt, iterations, hash function)
	// If the passphrase is wrong, the derived key will be wrong and decryption will fail
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
	// Open() verifies the authentication tag and decrypts the data
	// If the passphrase is wrong, the authentication tag verification will fail
	// This returns ErrInvalidPassphrase to avoid leaking information about the real error
	privateKeyBytes, err := gcm.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, models.ErrInvalidPassphrase
	}

	// Parse the decrypted bytes into an RSA private key structure
	// This converts from ASN.1 DER format back to a Go rsa.PrivateKey
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Return the decrypted and parsed private key
	// The caller can now use this to decrypt passwords
	return privateKey, nil
}

// SavePublicKey saves the RSA public key to disk in PEM format.
//
// Purpose: Stores the public key which is used to encrypt passwords.
// The public key doesn't need encryption - it's meant to be public.
//
// Parameters:
//   - publicKey: The RSA public key to save
//   - path: File path where the public key will be saved
//
// Returns:
//   - error: Error if file creation or writing fails
//
// File Format: PEM (Privacy-Enhanced Mail) format
//
//	PEM is a base64-encoded format with headers, widely used for cryptographic keys
//	Example:
//	  -----BEGIN RSA PUBLIC KEY-----
//	  MIIBCgKC... (base64 encoded data)
//	  -----END RSA PUBLIC KEY-----
//
// Security:
//   - File permissions are 0644 (readable by all, as it's public)
//   - No encryption needed - public keys are meant to be shared
//   - The public key can only encrypt, not decrypt
//
// When this is called:
//   - During "paman init" after key generation
func SavePublicKey(publicKey *rsa.PublicKey, path string) error {
	// Encode the RSA public key to ASN.1 DER format (PKCS#1 standard)
	// This converts the Go rsa.PublicKey structure to a byte array
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)

	// Create a PEM block containing the public key
	// PEM format includes type information and base64 encoding
	// This makes the key human-readable and easy to copy/paste
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY", // PEM block type
		Bytes: publicKeyBytes,   // The DER-encoded key data
	}

	// Create the public key file with 0644 permissions
	// 0644 means: read/write for owner, read-only for group and others
	// Public keys don't need protection - they're meant to be public
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer file.Close()

	// Write the PEM-encoded public key to the file
	// pem.Encode() handles the base64 encoding and PEM formatting
	if err := pem.Encode(file, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadPublicKey loads and parses the RSA public key from disk.
//
// Purpose: Reads the public key from disk for use in password encryption.
//
// Parameters:
//   - path: File path to the public key file
//
// Returns:
//   - *rsa.PublicKey: The loaded RSA public key
//   - error: Error if file can't be read or parsed
//
// When this is called:
//   - During "paman add" to encrypt new passwords
//   - During "paman update" when updating passwords
//
// File Format Expected: PEM format (same as SavePublicKey writes)
//
//	The function decodes the PEM format and parses the DER data
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	// Read the entire public key file
	publicKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	// Decode the PEM block
	// PEM format wraps binary data in base64 with headers
	// pem.Decode() extracts the binary data from the PEM format
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the DER-encoded public key into an RSA public key structure
	// This converts from ASN.1 DER format to a Go rsa.PublicKey
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Return the parsed public key
	// The caller can now use this to encrypt passwords
	return publicKey, nil
}

// KeyFilesExist checks if both the private and public key files exist on disk.
//
// Purpose: Quick check to determine if paman has been initialized.
// Both keys must exist for the system to be functional.
//
// Parameters:
//   - privateKeyPath: Path to the private key file
//   - publicKeyPath: Path to the public key file
//
// Returns:
//   - bool: true only if BOTH files exist, false otherwise
//
// When this is called:
//   - During "paman init" to prevent overwriting existing keys
//   - During other commands to verify initialization
//
// Security Note:
//   - This only checks file existence, not validity or permissions
//   - A file could exist but be corrupted or have wrong permissions
func KeyFilesExist(privateKeyPath, publicKeyPath string) bool {
	// Check if private key file exists
	// os.Stat() returns file info, error if file doesn't exist
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
// This is a helper function for key storage operations.
//
// Parameters:
//   - path: Path to a key file (directory is extracted from this path)
//
// Returns:
//   - error: Error if directory creation fails
//
// Security:
//   - Creates directory with 0700 permissions (owner only)
//   - This prevents other users from accessing the keys
//
// Note: This function is currently not used but kept for future flexibility.
func EnsureKeyDir(path string) error {
	// Extract the directory path from the file path
	dir := filepath.Dir(path)

	// Create the directory with 0700 permissions if it doesn't exist
	// MkdirAll creates parent directories as needed
	return os.MkdirAll(dir, 0700)
}
