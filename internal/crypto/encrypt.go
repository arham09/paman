// Package crypto provides cryptographic functions for paman.
// This file handles password encryption using RSA public keys.
//
// Encryption Method: RSA-OAEP (Optimal Asymmetric Encryption Padding)
//   - OAEP with SHA-256 is the recommended padding scheme for RSA encryption
//   - Provides semantic security and prevents chosen ciphertext attacks
//   - Maximum plaintext size for RSA-4096: 470 bytes (after OAEP padding)
//
// Password Storage Flow:
//  1. User enters password (plaintext)
//  2. Encrypt password with RSA public key using OAEP-SHA256
//  3. Encode encrypted result to Base64
//  4. Store Base64 string in SQLite database
//
// Security: Passwords can ONLY be decrypted with the private key (which is passphrase-protected)
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/arham09/paman/internal/models"
)

// EncryptPassword encrypts a plaintext password using RSA-OAEP with SHA-256.
//
// Purpose: Encrypts passwords before storing them in the database.
// Uses the public key so only the holder of the private key can decrypt.
//
// Parameters:
//   - password: The plaintext password to encrypt (user's actual password)
//   - publicKey: The RSA public key (4096-bit) for encryption
//
// Returns:
//   - string: Base64-encoded encrypted password (ready for database storage)
//   - error: Error if password is empty or encryption fails
//
// Encryption Process:
//  1. Validate password is not empty
//  2. Convert password string to bytes
//  3. Encrypt using RSA-OAEP with SHA-256 hash function
//  4. Encode encrypted bytes to Base64 for database storage
//
// Why Base64 encoding?
//   - Encrypted RSA output is binary data (arbitrary bytes)
//   - SQLite TEXT column expects text/strings
//   - Base64 converts binary to safe ASCII characters
//   - Easy to store and retrieve from database
//
// Security:
//   - RSA-OAEP prevents chosen ciphertext attacks
//   - SHA-256 provides cryptographic hash for padding
//   - Can only be decrypted with the matching private key
//   - Even if database is stolen, passwords remain safe
//
// When this is called:
//   - During "paman add" when adding a new credential
//   - During "paman update" when updating a password
//
// Password Size Limit:
//   - Maximum: ~470 characters (due to RSA-4096 with OAEP padding)
//   - Most passwords are well under this limit
func EncryptPassword(password string, publicKey *rsa.PublicKey) (string, error) {
	// Validate input - empty passwords are not allowed
	// This prevents accidental storage of empty credentials
	if password == "" {
		return "", models.ErrInvalidInput
	}

	// Encrypt the password using RSA-OAEP (Optimal Asymmetric Encryption Padding)
	// Parameters:
	//   - hash: SHA-256 hash function for the padding
	//   - random: Cryptographically secure random number generator
	//   - pubKey: The RSA public key for encryption
	//   - message: The password bytes to encrypt
	//   - label: Optional label (nil = no label)
	//
	// OAEP adds random padding to ensure that encrypting the same plaintext
	// multiple times produces different ciphertexts (prevents pattern analysis)
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(password), nil)
	if err != nil {
		// Encryption can fail if:
		// - Message is too long for the key size (>470 bytes for RSA-4096)
		// - Random number generator fails
		return "", fmt.Errorf("%w: %v", models.ErrEncryptionFailed, err)
	}

	// Encode the encrypted binary data to Base64
	// Base64 encoding makes the data safe for storage in text format
	// Standard encoding uses A-Z, a-z, 0-9, +, / characters
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	// Return the Base64-encoded encrypted password
	// This is what gets stored in the database
	return encoded, nil
}

// EncryptPasswordBytes encrypts password bytes and returns raw encrypted bytes (not Base64).
//
// Purpose: Same as EncryptPassword but works with bytes directly and doesn't Base64 encode.
// This is useful if you want the raw encrypted binary data.
//
// Parameters:
//   - password: The password as bytes (plaintext)
//   - publicKey: The RSA public key for encryption
//
// Returns:
//   - []byte: Raw encrypted binary data (not Base64-encoded)
//   - error: Error if password is empty or encryption fails
//
// When to use:
//   - Use EncryptPassword() for database storage (Base64 encoded)
//   - Use EncryptPasswordBytes() if you need raw binary encrypted data
//
// Note: This function is currently not used in the main application flow
// but is provided for flexibility and testing purposes.
func EncryptPasswordBytes(password []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	// Validate input - empty passwords are not allowed
	if len(password) == 0 {
		return nil, models.ErrInvalidInput
	}

	// Encrypt the password bytes using RSA-OAEP
	// Same encryption as EncryptPassword but returns raw bytes instead of Base64
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, password, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", models.ErrEncryptionFailed, err)
	}

	// Return the raw encrypted binary data
	return encrypted, nil
}

// GenerateRandomBytes generates cryptographically secure random bytes.
//
// Purpose: Helper function for generating random data.
// Currently not used in main application but useful for testing and future features.
//
// Parameters:
//   - size: Number of random bytes to generate
//
// Returns:
//   - []byte: Random bytes suitable for cryptographic use
//   - error: Error if random number generation fails
//
// Security:
//   - Uses crypto/rand which is cryptographically secure
//   - NOT math/rand which is predictable and not suitable for security
//
// Potential Uses:
//   - Testing encryption/decryption
//   - Generating salts for other purposes
//   - Creating session tokens or CSRF tokens
//   - Future password generation features
//
// Note: If entropy is exhausted on the system, this will block or error
func GenerateRandomBytes(size int) ([]byte, error) {
	// Allocate a byte slice of the requested size
	b := make([]byte, size)

	// Fill the slice with cryptographically secure random bytes
	// io.ReadFull ensures exactly 'size' bytes are read
	// crypto/rand reads from the operating system's CSPRNG
	// (e.g., /dev/urandom on Unix, CryptGenRandom on Windows)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		// This is rare but can happen if:
		// - System entropy pool is exhausted
		// - Hardware RNG failure
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Return the random bytes
	return b, nil
}
