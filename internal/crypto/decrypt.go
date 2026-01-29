// Package crypto provides cryptographic functions for paman.
// This file handles password decryption using RSA private keys.
//
// Decryption Method: RSA-OAEP (Optimal Asymmetric Encryption Padding)
//   - OAEP with SHA-256 must match the encryption method
//   - Only the private key can decrypt what was encrypted with the public key
//
// Password Retrieval Flow:
//  1. Retrieve Base64-encoded encrypted password from SQLite database
//  2. Decode Base64 to binary encrypted data
//  3. Decrypt using RSA private key with OAEP-SHA256
//  4. Return plaintext password to user (with --show-password flag)
//
// Security: Passwords can ONLY be decrypted by someone who:
//  1. Has access to the private key file (~/.paman/private_key.pem)
//  2. Knows the passphrase to decrypt the private key
//
// This two-layer protection (encrypted private key + encrypted passwords) provides
// defense in depth: even if the database is stolen, passwords remain safe.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/arham09/paman/internal/models"
)

// DecryptPassword decrypts a Base64-encoded encrypted password using RSA-OAEP.
//
// Purpose: Retrieves and decrypts a password that was encrypted with EncryptPassword().
// This is the reverse operation of encryption, requiring the private key.
//
// Parameters:
//   - encryptedPassword: Base64-encoded encrypted password (from database)
//   - privateKey: The RSA private key (must be the matching pair to the public key used for encryption)
//
// Returns:
//   - string: The plaintext password (user's actual password)
//   - error: Error if data is invalid or decryption fails
//
// Decryption Process:
//  1. Validate encrypted password is not empty
//  2. Decode Base64 string back to binary encrypted data
//  3. Decrypt using RSA-OAEP with SHA-256 (must match encryption parameters)
//  4. Convert decrypted bytes back to string
//
// Why Base64 decoding?
//   - Encrypted passwords are stored in database as Base64-encoded TEXT
//   - Need to decode back to binary before RSA decryption
//   - RSA works on binary data, not text strings
//
// Security:
//   - Decryption will FAIL if wrong private key is used
//   - Decryption will FAIL if encrypted data is corrupted
//   - Only the holder of the private key can decrypt
//   - The private key itself is encrypted with a passphrase (two-layer security)
//
// When this is called:
//   - During "paman get <id> --show-password" to display a password
//   - During password verification/update operations
//
// Error Scenarios:
//   - Invalid Base64: Corrupted database data
//   - Decryption failure: Wrong key or tampered data
//   - Empty input: Database integrity issue
func DecryptPassword(encryptedPassword string, privateKey *rsa.PrivateKey) (string, error) {
	// Validate input - empty encrypted passwords indicate database corruption
	if encryptedPassword == "" {
		return "", models.ErrInvalidInput
	}

	// Decode the Base64-encoded encrypted password back to binary
	// This reverses the Base64 encoding done in EncryptPassword()
	// Base64 is safe for database storage but RSA needs raw binary
	encrypted, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		// Base64 decoding error indicates corrupted database data
		// The stored value is not valid Base64
		return "", fmt.Errorf("%w: failed to decode base64", models.ErrDecryptionFailed)
	}

	// Decrypt the encrypted password using RSA-OAEP
	// Parameters:
	//   - hash: SHA-256 hash function (MUST match encryption)
	//   - random: Random source (required for OAEP blinding)
	//   - privKey: The RSA private key (must match the public key used for encryption)
	//   - ciphertext: The encrypted password bytes
	//   - label: Optional label (must match encryption, nil = no label)
	//
	// OAEP decryption reverses the OAEP padding applied during encryption
	// The padding includes random data, so the same plaintext encrypts differently each time
	// but always decrypts back to the original plaintext
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encrypted, nil)
	if err != nil {
		// Decryption can fail if:
		// - Wrong private key (key mismatch)
		// - Encrypted data is corrupted or tampered with
		// - Padding is invalid (attacker modified data)
		return "", fmt.Errorf("%w: %v", models.ErrDecryptionFailed, err)
	}

	// Convert decrypted bytes back to string
	// The original password was a string, so we convert back
	return string(decrypted), nil
}

// DecryptPasswordBytes decrypts encrypted password bytes and returns raw plaintext bytes.
//
// Purpose: Same as DecryptPassword but works with bytes directly and doesn't handle Base64.
// Useful when you already have the binary encrypted data.
//
// Parameters:
//   - encryptedPassword: The encrypted password as raw binary bytes (not Base64-encoded)
//   - privateKey: The RSA private key for decryption
//
// Returns:
//   - []byte: The decrypted password as raw bytes
//   - error: Error if decryption fails
//
// When to use:
//   - Use DecryptPassword() when reading from database (handles Base64)
//   - Use DecryptPasswordBytes() if you have raw encrypted binary data
//
// Note: This function is currently not used in the main application flow
// but is provided for flexibility and testing purposes.
func DecryptPasswordBytes(encryptedPassword []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Validate input - empty encrypted passwords are invalid
	if len(encryptedPassword) == 0 {
		return nil, models.ErrInvalidInput
	}

	// Decrypt the encrypted password bytes using RSA-OAEP
	// Same decryption as DecryptPassword but doesn't handle Base64
	// This is useful if you're working with raw binary data
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedPassword, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", models.ErrDecryptionFailed, err)
	}

	// Return the decrypted bytes
	return decrypted, nil
}
