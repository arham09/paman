// Package crypto provides cryptographic functions for paman.
// It handles RSA key generation, encryption, decryption, and secure key storage.
//
// Security Architecture:
//   - RSA-4096 bit keys for asymmetric encryption
//   - RSA-OAEP (Optimal Asymmetric Encryption Padding) with SHA-256
//   - PBKDF2 (100k iterations) for key derivation from passphrase
//   - AES-256-GCM for encrypting the private key at rest
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// GenerateKeyPair generates a new 4096-bit RSA key pair for password encryption.
//
// Purpose: Creates the cryptographic keys used to encrypt and decrypt passwords.
// The public key encrypts passwords, and the private key decrypts them.
//
// Returns:
//   - *rsa.PrivateKey: The private key (used for decryption) - MUST be kept secret!
//   - *rsa.PublicKey: The public key (used for encryption) - can be shared
//   - error: An error if key generation fails
//
// Security Details:
//   - Key Size: 4096 bits (recommended for high-security applications)
//   - Algorithm: RSA (Rivest-Shamir-Adleman)
//   - Randomness: Uses crypto/rand (cryptographically secure random number generator)
//
// Why 4096 bits?
//   - 2048-bit RSA is currently considered secure
//   - 4096-bit provides a large security margin for future-proofing
//   - Protects against potential advances in cryptanalysis
//   - Trade-off: Slower encryption/decryption but acceptable for CLI usage
//
// When this is called:
//   - During "paman init" to generate the initial key pair
//   - Keys are then stored: private key encrypted, public key as-is
//
// Key Lifetime:
//   - Keys are generated once during initialization
//   - Private key is encrypted with passphrase and stored
//   - Public key is stored unencrypted (it's public, after all)
//   - Keys are used for all subsequent encrypt/decrypt operations
//
// IMPORTANT: If the private key is lost, all encrypted passwords become permanently
// inaccessible. There is no way to recover passwords without the private key.
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Generate a new RSA private key with 4096-bit modulus
	// rand.Reader provides cryptographically secure random numbers
	// 4096 is the key size in bits (the modulus length)
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		// Key generation can fail if the system runs out of entropy
		// or if there's an issue with the random number generator
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Extract the public key from the private key
	// In RSA, the public key is just the modulus (n) and public exponent (e)
	// These are already part of the private key structure
	publicKey := &privateKey.PublicKey

	// Return both keys - the caller is responsible for storing them securely
	return privateKey, publicKey, nil
}
