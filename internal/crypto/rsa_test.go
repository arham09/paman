package crypto

import (
	"testing"
)

// TestGenerateKeyPair tests that RSA key generation works correctly
func TestGenerateKeyPair(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Check that keys are not nil
	if privateKey == nil {
		t.Fatal("Private key should not be nil")
	}

	if publicKey == nil {
		t.Fatal("Public key should not be nil")
	}

	// Check that public key matches private key
	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 {
		t.Error("Public key modulus does not match private key")
	}

	if privateKey.PublicKey.E != publicKey.E {
		t.Error("Public key exponent does not match private key")
	}
}

// TestGenerateKeyPairMultipleTimes tests that key generation produces different keys each time
func TestGenerateKeyPairMultipleTimes(t *testing.T) {
	key1, _, err1 := GenerateKeyPair()
	if err1 != nil {
		t.Fatalf("First GenerateKeyPair failed: %v", err1)
	}

	key2, _, err2 := GenerateKeyPair()
	if err2 != nil {
		t.Fatalf("Second GenerateKeyPair failed: %v", err2)
	}

	// Keys should be different (random generation)
	// Compare the moduli
	if key1.N.Cmp(key2.N) == 0 {
		t.Error("Key generation should produce different keys each time")
	}
}

// TestGenerateKeyPairConsistency tests that the same private key always produces the same public key
func TestGenerateKeyPairConsistency(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Extract public key from private key
	publicKeyFromPrivate := &privateKey.PublicKey

	// Check they match
	if publicKeyFromPrivate.N.Cmp(publicKey.N) != 0 {
		t.Error("Public key from private key should match the generated public key")
	}

	if publicKeyFromPrivate.E != publicKey.E {
		t.Error("Public key exponent should match")
	}
}
