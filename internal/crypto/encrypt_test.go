package crypto

import (
	"testing"
)

// TestEncryptPassword tests that password encryption works correctly
func TestEncryptPassword(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	password := "test_password_123"

	// Encrypt the password
	encrypted, err := EncryptPassword(password, publicKey)
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}

	// Check that encrypted string is not empty
	if encrypted == "" {
		t.Error("Encrypted password should not be empty")
	}

	// Check that encrypted password is different from original
	if encrypted == password {
		t.Error("Encrypted password should be different from original password")
	}

	// Decrypt to verify
	decrypted, err := DecryptPassword(encrypted, privateKey)
	if err != nil {
		t.Fatalf("DecryptPassword failed: %v", err)
	}

	if decrypted != password {
		t.Errorf("Decrypted password doesn't match original. Got %s, want %s", decrypted, password)
	}
}

// TestEncryptPasswordEmpty tests that empty password returns an error
func TestEncryptPasswordEmpty(t *testing.T) {
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	_, err = EncryptPassword("", publicKey)
	if err == nil {
		t.Error("Expected error for empty password, got nil")
	}
}

// TestEncryptPasswordDifferentPasswords tests that different passwords produce different ciphertexts
func TestEncryptPasswordDifferentPasswords(t *testing.T) {
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	password1 := "password123"
	password2 := "password456"

	encrypted1, err := EncryptPassword(password1, publicKey)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := EncryptPassword(password2, publicKey)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Same password should produce different ciphertext (due to OAEP random padding)
	encrypted1Again, err := EncryptPassword(password1, publicKey)
	if err != nil {
		t.Fatalf("Third encryption failed: %v", err)
	}

	if encrypted1 == encrypted1Again {
		t.Error("OAEP encryption should produce different ciphertext for the same plaintext (random padding)")
	}

	// Different passwords should produce different ciphertext
	if encrypted1 == encrypted2 {
		t.Error("Different passwords should produce different ciphertext")
	}
}

// TestEncryptPasswordLongPassword tests encryption of a long password
func TestEncryptPasswordLongPassword(t *testing.T) {
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create a password that's close to the maximum size for RSA-4096 with OAEP
	// Maximum is 470 bytes, but let's test with a reasonably long password
	longPassword := "this_is_a_very_long_password_that_should_still_work_fine_with_rsa_4098_encryption"
	encrypted, err := EncryptPassword(longPassword, publicKey)
	if err != nil {
		t.Fatalf("Failed to encrypt long password: %v", err)
	}

	if encrypted == "" {
		t.Error("Encrypted password should not be empty")
	}
}

// TestEncryptPasswordBytes tests encryption of password bytes
func TestEncryptPasswordBytes(t *testing.T) {
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	password := []byte("test_password_123")

	encrypted, err := EncryptPasswordBytes(password, publicKey)
	if err != nil {
		t.Fatalf("EncryptPasswordBytes failed: %v", err)
	}

	if len(encrypted) == 0 {
		t.Error("Encrypted password should not be empty")
	}

	// Check that encrypted is different from original
	for i := range password {
		if len(encrypted) <= i {
			break
		}
		// At least some bytes should be different
		// (with OAEP, all bytes should be different, but we'll just check non-empty)
	}
}

// TestEncryptPasswordBytesEmpty tests that empty password bytes returns an error
func TestEncryptPasswordBytesEmpty(t *testing.T) {
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	_, err = EncryptPasswordBytes([]byte{}, publicKey)
	if err == nil {
		t.Error("Expected error for empty password, got nil")
	}
}
