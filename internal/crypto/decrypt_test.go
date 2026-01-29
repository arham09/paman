package crypto

import (
	"strings"

	"testing"
)

// TestDecryptPassword tests that password decryption works correctly
func TestDecryptPassword(t *testing.T) {
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

	// Decrypt the password
	decrypted, err := DecryptPassword(encrypted, privateKey)
	if err != nil {
		t.Fatalf("DecryptPassword failed: %v", err)
	}

	// Check that decrypted password matches original
	if decrypted != password {
		t.Errorf("Decrypted password doesn't match original. Got %s, want %s", decrypted, password)
	}
}

// TestDecryptPasswordEmpty tests that empty encrypted password returns an error
func TestDecryptPasswordEmpty(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	_, err = DecryptPassword("", privateKey)
	if err == nil {
		t.Error("Expected error for empty encrypted password")
	}
}

// TestDecryptPasswordInvalidBase64 tests that invalid Base64 returns an error
func TestDecryptPasswordInvalidBase64(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	invalidBase64 := "this_is_not_valid_base64!!!"

	_, err = DecryptPassword(invalidBase64, privateKey)
	if err == nil {
		t.Error("Expected error for invalid Base64 string")
	}
}

// TestDecryptPasswordBytes tests decryption of password bytes
func TestDecryptPasswordBytes(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	password := []byte("test_password_123")

	// Encrypt the password
	encrypted, err := EncryptPasswordBytes(password, publicKey)
	if err != nil {
		t.Fatalf("EncryptPasswordBytes failed: %v", err)
	}

	// Decrypt the password
	decrypted, err := DecryptPasswordBytes(encrypted, privateKey)
	if err != nil {
		t.Fatalf("DecryptPasswordBytes failed: %v", err)
	}

	// Check that decrypted password matches original
	if string(decrypted) != string(password) {
		t.Errorf("Decrypted password doesn't match original. Got %s, want %s", string(decrypted), string(password))
	}
}

// TestDecryptPasswordBytesEmpty tests that empty encrypted bytes returns an error
func TestDecryptPasswordBytesEmpty(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	_, err = DecryptPasswordBytes([]byte{}, privateKey)
	if err == nil {
		t.Error("Expected error for empty encrypted password bytes")
	}
}

// TestEncryptDecryptRoundTrip tests that encrypt-decrypt round trip works for various passwords
func TestEncryptDecryptRoundTrip(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	passwords := []string{
		"short",
		"password123",
		"P@ssw0rd!#$%",
		strings.Repeat("a", 100), // 100 character password
		"密码123",                  // Unicode password
		"emoji😀password",         // Emoji password
	}

	for _, password := range passwords {
		t.Run(password, func(t *testing.T) {
			// Encrypt
			encrypted, err := EncryptPassword(password, publicKey)
			if err != nil {
				t.Fatalf("EncryptPassword failed: %v", err)
			}

			// Decrypt
			decrypted, err := DecryptPassword(encrypted, privateKey)
			if err != nil {
				t.Fatalf("DecryptPassword failed: %v", err)
			}

			// Verify round trip
			if decrypted != password {
				t.Errorf("Round trip failed. Got %s, want %s", decrypted, password)
			}
		})
	}
}
