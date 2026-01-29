package models

import (
	"testing"
	"time"
)

// TestCredentialToDisplay tests that ToDisplay correctly converts a Credential to CredentialDisplay
func TestCredentialToDisplay(t *testing.T) {
	cred := &Credential{
		ID:                1,
		Title:             "GitHub",
		Address:           "https://github.com",
		Username:          "user@example.com",
		EncryptedPassword: []byte("encrypted_data"),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	display := cred.ToDisplay()

	// Check that all fields are copied correctly
	if display.ID != cred.ID {
		t.Errorf("Expected ID %d, got %d", cred.ID, display.ID)
	}

	if display.Title != cred.Title {
		t.Errorf("Expected Title %s, got %s", cred.Title, display.Title)
	}

	if display.Address != cred.Address {
		t.Errorf("Expected Address %s, got %s", cred.Address, display.Address)
	}

	if display.Username != cred.Username {
		t.Errorf("Expected Username %s, got %s", cred.Username, display.Username)
	}

	// The key check: encrypted password should NOT be in the display
	// This is verified by the struct definition (no EncryptedPassword field)
}

// TestCredentialDisplay tests CredentialDisplay struct
func TestCredentialDisplay(t *testing.T) {
	display := CredentialDisplay{
		ID:        1,
		Title:     "Test",
		Address:   "https://test.com",
		Username:  "user@test.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Verify all fields are set
	if display.ID == 0 {
		t.Error("ID should not be zero")
	}

	if display.Title == "" {
		t.Error("Title should not be empty")
	}

	if display.Username == "" {
		t.Error("Username should not be empty")
	}
}

// TestCredentialStructFields tests that Credential has all required fields
func TestCredentialStructFields(t *testing.T) {
	cred := Credential{
		ID:                1,
		Title:             "Test",
		Username:          "user@test.com",
		EncryptedPassword: []byte("encrypted"),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	// Verify fields
	if cred.ID != 1 {
		t.Errorf("Expected ID 1, got %d", cred.ID)
	}

	if cred.Title != "Test" {
		t.Errorf("Expected Title 'Test', got %s", cred.Title)
	}

	if len(cred.EncryptedPassword) == 0 {
		t.Error("EncryptedPassword should not be empty")
	}
}

// TestErrorsAreNotNil tests that all error variables are defined
func TestErrorsAreNotNil(t *testing.T) {
	errors := []error{
		ErrNotFound,
		ErrInvalidPassphrase,
		ErrPassphraseTooWeak,
		ErrKeysExist,
		ErrKeysNotFound,
		ErrDatabaseExists,
		ErrDatabaseNotFound,
		ErrTooManyAttempts,
		ErrInvalidInput,
		ErrEncryptionFailed,
		ErrDecryptionFailed,
	}

	for i, err := range errors {
		if err == nil {
			t.Errorf("Error %d should not be nil", i)
		}
	}
}

// TestErrorMessages tests that error messages are not empty
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrNotFound", ErrNotFound, "credential not found"},
		{"ErrInvalidPassphrase", ErrInvalidPassphrase, "invalid passphrase"},
		{"ErrPassphraseTooWeak", ErrPassphraseTooWeak, "12 characters"},
		{"ErrKeysExist", ErrKeysExist, "already exist"},
		{"ErrKeysNotFound", ErrKeysNotFound, "not found"},
		{"ErrDatabaseExists", ErrDatabaseExists, "already exists"},
		{"ErrDatabaseNotFound", ErrDatabaseNotFound, "not found"},
		{"ErrTooManyAttempts", ErrTooManyAttempts, "too many failed"},
		{"ErrInvalidInput", ErrInvalidInput, "invalid input"},
		{"ErrEncryptionFailed", ErrEncryptionFailed, "encryption failed"},
		{"ErrDecryptionFailed", ErrDecryptionFailed, "decryption failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("Error should not be nil")
			}
			if tt.err.Error() == "" {
				t.Error("Error message should not be empty")
			}
		})
	}
}
