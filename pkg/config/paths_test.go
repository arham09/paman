package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGetConfigDir tests that GetConfigDir returns the correct path
func TestGetConfigDir(t *testing.T) {
	configDir, err := GetConfigDir()
	if err != nil {
		t.Fatalf("GetConfigDir failed: %v", err)
	}

	// Should end with .paman
	if filepath.Base(configDir) != ".paman" {
		t.Errorf("Expected config dir to end with .paman, got %s", filepath.Base(configDir))
	}

	// Should be under home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home dir: %v", err)
	}

	expectedDir := filepath.Join(homeDir, ".paman")
	if configDir != expectedDir {
		t.Errorf("Expected %s, got %s", expectedDir, configDir)
	}
}

// TestGetPrivateKeyPath tests that the private key path is correct
func TestGetPrivateKeyPath(t *testing.T) {
	path, err := GetPrivateKeyPath()
	if err != nil {
		t.Fatalf("GetPrivateKeyPath failed: %v", err)
	}

	// Should be .paman/private_key.pem
	if filepath.Base(path) != "private_key.pem" {
		t.Errorf("Expected private_key.pem, got %s", filepath.Base(path))
	}

	// Should be under .paman directory
	configDir, err := GetConfigDir()
	if err != nil {
		t.Fatalf("GetConfigDir failed: %v", err)
	}

	expectedPath := filepath.Join(configDir, "private_key.pem")
	if path != expectedPath {
		t.Errorf("Expected %s, got %s", expectedPath, path)
	}
}

// TestGetPublicKeyPath tests that the public key path is correct
func TestGetPublicKeyPath(t *testing.T) {
	path, err := GetPublicKeyPath()
	if err != nil {
		t.Fatalf("GetPublicKeyPath failed: %v", err)
	}

	// Should be .paman/public_key.pem
	if filepath.Base(path) != "public_key.pem" {
		t.Errorf("Expected public_key.pem, got %s", filepath.Base(path))
	}

	// Should be under .paman directory
	configDir, err := GetConfigDir()
	if err != nil {
		t.Fatalf("GetConfigDir failed: %v", err)
	}

	expectedPath := filepath.Join(configDir, "public_key.pem")
	if path != expectedPath {
		t.Errorf("Expected %s, got %s", expectedPath, path)
	}
}

// TestGetDatabasePath tests that the database path is correct
func TestGetDatabasePath(t *testing.T) {
	path, err := GetDatabasePath()
	if err != nil {
		t.Fatalf("GetDatabasePath failed: %v", err)
	}

	// Should be .paman/credentials.db
	if filepath.Base(path) != "credentials.db" {
		t.Errorf("Expected credentials.db, got %s", filepath.Base(path))
	}

	// Should be under .paman directory
	configDir, err := GetConfigDir()
	if err != nil {
		t.Fatalf("GetConfigDir failed: %v", err)
	}

	expectedPath := filepath.Join(configDir, "credentials.db")
	if path != expectedPath {
		t.Errorf("Expected %s, got %s", expectedPath, path)
	}
}

// TestEnsureConfigDir tests that EnsureConfigDir creates the directory
func TestEnsureConfigDir(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "paman-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Change the config directory to use temp dir for this test
	// We'll need to modify the function or test differently
	// For now, just test that the function doesn't error
	configDir, err := EnsureConfigDir()
	if err != nil {
		t.Fatalf("EnsureConfigDir failed: %v", err)
	}

	// Check that configDir exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		t.Errorf("Config directory was not created: %s", configDir)
	}
}
