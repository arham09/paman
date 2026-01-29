package db

import (
	"os"
	"testing"
)

// TestCreateDatabase tests database creation
func TestCreateDatabase(t *testing.T) {
	// Create a temporary database file
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	// Create database
	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Check that database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}

	// Verify database is connected
	if err := database.Ping(); err != nil {
		t.Errorf("Database is not connected: %v", err)
	}
}

// TestCreateDatabasePermissions tests that database has correct permissions (0600)
func TestCreateDatabasePermissions(t *testing.T) {
	// Create a temporary database file
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	// Create database
	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Check file permissions
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Failed to stat database: %v", err)
	}

	// Check Unix permissions (0600 = rw-------)
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Database should have 0600 permissions, got %04o", mode)
	}
}

// TestCreateDatabaseAlreadyExists tests error when database already exists
func TestCreateDatabaseAlreadyExists(t *testing.T) {
	// Create a temporary database file
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()

	// Try to create database that already exists
	_, err = CreateDatabase(dbPath)
	if err == nil {
		t.Error("Expected error when creating database that already exists")
	}

	os.Remove(dbPath)
}

// TestOpenDatabase tests opening an existing database
func TestOpenDatabase(t *testing.T) {
	// Create a temporary database file
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	// Create database first
	createdDB, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	createdDB.Close()

	// Now open it
	openedDB, err := OpenDatabase(dbPath)
	if err != nil {
		t.Fatalf("OpenDatabase failed: %v", err)
	}
	defer openedDB.Close()
	defer os.Remove(dbPath)

	// Verify connection
	if err := openedDB.Ping(); err != nil {
		t.Errorf("Opened database is not connected: %v", err)
	}
}

// TestOpenDatabaseNotExists tests error when database doesn't exist
func TestOpenDatabaseNotExists(t *testing.T) {
	nonExistentPath := "/tmp/nonexistent_paman_test_12345.db"

	_, err := OpenDatabase(nonExistentPath)
	if err == nil {
		t.Error("Expected error when opening non-existent database")
	}
}

// TestCredentialCRUD tests Create, Get, Update, Delete operations
func TestCredentialCRUD(t *testing.T) {
	// Create temporary database
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Test Create
	title := "Test Service"
	address := "https://test.com"
	username := "user@test.com"
	encryptedPassword := "encrypted_data_here"

	id, err := CreateCredential(database, title, address, username, encryptedPassword)
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	if id == 0 {
		t.Error("Expected non-zero credential ID")
	}

	// Test Get
	cred, err := GetCredential(database, int(id))
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}

	if cred.Title != title {
		t.Errorf("Expected title %s, got %s", title, cred.Title)
	}

	if cred.Username != username {
		t.Errorf("Expected username %s, got %s", username, cred.Username)
	}

	// Test Update
	newTitle := "Updated Service"
	newAddress := "https://updated.com"
	newUsername := "updated@test.com"
	newEncryptedPassword := "new_encrypted_data"

	err = UpdateCredential(database, int(id), newTitle, newAddress, newUsername, newEncryptedPassword)
	if err != nil {
		t.Fatalf("UpdateCredential failed: %v", err)
	}

	// Verify update
	updatedCred, err := GetCredential(database, int(id))
	if err != nil {
		t.Fatalf("GetCredential after update failed: %v", err)
	}

	if updatedCred.Title != newTitle {
		t.Errorf("Expected updated title %s, got %s", newTitle, updatedCred.Title)
	}

	// Test Delete
	err = DeleteCredential(database, int(id))
	if err != nil {
		t.Fatalf("DeleteCredential failed: %v", err)
	}

	// Verify deletion
	_, err = GetCredential(database, int(id))
	if err == nil {
		t.Error("Expected error when getting deleted credential")
	}
}

// TestCredentialExists tests checking if a credential exists
func TestCredentialExists(t *testing.T) {
	// Create temporary database
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Create a credential
	title := "Test Service"
	username := "user@test.com"
	encryptedPassword := "encrypted_data"

	id, err := CreateCredential(database, title, "", username, encryptedPassword)
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// Test that credential exists
	exists, err := CredentialExists(database, int(id))
	if err != nil {
		t.Fatalf("CredentialExists failed: %v", err)
	}

	if !exists {
		t.Error("Expected credential to exist")
	}

	// Test that non-existent credential doesn't exist
	exists, err = CredentialExists(database, 9999)
	if err != nil {
		t.Fatalf("CredentialExists for non-existent ID failed: %v", err)
	}

	if exists {
		t.Error("Expected non-existent credential to not exist")
	}
}

// TestListCredentials tests listing all credentials
func TestListCredentials(t *testing.T) {
	// Create temporary database
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Create multiple credentials
	_, err = CreateCredential(database, "Service A", "", "userA@test.com", "encryptedA")
	if err != nil {
		t.Fatalf("CreateCredential 1 failed: %v", err)
	}

	_, err = CreateCredential(database, "Service B", "", "userB@test.com", "encryptedB")
	if err != nil {
		t.Fatalf("CreateCredential 2 failed: %v", err)
	}

	// List credentials
	credentials, err := ListCredentials(database)
	if err != nil {
		t.Fatalf("ListCredentials failed: %v", err)
	}

	if len(credentials) != 2 {
		t.Errorf("Expected 2 credentials, got %d", len(credentials))
	}
}

// TestUpdateCredentialPartial tests partial updates
func TestUpdateCredentialPartial(t *testing.T) {
	// Create temporary database
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Create a credential
	id, err := CreateCredential(database, "Original Title", "https://original.com", "user@test.com", "encrypted")
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// Update only the title
	newTitle := "Updated Title"
	err = UpdateCredentialPartial(database, int(id), &newTitle, nil, nil, nil)
	if err != nil {
		t.Fatalf("UpdateCredentialPartial failed: %v", err)
	}

	// Verify only title was updated
	cred, err := GetCredential(database, int(id))
	if err != nil {
		t.Fatalf("GetCredential failed: %v", err)
	}

	if cred.Title != newTitle {
		t.Errorf("Expected title %s, got %s", newTitle, cred.Title)
	}

	if cred.Address != "https://original.com" {
		t.Error("Address should not have been updated")
	}

	if cred.Username != "user@test.com" {
		t.Error("Username should not have been updated")
	}
}

// TestDeleteCredential tests deleting a credential
func TestDeleteCredential(t *testing.T) {
	// Create temporary database
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Create a credential
	id, err := CreateCredential(database, "Test", "", "user@test.com", "encrypted")
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// Verify it exists
	exists, err := CredentialExists(database, int(id))
	if err != nil {
		t.Fatalf("CredentialExists failed: %v", err)
	}

	if !exists {
		t.Fatal("Credential should exist before deletion")
	}

	// Delete it
	err = DeleteCredential(database, int(id))
	if err != nil {
		t.Fatalf("DeleteCredential failed: %v", err)
	}

	// Verify it's gone
	exists, err = CredentialExists(database, int(id))
	if err != nil {
		t.Fatalf("CredentialExists after delete failed: %v", err)
	}

	if exists {
		t.Error("Credential should not exist after deletion")
	}
}

// TestSearchCredentials tests full-text search
func TestSearchCredentials(t *testing.T) {
	// Create temporary database
	tempDB, err := os.CreateTemp("", "credentials_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	dbPath := tempDB.Name()
	tempDB.Close()
	os.Remove(dbPath)

	database, err := CreateDatabase(dbPath)
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	defer database.Close()
	defer os.Remove(dbPath)

	// Create credentials with searchable terms
	_, err = CreateCredential(database, "GitHub Account", "https://github.com", "githubuser@test.com", "encrypted1")
	if err != nil {
		t.Fatalf("CreateCredential 1 failed: %v", err)
	}

	_, err = CreateCredential(database, "Gmail Account", "https://gmail.com", "gmailuser@test.com", "encrypted2")
	if err != nil {
		t.Fatalf("CreateCredential 2 failed: %v", err)
	}

	_, err = CreateCredential(database, "Work Email", "https://work-mail.com", "workuser@work.com", "encrypted3")
	if err != nil {
		t.Fatalf("CreateCredential 3 failed: %v", err)
	}

	// Search for "github"
	results, err := SearchCredentials(database, "github")
	if err != nil {
		t.Fatalf("SearchCredentials failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected to find results for 'github' search")
	}

	// Verify the result
	found := false
	for _, result := range results {
		if result.Title == "GitHub Account" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find 'GitHub Account' in search results")
	}
}
