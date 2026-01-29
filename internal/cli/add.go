package cli

import (
	"fmt"
	"os"

	"github.com/arham09/paman/internal/crypto"
	"github.com/arham09/paman/internal/db"
	"github.com/arham09/paman/pkg/config"
	"github.com/spf13/cobra"
)

// Command flag variables for the add command
var (
	title    string
	address  string
	username string
	password string
)

// addCmd represents the "paman add" command
//
// Purpose: Adds a new credential to the password manager.
// The password is encrypted with the public key before storage.
//
// Usage:
//
//	paman add --title "GitHub" --username "user@example.com" --password "secret123"
//	paman add --title "Gmail" --address "https://gmail.com" --username "user@gmail.com" --password "pass"
//
// Required Flags:
//
//	--title: Credential name
//	--username: Email/username
//	--password: Password to encrypt
//
// Optional Flags:
//
//	--address: URL of the service
//
// Security:
//   - Password is encrypted with RSA-4096-OAEP before storage
//   - Only the public key is needed for encryption
//   - Encrypted password is Base64-encoded for database storage
//   - Password never touches disk in plaintext form
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new credential",
	Long: `Add a new credential to the password manager.
You can provide the credential details via flags or interactive prompts.`,
	RunE: runAdd,
}

// init() registers command flags with cobra
func init() {
	// Define all flags for the add command
	addCmd.Flags().StringVar(&title, "title", "", "Title/Name of the credential (required)")
	addCmd.Flags().StringVar(&address, "address", "", "Address/URL of the service")
	addCmd.Flags().StringVar(&username, "username", "", "Username/Email (required)")
	addCmd.Flags().StringVar(&password, "password", "", "Password (required)")

	// Mark required flags
	addCmd.MarkFlagRequired("title")
	addCmd.MarkFlagRequired("username")
	addCmd.MarkFlagRequired("password")
}

// runAdd executes the add command
func runAdd(cmd *cobra.Command, args []string) error {
	// Step 1: Get file paths from config package
	// Public key: ~/.paman/public_key.pem (used for encryption)
	// Database: ~/.paman/credentials.db (stores encrypted credentials)
	publicKeyPath, err := config.GetPublicKeyPath()
	if err != nil {
		return fmt.Errorf("failed to get public key path: %w", err)
	}

	databasePath, err := config.GetDatabasePath()
	if err != nil {
		return fmt.Errorf("failed to get database path: %w", err)
	}

	// Step 2: Verify initialization (only check public key, private key is user-provided)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("paman not initialized. Run 'paman init' first")
	}

	if _, err := os.Stat(databasePath); os.IsNotExist(err) {
		return fmt.Errorf("database not found. Run 'paman init' first")
	}

	// Step 3: Load the public key
	// Public key is used to encrypt the password
	// Private key is NOT needed for encryption (only for decryption)
	publicKey, err := crypto.LoadPublicKey(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	// Step 4: Encrypt the password
	// RSA-OAEP encryption with the public key
	// Only someone with the private key can decrypt
	// Encrypted password is Base64-encoded for database storage
	encryptedPassword, err := crypto.EncryptPassword(password, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}

	// Step 5: Open database connection
	database, err := db.OpenDatabase(databasePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	// Ensure database is closed when function exits
	defer database.Close()

	// Step 6: Insert the encrypted credential into database
	// Returns the auto-generated ID of the new credential
	id, err := db.CreateCredential(database, title, address, username, encryptedPassword)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	// Step 7: Display success message
	// Shows the ID for future reference (get, update, delete)
	fmt.Printf("✓ Credential added successfully with ID: %d\n", id)
	fmt.Printf("  Title: %s\n", title)
	fmt.Printf("  Username: %s\n", username)

	return nil
}
