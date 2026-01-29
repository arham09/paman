package cli

import (
	"fmt"

	"github.com/arham09/paman/internal/cli/handler"
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
	// Services already initialized by root.PreRun
	h := handler.NewAddHandler(GetCredentialService())

	id, err := h.Run(title, address, username, password)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Credential added successfully with ID: %d\n", id)
	fmt.Printf("  Title: %s\n", title)
	fmt.Printf("  Username: %s\n", username)

	return nil
}
