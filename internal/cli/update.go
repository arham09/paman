package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/arham09/paman/internal/crypto"
	"github.com/arham09/paman/internal/db"
	"github.com/arham09/paman/pkg/config"
	"github.com/spf13/cobra"
)

// Command flags for update command
var (
	updateTitle    string
	updateAddress  string
	updateUsername string
	updatePassword string
)

// updateCmd represents "paman update <id>" command
// Updates an existing credential
var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update a credential",
	Long: `Update an existing credential by ID.
Provide the fields you want to update using flags. Only provided fields will be updated.`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().StringVar(&updateTitle, "title", "", "New title")
	updateCmd.Flags().StringVar(&updateAddress, "address", "", "New address")
	updateCmd.Flags().StringVar(&updateUsername, "username", "", "New username")
	updateCmd.Flags().StringVar(&updatePassword, "password", "", "New password")
}

// runUpdate executes the update command
func runUpdate(cmd *cobra.Command, args []string) error {
	// Parse credential ID
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid credential ID: %w", err)
	}

	// Validate at least one field is provided
	if updateTitle == "" && updateAddress == "" && updateUsername == "" && updatePassword == "" {
		return fmt.Errorf("at least one field must be provided for update")
	}

	// Get paths
	publicKeyPath, err := config.GetPublicKeyPath()
	if err != nil {
		return fmt.Errorf("failed to get public key path: %w", err)
	}

	databasePath, err := config.GetDatabasePath()
	if err != nil {
		return fmt.Errorf("failed to get database path: %w", err)
	}

	// Verify initialization (only check public key)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("paman not initialized. Run 'paman init' first")
	}

	if _, err := os.Stat(databasePath); os.IsNotExist(err) {
		return fmt.Errorf("database not found. Run 'paman init' first")
	}

	// Open database
	database, err := db.OpenDatabase(databasePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	// Check if credential exists
	exists, err := db.CredentialExists(database, id)
	if err != nil {
		return fmt.Errorf("failed to check credential existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("credential with ID %d not found", id)
	}

	// Prepare update fields
	var titlePtr, addressPtr, usernamePtr, encryptedPasswordPtr *string

	if updateTitle != "" {
		titlePtr = &updateTitle
	}
	if updateAddress != "" {
		addressPtr = &updateAddress
	}
	if updateUsername != "" {
		usernamePtr = &updateUsername
	}
	if updatePassword != "" {
		// Load public key to encrypt new password
		publicKey, err := crypto.LoadPublicKey(publicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load public key: %w", err)
		}

		encrypted, err := crypto.EncryptPassword(updatePassword, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt password: %w", err)
		}
		encryptedPasswordPtr = &encrypted
	}

	// Update credential
	err = db.UpdateCredentialPartial(database, id, titlePtr, addressPtr, usernamePtr, encryptedPasswordPtr)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	fmt.Printf("✓ Credential ID %d updated successfully\n", id)

	return nil
}
