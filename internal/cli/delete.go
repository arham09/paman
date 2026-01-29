package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/arham09/paman/internal/db"
	"github.com/arham09/paman/pkg/config"
	"github.com/spf13/cobra"
)

// deleteCmd represents "paman delete <id>" command
// Deletes a credential permanently
var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a credential",
	Long: `Delete a credential by ID.
This action cannot be undone.`,
	Args: cobra.ExactArgs(1),
	RunE: runDelete,
}

// runDelete executes the delete command
func runDelete(cmd *cobra.Command, args []string) error {
	// Parse credential ID
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid credential ID: %w", err)
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

	// Delete credential
	err = db.DeleteCredential(database, id)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	fmt.Printf("✓ Credential ID %d deleted successfully\n", id)

	return nil
}
