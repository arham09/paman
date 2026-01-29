package cli

import (
	"fmt"
	"os"

	"github.com/arham09/paman/internal/db"
	"github.com/arham09/paman/pkg/config"
	"github.com/spf13/cobra"
)

// listCmd represents "paman list" command
// Lists all credentials without showing passwords
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all credentials",
	Long: `List all stored credentials without showing passwords.
This command displays all credentials in a summarized format.`,
	RunE: runList,
}

// runList executes the list command
func runList(cmd *cobra.Command, args []string) error {
	// Get paths
	publicKeyPath, err := config.GetPublicKeyPath()
	if err != nil {
		return fmt.Errorf("failed to get public key path: %w", err)
	}

	databasePath, err := config.GetDatabasePath()
	if err != nil {
		return fmt.Errorf("failed to get database path: %w", err)
	}

	// Verify initialization (only check public key, private key is provided by user)
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

	// List credentials
	credentials, err := db.ListCredentials(database)
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	if len(credentials) == 0 {
		fmt.Println("No credentials found.")
		return nil
	}

	// Display credentials
	fmt.Printf("\nFound %d credential(s):\n\n", len(credentials))
	for _, cred := range credentials {
		display := cred.ToDisplay()
		fmt.Printf("ID: %d\n", display.ID)
		fmt.Printf("  Title: %s\n", display.Title)
		if display.Address != "" {
			fmt.Printf("  Address: %s\n", display.Address)
		}
		fmt.Printf("  Username: %s\n", display.Username)
		fmt.Printf("  Created: %s\n", display.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	return nil
}
