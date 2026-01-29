package cli

import (
	"fmt"
	"os"

	"github.com/arham09/paman/internal/db"
	"github.com/arham09/paman/pkg/config"
	"github.com/spf13/cobra"
)

// searchCmd represents "paman search <query>" command
// Searches credentials using full-text search
var searchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search credentials",
	Long: `Search credentials by title, address, or username using full-text search.
This command performs a case-insensitive search across all credential fields.`,
	Args: cobra.ExactArgs(1),
	RunE: runSearch,
}

// runSearch executes the search command
func runSearch(cmd *cobra.Command, args []string) error {
	query := args[0]

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

	// Search credentials
	credentials, err := db.SearchCredentials(database, query)
	if err != nil {
		return fmt.Errorf("failed to search credentials: %w", err)
	}

	if len(credentials) == 0 {
		fmt.Printf("No credentials found matching '%s'.\n", query)
		return nil
	}

	// Display results
	fmt.Printf("\nFound %d credential(s) matching '%s':\n\n", len(credentials), query)
	for _, cred := range credentials {
		display := cred.ToDisplay()
		fmt.Printf("ID: %d\n", display.ID)
		fmt.Printf("  Title: %s\n", display.Title)
		if display.Address != "" {
			fmt.Printf("  Address: %s\n", display.Address)
		}
		fmt.Printf("  Username: %s\n", display.Username)
		fmt.Println()
	}

	return nil
}
