package cli

import (
	"fmt"

	"github.com/arham09/paman/internal/cli/handler"
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
	if len(args) == 0 {
		return fmt.Errorf("search query required")
	}
	query := args[0]

	// Services already initialized by root.PreRun
	h := handler.NewSearchHandler(GetCredentialService())
	return h.Run(query)
}
