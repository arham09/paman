package cli

import (
	"github.com/arham09/paman/internal/cli/handler"
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
	// Services already initialized by root.PreRun
	h := handler.NewListHandler(GetCredentialService())
	return h.Run()
}
