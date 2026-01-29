package cli

import (
	"fmt"
	"strconv"

	"github.com/arham09/paman/internal/cli/handler"
	"github.com/spf13/cobra"
)

// Flag for delete command
var forceDelete bool

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

func init() {
	deleteCmd.Flags().BoolVar(&forceDelete, "force", false, "Skip confirmation prompt")
}

// runDelete executes the delete command
func runDelete(cmd *cobra.Command, args []string) error {
	// Parse credential ID
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid credential ID: %w", err)
	}

	// Services already initialized by root.PreRun
	h := handler.NewDeleteHandler(GetCredentialService())

	err = h.Run(id, false, forceDelete)
	if err != nil {
		return err
	}

	fmt.Println(h.FormatSuccessMessage(id))
	return nil
}
