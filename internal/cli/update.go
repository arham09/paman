package cli

import (
	"fmt"
	"strconv"

	"github.com/arham09/paman/internal/cli/handler"
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

	// Services already initialized by root.PreRun
	h := handler.NewUpdateHandler(GetCredentialService())

	err = h.Run(id, updateTitle, updateAddress, updateUsername, updatePassword, privateKeyPath)
	if err != nil {
		return err
	}

	fmt.Println(h.FormatUpdateSummary(id, updateTitle, updateAddress, updateUsername, updatePassword != ""))
	return nil
}
