package cli

import (
	"fmt"
	"strconv"

	"github.com/arham09/paman/internal/cli/handler"
	"github.com/spf13/cobra"
)

// Flag for the get command
var showPassword bool

// getCmd represents "paman get <id>" command
// Retrieves and displays a credential, optionally decrypting the password
var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get a credential by ID",
	Long: `Retrieve a credential by its ID.
Use the --show-password flag to display the decrypted password.`,
	Args: cobra.ExactArgs(1),
	RunE: runGet,
}

func init() {
	getCmd.Flags().BoolVar(&showPassword, "show-password", false, "Show the decrypted password")
}

// runGet executes the get command
func runGet(cmd *cobra.Command, args []string) error {
	// Parse credential ID from argument
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid credential ID: %w", err)
	}

	// Services already initialized by root.PreRun
	h := handler.NewGetHandler(GetCredentialService())

	// Get passphrase if --show-password is used
	var passphrase string
	if showPassword {
		if privateKeyPath == "" {
			return fmt.Errorf("--private-key flag is required when using --show-password")
		}
		// Prompt for passphrase using utils.getPassphrase()
		passphrase, err = getPassphrase()
		if err != nil {
			return err
		}
	}

	// Get credential data
	data, err := h.Run(id, showPassword, privateKeyPath, passphrase)
	if err != nil {
		return err
	}

	// Display formatted output
	fmt.Println(data.Format())
	return nil
}
