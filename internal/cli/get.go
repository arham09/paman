package cli

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strconv"

	"github.com/arham09/paman/internal/crypto"
	"github.com/arham09/paman/internal/db"
	"github.com/arham09/paman/internal/models"
	"github.com/arham09/paman/pkg/config"
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

	// Get file paths
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

	// Load private key if --show-password flag is used
	// NEW DESIGN: Private key comes from --private-key flag, not from ~/.paman/
	var privateKey *rsa.PrivateKey
	if showPassword {
		// Validate that --private-key flag was provided
		if privateKeyPath == "" {
			return fmt.Errorf("--private-key flag is required when using --show-password")
		}

		// Get passphrase to decrypt private key
		passphrase, err := getPassphrase()
		if err != nil {
			return err
		}

		// Load and decrypt private key from user-provided path
		privateKey, err = crypto.LoadPrivateKey(passphrase, privateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
	}

	// Open database
	database, err := db.OpenDatabase(databasePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	// Get credential from database
	credential, err := db.GetCredential(database, id)
	if err != nil {
		if err == models.ErrNotFound {
			return fmt.Errorf("credential with ID %d not found", id)
		}
		return fmt.Errorf("failed to get credential: %w", err)
	}

	// Display credential (with optional password decryption)
	displayCredential(credential, privateKey, showPassword)

	return nil
}

// displayCredential shows a credential with optional password decryption
func displayCredential(credential *models.Credential, privateKey *rsa.PrivateKey, showPassword bool) {
	fmt.Printf("\nID: %d\n", credential.ID)
	fmt.Printf("Title: %s\n", credential.Title)
	if credential.Address != "" {
		fmt.Printf("Address: %s\n", credential.Address)
	}
	fmt.Printf("Username: %s\n", credential.Username)
	fmt.Printf("Created: %s\n", credential.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated: %s\n", credential.UpdatedAt.Format("2006-01-02 15:04:05"))

	if showPassword {
		// Decrypt and display password
		password, err := crypto.DecryptPassword(string(credential.EncryptedPassword), privateKey)
		if err != nil {
			fmt.Printf("Password: [Failed to decrypt]\n")
		} else {
			fmt.Printf("Password: %s\n", password)
		}
	} else {
		fmt.Printf("Password: [Hidden - use --show-password to reveal]\n")
	}
	fmt.Println()
}
