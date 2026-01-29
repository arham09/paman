package cli

import (
	"github.com/arham09/paman/internal/cli/handler"
	"github.com/arham09/paman/internal/infrastructure/config"
	"github.com/arham09/paman/internal/infrastructure/security"
	"github.com/arham09/paman/internal/application/service"
	"github.com/spf13/cobra"
)

// initCmd represents the "paman init" command.
//
// NEW DESIGN: Private key is printed to stdout, NOT saved to disk.
// Public key is saved to ~/.paman/public_key.pem for encryption.
//
// Purpose: Initializes paman for first-time use by:
//  1. Creating the config directory (~/.paman/)
//  2. Generating RSA-4096 key pair
//  3. Saving public key to ~/.paman/public_key.pem
//  4. Printing private key to stdout (user saves manually)
//  5. Creating the encrypted database
//
// This command must be run before any other paman commands can be used.
//
// User Flow:
//  1. Run "paman init"
//  2. Enter passphrase (min 12 characters)
//  3. Confirm passphrase (must match)
//  4. Keys generated
//  5. Private key printed to stdout (SAVE THIS SECURELY!)
//  6. Public key saved to ~/.paman/public_key.pem
//  7. Database created
//
// Security:
//   - Private key never touches ~/.paman/ directory
//   - User stores private key elsewhere (USB drive, encrypted volume, etc.)
//   - Private key is provided via --private-key flag for all operations
//   - Public key is not encrypted (doesn't need to be)
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize paman (generate keys and create database)",
	Long: `Initialize paman by generating RSA keys and creating the encrypted database.
The public key will be saved to ~/.paman/public_key.pem.
The private key will be printed to stdout - SAVE IT SECURELY!`,
	RunE: runInit,
}

// runInit executes the init command.
//
// This is the main function that performs all initialization steps.
// It orchestrates the entire setup process with proper error handling and cleanup.
//
// Error Handling:
//   - If any step fails, partial setup is cleaned up
//   - User can re-run init without manual cleanup
//   - Clear error messages guide the user
//
// Security Considerations:
//   - Private key is printed to stdout (not stored in ~/.paman/)
//   - Public key is saved to ~/.paman/public_key.pem
//   - File permissions are set correctly (0600 for sensitive files)
func runInit(cmd *cobra.Command, args []string) error {
	// Create fresh services for init (don't use globals)
	configService := config.NewFilesystemConfig()
	cryptoService := security.NewRSACryptoService()
	initService := service.NewInitializationService(cryptoService, configService)

	// Create handler with initialization service
	h := handler.NewInitHandler(initService, nil, configService)

	// Execute initialization
	return h.Run("")
}
