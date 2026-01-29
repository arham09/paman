// Package handler provides CLI command handlers for the paman application.
// Each handler bridges a Cobra command with the application services.
//
// Purpose: Handlers are responsible for:
//   - Accepting command-line flags and user input
//   - Calling application services
//   - Formatting and displaying results
//   - Handling errors appropriately for CLI context
package handler

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/arham09/paman/internal/application/service"
	"github.com/arham09/paman/internal/infrastructure/config"
	"github.com/arham09/paman/internal/infrastructure/persistence/sqlite"
)

// InitHandler handles the "paman init" command.
//
// Purpose: Orchestrates the initialization workflow by calling the initialization service.
// This handler is responsible for user-facing output and error handling.
type InitHandler struct {
	initializationService *service.InitializationService
	credentialService     *service.CredentialService
	configService         *config.FilesystemConfig
}

// NewInitHandler creates a new init handler.
//
// Purpose: Constructor that wires dependencies via dependency injection.
//
// Parameters:
//   - initializationService: Service for key generation and initialization
//   - credentialService: Service for credential operations (used for database setup)
//   - configService: Service for path resolution
//
// Returns:
//   - *InitHandler: Handler instance ready for use
func NewInitHandler(
	initializationService *service.InitializationService,
	credentialService *service.CredentialService,
	configService *config.FilesystemConfig,
) *InitHandler {
	return &InitHandler{
		initializationService: initializationService,
		credentialService:     credentialService,
		configService:         configService,
	}
}

// Run executes the initialization workflow.
//
// Purpose: Use case for initializing paman for the first time.
// Generates keys, creates database, and displays setup information.
//
// Parameters:
//   - passphrase: User's passphrase (currently unused, reserved for future encryption)
//
// Returns:
//   - error: Error if initialization fails
//
// Workflow:
//   1. Check if already initialized
//   2. Generate RSA key pair
//   3. Print private key to stdout (user must save it)
//   4. Save public key to disk
//   5. Create database
//   6. Display success message
//
// Security:
//   - Private key is printed to stdout, NOT stored in ~/.paman/
//   - User must manually save the private key
//   - Private key is provided via --private-key flag for decryption operations
func (h *InitHandler) Run(passphrase string) error {
	// Step 1: Get paths
	configDir, err := h.configService.EnsureConfigDir()
	if err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	publicKeyPath, err := h.configService.GetPublicKeyPath()
	if err != nil {
		return fmt.Errorf("failed to get public key path: %w", err)
	}

	databasePath, err := h.configService.GetDatabasePath()
	if err != nil {
		return fmt.Errorf("failed to get database path: %w", err)
	}

	// Step 2: Check if already initialized
	// We check for both public key and database
	if _, err := os.Stat(publicKeyPath); err == nil {
		if _, err := os.Stat(databasePath); err == nil {
			return fmt.Errorf("paman is already initialized at %s", configDir)
		}
	}

	if _, err := os.Stat(databasePath); err == nil {
		return fmt.Errorf("database already exists at %s", databasePath)
	}

	// Step 3: Generate RSA key pair
	fmt.Println("Generating 4096-bit RSA key pair...")
	generatedKeys, err := h.initializationService.Initialize(passphrase)
	if err != nil {
		return err
	}

	privateKey := generatedKeys.PrivateKey.(*rsa.PrivateKey)
	_ = generatedKeys.PublicKey // Public key already saved by Initialize()

	// Step 4: Print private key to stdout (NEW DESIGN)
	// Private key is NOT saved to disk in ~/.paman/
	// User must save this securely (USB drive, encrypted volume, password manager, etc.)
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("PRIVATE KEY - SAVE THIS SECURELY!")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nCopy the key below and save it to a secure location:")
	fmt.Println("You will need to provide this file via --private-key flag for all operations.")

	// Encode private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Print private key to stdout
	if err := pem.Encode(os.Stdout, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("IMPORTANT: Keep this private key secure and never share it!")
	fmt.Println(strings.Repeat("=", 70) + "\n")

	// Step 5: Public key is already saved by initializationService.Initialize()
	fmt.Println("Saving public key to ~/.paman/public_key.pem...")

	// Step 6: Create database with schema
	fmt.Println("Creating encrypted database...")
	database, err := sqlite.CreateDatabase(databasePath)
	if err != nil {
		// Cleanup: Remove public key if database creation fails
		os.Remove(publicKeyPath)
		return fmt.Errorf("failed to create database: %w", err)
	}
	defer database.Close()

	// Step 7: Display success message
	fmt.Printf("\n✓ paman initialized successfully!\n")
	fmt.Printf("  Config directory: %s\n", configDir)
	fmt.Printf("  Public key: %s\n", publicKeyPath)
	fmt.Printf("  Database: %s\n", databasePath)

	// Remind user about security
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("SETUP COMPLETE!")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\n⚠️  CRITICAL SECURITY INFORMATION:")
	fmt.Println("  1. Your PRIVATE KEY was printed above - save it securely!")
	fmt.Println("     Store it on a USB drive, encrypted volume, or password manager.")
	fmt.Println()
	fmt.Println("  2. Use the --private-key flag for all operations:")
	fmt.Println("     paman --private-key /path/to/private_key.pem list")
	fmt.Println("     paman --private-key /path/to/private_key.pem add --title 'GitHub' ...")
	fmt.Println()
	fmt.Println("  3. NEVER share your private key with anyone!")
	fmt.Println("  4. Back up your ~/.paman directory regularly.")
	fmt.Println(strings.Repeat("=", 70) + "\n")

	return nil
}
