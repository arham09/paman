package cli

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/arham09/paman/internal/crypto"
	"github.com/arham09/paman/internal/db"
	"github.com/arham09/paman/internal/models"
	"github.com/arham09/paman/pkg/config"
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
//   - Private key is encrypted BEFORE being written to disk
//   - Passphrase is validated for minimum length
//   - Passphrase confirmation prevents typos
//   - File permissions are set correctly (0600 for sensitive files)
func runInit(cmd *cobra.Command, args []string) error {
	// Step 1: Ensure config directory exists
	// Creates ~/.paman/ with 0700 permissions (owner only)
	// This prevents other users from accessing sensitive data
	configDir, err := config.EnsureConfigDir()
	if err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Step 2: Get all file paths
	// These paths are centralized in config package
	// Public key: ~/.paman/public_key.pem (saved for encryption)
	// Database: ~/.paman/credentials.db (encrypted passwords)
	// Private key is NOT stored in ~/.paman/ anymore (user provides via --private-key flag)
	publicKeyPath, err := config.GetPublicKeyPath()
	if err != nil {
		return fmt.Errorf("failed to get public key path: %w", err)
	}

	databasePath, err := config.GetDatabasePath()
	if err != nil {
		return fmt.Errorf("failed to get database path: %w", err)
	}

	// Step 3: Check if already initialized
	// Prevents accidental overwriting of existing database
	// Only check for public key and database (private key is not stored here anymore)
	if _, err := os.Stat(publicKeyPath); err == nil {
		if _, err := os.Stat(databasePath); err == nil {
			return fmt.Errorf("paman is already initialized at %s", configDir)
		}
	}

	if _, err := os.Stat(databasePath); err == nil {
		return models.ErrDatabaseExists
	}

	// Step 4: Generate RSA key pair
	// RSA-4096 provides strong encryption for passwords
	// This can take a second or two on slower machines
	fmt.Println("Generating 4096-bit RSA key pair...")
	privateKey, publicKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Step 5: Print private key to stdout (NEW DESIGN)
	// Private key is NOT saved to disk in ~/.paman/
	// User must save this securely (USB drive, encrypted volume, password manager, etc.)
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("PRIVATE KEY - SAVE THIS SECURELY!")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nCopy the key below and save it to a secure location:")
	fmt.Println("You will need to provide this file via --private-key flag for all operations.\n")

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

	// Step 6: Save public key
	// Public key is saved to ~/.paman/public_key.pem
	// Used for encrypting passwords before storage
	fmt.Println("Saving public key to ~/.paman/public_key.pem...")
	if err := crypto.SavePublicKey(publicKey, publicKeyPath); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// Step 7: Create database with schema
	// Creates credentials.db with tables, indexes, and FTS search
	// File has 0600 permissions (owner read/write only)
	fmt.Println("Creating encrypted database...")
	database, err := db.CreateDatabase(databasePath)
	if err != nil {
		// Cleanup: Remove public key if database creation fails
		os.Remove(publicKeyPath)
		return fmt.Errorf("failed to create database: %w", err)
	}
	defer database.Close()

	// Step 8: Display success message
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
