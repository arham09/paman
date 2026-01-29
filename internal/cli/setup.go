// Package cli provides dependency injection setup for the paman CLI.
// This file acts as the composition root - the single place where all
// dependencies are wired together.
//
// Purpose: Centralizes dependency injection logic.
// This is the "composition root" pattern from clean architecture.
//
// Design:
//   - Creates all adapters (infrastructure layer)
//   - Creates application services (depends on ports)
//   - Returns initialized services for use by handlers
//
// Benefits:
//   - Single place to see the entire dependency graph
//   - Easy to swap implementations
//   - Explicit wiring (no magic containers)
package cli

import (
	"database/sql"

	"github.com/arham09/paman/internal/application/service"
	"github.com/arham09/paman/internal/infrastructure/config"
	"github.com/arham09/paman/internal/infrastructure/persistence/sqlite"
	"github.com/arham09/paman/internal/infrastructure/security"
)

// Global services (initialized at startup)
// These are set by the init() function and used by command handlers
var (
	credentialService    *service.CredentialService
	initializationService *service.InitializationService
)

// InitializeServices sets up all application services with their dependencies.
//
// Purpose: Composition root - wires all dependencies together.
// This function should be called once at application startup.
//
// Parameters:
//   - dbPath: Path to SQLite database (optional, if empty uses config service)
//
// Returns:
//   - error: Error if initialization fails
//
// Workflow:
//   1. Create infrastructure adapters
//   2. Create application services (depends on adapters)
//   3. Store services in global variables for CLI handlers to use
//
// Note: Database connection is not opened here - it's opened per-command
// to allow commands to work with different database paths.
func InitializeServices(dbPath string) error {
	// Step 1: Create infrastructure adapters

	// Config service - provides paths and directory management
	configService := config.NewFilesystemConfig()

	// Crypto service - provides encryption/decryption
	cryptoService := security.NewRSACryptoService()

	// Open database connection
	var db *sql.DB
	var err error

	if dbPath == "" {
		// Use default database path from config
		dbPath, err = configService.GetDatabasePath()
		if err != nil {
			return err
		}
	}

	db, err = sqlite.OpenDatabase(dbPath)
	if err != nil {
		return err
	}

	// Repository - persists credentials
	// Depends on database connection
	repository := sqlite.NewSQLiteCredentialRepository(db)

	// Step 2: Create application services (depend on ports)

	// Credential service - orchestrates credential operations
	credentialService = service.NewCredentialService(repository, cryptoService, configService)

	// Initialization service - orchestrates initialization
	initializationService = service.NewInitializationService(cryptoService, configService)

	return nil
}

// GetCredentialService returns the credential service instance.
//
// Purpose: Getter for CLI handlers to access the service.
func GetCredentialService() *service.CredentialService {
	return credentialService
}

// GetInitializationService returns the initialization service instance.
//
// Purpose: Getter for CLI handlers to access the service.
func GetInitializationService() *service.InitializationService {
	return initializationService
}
