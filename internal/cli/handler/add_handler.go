// Package handler provides CLI command handlers for the paman application.
package handler

import (
	"fmt"

	"github.com/arham09/paman/internal/application/service"
)

// AddHandler handles the "paman add" command.
//
// Purpose: Orchestrates adding a new credential with encrypted password.
type AddHandler struct {
	credentialService *service.CredentialService
}

// NewAddHandler creates a new add handler.
//
// Purpose: Constructor that wires dependencies via dependency injection.
//
// Parameters:
//   - credentialService: Service for credential operations
//
// Returns:
//   - *AddHandler: Handler instance ready for use
func NewAddHandler(credentialService *service.CredentialService) *AddHandler {
	return &AddHandler{
		credentialService: credentialService,
	}
}

// Run executes the add credential workflow.
//
// Purpose: Use case for adding a new credential to the password manager.
// Encrypts the password and persists the credential.
//
// Parameters:
//   - title: Credential title/name (e.g., "GitHub", "Gmail")
//   - address: Optional URL/address (e.g., "https://github.com")
//   - username: User's email or username
//   - password: Plaintext password to encrypt
//
// Returns:
//   - int64: Auto-generated ID of the new credential
//   - error: Error if operation fails
//
// Workflow:
//   1. Validate input parameters
//   2. Call credentialService.AddCredential() which handles encryption and persistence
//   3. Return the new credential ID
func (h *AddHandler) Run(title, address, username, password string) (int64, error) {
	// Step 1: Validate input (basic validation)
	// The service layer will perform full validation
	if title == "" {
		return 0, fmt.Errorf("title is required")
	}
	if username == "" {
		return 0, fmt.Errorf("username is required")
	}
	if password == "" {
		return 0, fmt.Errorf("password is required")
	}

	// Step 2: Call application service to add credential
	// The service will:
	//   - Load the public key
	//   - Encrypt the password
	//   - Create and validate the credential entity
	//   - Persist to repository
	id, err := h.credentialService.AddCredential(title, address, username, password)
	if err != nil {
		return 0, fmt.Errorf("failed to add credential: %w", err)
	}

	// Step 3: Return the new credential ID
	return id, nil
}
