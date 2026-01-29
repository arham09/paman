// Package handler provides CLI command handlers for the paman application.
package handler

import (
	"fmt"
	"strings"
	"time"

	"github.com/arham09/paman/internal/application/service"
	"github.com/arham09/paman/internal/domain/entity"
)

// GetHandler handles the "paman get" command.
//
// Purpose: Orchestrates retrieving a credential by ID, optionally decrypting the password.
type GetHandler struct {
	credentialService *service.CredentialService
}

// NewGetHandler creates a new get handler.
//
// Purpose: Constructor that wires dependencies via dependency injection.
//
// Parameters:
//   - credentialService: Service for credential operations
//
// Returns:
//   - *GetHandler: Handler instance ready for use
func NewGetHandler(credentialService *service.CredentialService) *GetHandler {
	return &GetHandler{
		credentialService: credentialService,
	}
}

// CredentialDisplayData holds the data to display for a credential.
//
// Purpose: Simple data structure for formatting credential output.
type CredentialDisplayData struct {
	ID       int
	Title    string
	Address  string
	Username string
	Password string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Run executes the get credential workflow.
//
// Purpose: Use case for retrieving a credential from the password manager.
// Optionally decrypts the password if requested.
//
// Parameters:
//   - id: Unique credential identifier
//   - showPassword: If true, decrypt and return the password
//   - privateKeyPath: Path to private key (required if showPassword is true)
//   - privateKeyPassphrase: Passphrase for private key (required if showPassword is true)
//
// Returns:
//   - *CredentialDisplayData: The credential data (with password if requested)
//   - error: Error if operation fails
//
// Workflow:
//   1. Retrieve credential from service
//   2. If showPassword is true, decrypt the password
//   3. Format and return the credential data
func (h *GetHandler) Run(id int, showPassword bool, privateKeyPath, privateKeyPassphrase string) (*CredentialDisplayData, error) {
	// Validate showPassword parameters
	if showPassword {
		if privateKeyPath == "" {
			return nil, fmt.Errorf("--private-key flag is required when using --show-password")
		}
		if privateKeyPassphrase == "" {
			return nil, fmt.Errorf("private key passphrase is required when using --show-password")
		}
	}

	// Retrieve credential from service
	cred, password, err := h.credentialService.GetCredential(id, showPassword, privateKeyPath, privateKeyPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	// Format display data
	displayData := &CredentialDisplayData{
		ID:        cred.ID,
		Title:     cred.Title,
		Address:   cred.Address,
		Username:  cred.Username,
		Password:  password, // Empty string if showPassword is false
		CreatedAt: cred.CreatedAt,
		UpdatedAt: cred.UpdatedAt,
	}

	return displayData, nil
}

// Format formats the credential display data as a string.
//
// Purpose: Converts credential data to a human-readable string format.
//
// Returns:
//   - string: Formatted credential information
func (d *CredentialDisplayData) Format() string {
	var sb strings.Builder

	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Credential ID: %d\n", d.ID))
	sb.WriteString(strings.Repeat("=", 70))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  Title:      %s\n", d.Title))
	if d.Address != "" {
		sb.WriteString(fmt.Sprintf("  Address:    %s\n", d.Address))
	}
	sb.WriteString(fmt.Sprintf("  Username:   %s\n", d.Username))
	if d.Password != "" {
		sb.WriteString(fmt.Sprintf("  Password:   %s\n", d.Password))
	} else {
		sb.WriteString("  Password:   [Hidden - use --show-password to reveal]\n")
	}
	sb.WriteString(fmt.Sprintf("  Created:    %s\n", d.CreatedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("  Updated:    %s\n", d.UpdatedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(strings.Repeat("=", 70))

	return sb.String()
}

// ToDisplayData converts a domain entity to display data.
//
// Purpose: Helper function to convert entity.Credential to CredentialDisplayData.
// This is useful for handlers that need to display credentials.
//
// Parameters:
//   - cred: The credential entity
//   - password: The decrypted password (empty if not decrypted)
//
// Returns:
//   - *CredentialDisplayData: The display data
func ToDisplayData(cred *entity.Credential, password string) *CredentialDisplayData {
	return &CredentialDisplayData{
		ID:        cred.ID,
		Title:     cred.Title,
		Address:   cred.Address,
		Username:  cred.Username,
		Password:  password,
		CreatedAt: cred.CreatedAt,
		UpdatedAt: cred.UpdatedAt,
	}
}
