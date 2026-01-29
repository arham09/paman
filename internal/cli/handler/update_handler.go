// Package handler provides CLI command handlers for the paman application.
package handler

import (
	"fmt"

	"github.com/arham09/paman/internal/application/service"
)

// UpdateHandler handles the "paman update" command.
//
// Purpose: Orchestrates updating an existing credential.
type UpdateHandler struct {
	credentialService *service.CredentialService
}

// NewUpdateHandler creates a new update handler.
//
// Purpose: Constructor that wires dependencies via dependency injection.
//
// Parameters:
//   - credentialService: Service for credential operations
//
// Returns:
//   - *UpdateHandler: Handler instance ready for use
func NewUpdateHandler(credentialService *service.CredentialService) *UpdateHandler {
	return &UpdateHandler{
		credentialService: credentialService,
	}
}

// Run executes the update credential workflow.
//
// Purpose: Use case for updating credential fields.
// Can update individual fields or entire credential.
//
// Parameters:
//   - id: Unique credential identifier
//   - title: New title (optional)
//   - address: New address (optional)
//   - username: New username (optional)
//   - password: New password (optional, encrypted if provided)
//   - privateKeyPath: Path to private key for re-encryption (only if password provided)
//
// Returns:
//   - error: Error if operation fails
//
// Workflow:
//   1. Validate at least one field is provided
//   2. Call credentialService.UpdateCredential()
//   3. Display success message
//
// Note: If password is provided, it will be re-encrypted with the current public key.
// The privateKeyPath is NOT used for password updates (only public key needed for encryption).
// It's included in the signature for API consistency with other handlers.
func (h *UpdateHandler) Run(id int, title, address, username, password, privateKeyPath string) error {
	// Validate that at least one field is being updated
	if title == "" && address == "" && username == "" && password == "" {
		return fmt.Errorf("at least one field must be provided for update")
	}

	// Validate ID
	if id <= 0 {
		return fmt.Errorf("invalid credential ID: %d", id)
	}

	// Call application service to update credential
	// The service will:
	//   - Verify credential exists
	//   - Build updates map with provided fields
	//   - If password provided, encrypt it with public key
	//   - Apply partial update
	err := h.credentialService.UpdateCredential(id, title, address, username, password, privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	// Return success (caller will display message)
	return nil
}

// FormatSuccessMessage formats a success message for the update operation.
//
// Purpose: Provides a consistent success message format.
//
// Parameters:
//   - id: The credential ID that was updated
//
// Returns:
//   - string: Formatted success message
func (h *UpdateHandler) FormatSuccessMessage(id int) string {
	return fmt.Sprintf("✓ Credential %d updated successfully\n", id)
}

// FormatUpdateSummary formats a summary of what was updated.
//
// Purpose: Provides detailed feedback about which fields were updated.
//
// Parameters:
//   - id: The credential ID that was updated
//   - title: New title (empty if not updated)
//   - address: New address (empty if not updated)
//   - username: New username (empty if not updated)
//   - hasPassword: Whether password was updated
//
// Returns:
//   - string: Formatted update summary
func (h *UpdateHandler) FormatUpdateSummary(id int, title, address, username string, hasPassword bool) string {
	var updatedFields []string

	if title != "" {
		updatedFields = append(updatedFields, "title")
	}
	if address != "" {
		updatedFields = append(updatedFields, "address")
	}
	if username != "" {
		updatedFields = append(updatedFields, "username")
	}
	if hasPassword {
		updatedFields = append(updatedFields, "password")
	}

	msg := fmt.Sprintf("✓ Credential %d updated successfully\n", id)
	if len(updatedFields) > 0 {
		msg += fmt.Sprintf("  Updated fields: %s\n", joinWithComma(updatedFields))
	}

	return msg
}

// joinWithComma joins a slice of strings with commas and "and" for the last item.
//
// Purpose: Helper function to format lists nicely.
//
// Parameters:
//   - items: Slice of strings to join
//
// Returns:
//   - string: Formatted string
func joinWithComma(items []string) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		return items[0]
	}
	if len(items) == 2 {
		return items[0] + " and " + items[1]
	}

	// Join all but the last with commas
	return fmt.Sprintf("%s, and %s", joinStrings(items[:len(items)-1], ", "), items[len(items)-1])
}

// joinStrings joins a slice of strings with a separator.
//
// Purpose: Helper function for string joining.
func joinStrings(items []string, sep string) string {
	if len(items) == 0 {
		return ""
	}
	result := items[0]
	for i := 1; i < len(items); i++ {
		result += sep + items[i]
	}
	return result
}
