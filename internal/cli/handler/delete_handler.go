// Package handler provides CLI command handlers for the paman application.
package handler

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/arham09/paman/internal/application/service"
)

// DeleteHandler handles the "paman delete" command.
//
// Purpose: Orchestrates deleting a credential by ID.
type DeleteHandler struct {
	credentialService *service.CredentialService
}

// NewDeleteHandler creates a new delete handler.
//
// Purpose: Constructor that wires dependencies via dependency injection.
//
// Parameters:
//   - credentialService: Service for credential operations
//
// Returns:
//   - *DeleteHandler: Handler instance ready for use
func NewDeleteHandler(credentialService *service.CredentialService) *DeleteHandler {
	return &DeleteHandler{
		credentialService: credentialService,
	}
}

// Run executes the delete credential workflow.
//
// Purpose: Use case for removing a credential from the password manager.
// This operation is irreversible.
//
// Parameters:
//   - id: Unique credential identifier
//   - confirm: If false, prompt user for confirmation before deleting
//   - force: If true, skip confirmation prompt
//
// Returns:
//   - error: Error if operation fails
//
// Workflow:
//   1. Validate ID
//   2. If not forced, prompt user for confirmation
//   3. Call credentialService.DeleteCredential()
//   4. Display success message
func (h *DeleteHandler) Run(id int, confirm, force bool) error {
	// Validate ID
	if id <= 0 {
		return fmt.Errorf("invalid credential ID: %d", id)
	}

	// Prompt for confirmation unless force flag is set
	if !force {
		confirmed, err := h.promptForConfirmation(id)
		if err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirmed {
			fmt.Println("Delete operation cancelled.")
			return nil
		}
	}

	// Delete the credential
	err := h.credentialService.DeleteCredential(id)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	// Return success (caller will display message)
	return nil
}

// promptForConfirmation prompts the user to confirm the delete operation.
//
// Purpose: Interactively confirms with the user before deleting.
// This prevents accidental deletions.
//
// Parameters:
//   - id: The credential ID to be deleted
//
// Returns:
//   - bool: true if user confirmed, false otherwise
//   - error: Error if input fails
//
// Workflow:
//   1. Display confirmation prompt
//   2. Read user input
//   3. Check if input matches confirmation
func (h *DeleteHandler) promptForConfirmation(id int) (bool, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Are you sure you want to delete credential %d? (yes/no): ", id)

	// Read user input
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	// Trim whitespace and convert to lowercase
	input = strings.TrimSpace(strings.ToLower(input))

	// Check for confirmation
	if input == "yes" || input == "y" {
		return true, nil
	}

	return false, nil
}

// FormatSuccessMessage formats a success message for the delete operation.
//
// Purpose: Provides a consistent success message format.
//
// Parameters:
//   - id: The credential ID that was deleted
//
// Returns:
//   - string: Formatted success message
func (h *DeleteHandler) FormatSuccessMessage(id int) string {
	return fmt.Sprintf("✓ Credential %d deleted successfully\n", id)
}

// PromptForID prompts the user to enter a credential ID.
//
// Purpose: Interactively collects a credential ID from the user.
// Useful for interactive delete operations.
//
// Returns:
//   - int: The credential ID entered by the user
//   - error: Error if input is invalid or not a number
func (h *DeleteHandler) PromptForID() (int, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter credential ID to delete: ")

	// Read user input
	input, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	// Trim whitespace
	input = strings.TrimSpace(input)

	// Parse as integer
	id, err := strconv.Atoi(input)
	if err != nil {
		return 0, fmt.Errorf("invalid credential ID: %s (must be a number)", input)
	}

	if id <= 0 {
		return 0, fmt.Errorf("invalid credential ID: %d (must be positive)", id)
	}

	return id, nil
}

// FormatDeleteConfirmation formats a confirmation prompt.
//
// Purpose: Provides a detailed confirmation prompt showing what will be deleted.
//
// Parameters:
//   - id: The credential ID to be deleted
//
// Returns:
//   - string: Formatted confirmation prompt
func (h *DeleteHandler) FormatDeleteConfirmation(id int) string {
	return fmt.Sprintf("⚠️  WARNING: You are about to permanently delete credential %d\n"+
		"This operation cannot be undone!\n"+
		"Are you sure you want to continue? (yes/no): ", id)
}
