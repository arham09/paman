// Package handler provides CLI command handlers for the paman application.
package handler

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/arham09/paman/internal/application/service"
	"github.com/arham09/paman/internal/domain/entity"
)

// ListHandler handles the "paman list" command.
//
// Purpose: Orchestrates listing all credentials (without passwords).
type ListHandler struct {
	credentialService *service.CredentialService
}

// NewListHandler creates a new list handler.
//
// Purpose: Constructor that wires dependencies via dependency injection.
//
// Parameters:
//   - credentialService: Service for credential operations
//
// Returns:
//   - *ListHandler: Handler instance ready for use
func NewListHandler(credentialService *service.CredentialService) *ListHandler {
	return &ListHandler{
		credentialService: credentialService,
	}
}

// Run executes the list credentials workflow.
//
// Purpose: Use case for listing all stored credentials.
// Returns credentials without decrypted passwords for security.
//
// Returns:
//   - error: Error if operation fails
//
// Workflow:
//   1. Retrieve all credentials from service
//   2. Format output as a table
//   3. Handle empty list case
func (h *ListHandler) Run() error {
	// Retrieve all credentials from service
	credentials, err := h.credentialService.ListCredentials()
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	// Handle empty list
	if len(credentials) == 0 {
		fmt.Println("No credentials found.")
		fmt.Println("\nAdd your first credential using:")
		fmt.Println("  paman add --title \"GitHub\" --username \"user@example.com\" --password \"secret123\"")
		return nil
	}

	// Format output as a table
	h.displayTable(credentials)

	return nil
}

// displayTable formats and displays credentials as a table.
//
// Purpose: Creates a nicely formatted table output for credentials.
// Uses tabwriter for aligned columns.
//
// Parameters:
//   - credentials: List of credential display objects
func (h *ListHandler) displayTable(credentials []*entity.CredentialDisplay) {
	// Create tabwriter for nicely aligned columns
	// minwidth=0, tabwidth=8, padding=4, padchar=' ', flags=0
	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)

	// Print header
	fmt.Fprintln(writer, "ID\tTitle\tAddress\tUsername\tCreated")
	fmt.Fprintln(writer, "--\t-----\t-------\t--------\t-------")

	// Print each credential
	for _, cred := range credentials {
		address := cred.Address
		if address == "" {
			address = "-" // Show dash for empty address
		}

		created := cred.CreatedAt.Format("2006-01-02")
		fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\n",
			cred.ID,
			cred.Title,
			address,
			cred.Username,
			created,
		)
	}

	writer.Flush()

	// Print summary
	fmt.Printf("\nTotal: %d credential(s)\n", len(credentials))
	fmt.Println("\n💡 Tip: Use 'paman get <id>' to view details")
	fmt.Println("           Use 'paman get <id> --show-password' to view password")
}

// FormatAsText formats credentials as plain text (alternative to table).
//
// Purpose: Provides an alternative text format for listing credentials.
// Useful for scripting or when table formatting is not desired.
//
// Parameters:
//   - credentials: List of credential display objects
//
// Returns:
//   - string: Formatted text output
func (h *ListHandler) FormatAsText(credentials []*entity.CredentialDisplay) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Found %d credential(s):\n", len(credentials)))
	sb.WriteString("\n")

	for _, cred := range credentials {
		sb.WriteString(fmt.Sprintf("ID: %d\n", cred.ID))
		sb.WriteString(fmt.Sprintf("  Title: %s\n", cred.Title))
		if cred.Address != "" {
			sb.WriteString(fmt.Sprintf("  Address: %s\n", cred.Address))
		}
		sb.WriteString(fmt.Sprintf("  Username: %s\n", cred.Username))
		sb.WriteString(fmt.Sprintf("  Created: %s\n", cred.CreatedAt.Format("2006-01-02 15:04:05")))
		sb.WriteString("\n")
	}

	return sb.String()
}
