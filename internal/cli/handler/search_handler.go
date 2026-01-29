// Package handler provides CLI command handlers for the paman application.
package handler

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/arham09/paman/internal/application/service"
	"github.com/arham09/paman/internal/domain/entity"
	"os"
)

// SearchHandler handles the "paman search" command.
//
// Purpose: Orchestrates searching credentials by query string.
type SearchHandler struct {
	credentialService *service.CredentialService
}

// NewSearchHandler creates a new search handler.
//
// Purpose: Constructor that wires dependencies via dependency injection.
//
// Parameters:
//   - credentialService: Service for credential operations
//
// Returns:
//   - *SearchHandler: Handler instance ready for use
func NewSearchHandler(credentialService *service.CredentialService) *SearchHandler {
	return &SearchHandler{
		credentialService: credentialService,
	}
}

// Run executes the search credentials workflow.
//
// Purpose: Use case for searching stored credentials.
// Returns matching credentials without decrypted passwords.
//
// Parameters:
//   - query: Search query string
//
// Returns:
//   - error: Error if operation fails
//
// Workflow:
//   1. Validate query is not empty
//   2. Search repository
//   3. Format output as a table
//   4. Handle no results case
func (h *SearchHandler) Run(query string) error {
	// Validate query
	query = strings.TrimSpace(query)
	if query == "" {
		return fmt.Errorf("search query cannot be empty")
	}

	// Search repository
	credentials, err := h.credentialService.SearchCredentials(query)
	if err != nil {
		return fmt.Errorf("failed to search credentials: %w", err)
	}

	// Handle no results
	if len(credentials) == 0 {
		fmt.Printf("No credentials found matching '%s'.\n", query)
		fmt.Println("\n💡 Tip: Search looks in title, address, and username fields")
		fmt.Println("           Try a broader search term")
		return nil
	}

	// Format output as a table
	h.displayTable(query, credentials)

	return nil
}

// displayTable formats and displays search results as a table.
//
// Purpose: Creates a nicely formatted table output for search results.
// Uses tabwriter for aligned columns.
//
// Parameters:
//   - query: The search query used
//   - credentials: List of matching credential display objects
func (h *SearchHandler) displayTable(query string, credentials []*entity.CredentialDisplay) {
	// Create tabwriter for nicely aligned columns
	// minwidth=0, tabwidth=8, padding=4, padchar=' ', flags=0
	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)

	// Print header with search query
	fmt.Printf("Found %d credential(s) matching '%s':\n\n", len(credentials), query)

	// Print table header
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
	fmt.Printf("\nTotal: %d result(s)\n", len(credentials))
	fmt.Println("\n💡 Tip: Use 'paman get <id>' to view details")
	fmt.Println("           Use 'paman get <id> --show-password' to view password")
}

// FormatAsText formats search results as plain text (alternative to table).
//
// Purpose: Provides an alternative text format for search results.
// Useful for scripting or when table formatting is not desired.
//
// Parameters:
//   - query: The search query used
//   - credentials: List of matching credential display objects
//
// Returns:
//   - string: Formatted text output
func (h *SearchHandler) FormatAsText(query string, credentials []*entity.CredentialDisplay) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Found %d credential(s) matching '%s':\n", len(credentials), query))
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
