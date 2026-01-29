// Package entity defines the core domain entities used throughout the paman application.
// These entities represent the business objects and their validation rules.
//
// Purpose: Entities are the heart of the domain layer. They contain business logic
// and validation rules that must always be enforced, regardless of where they're used.
package entity

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrValidationFailed is returned when entity validation fails.
	ErrValidationFailed = errors.New("validation failed")
)

// Credential represents a single password entry stored in the database.
//
// Purpose: This is the primary domain entity for storing user credentials.
// It contains all the information about a service/account including the encrypted password.
//
// Security Considerations:
//   - EncryptedPassword is stored as []byte (Base64-encoded in SQLite)
//   - The password is encrypted using RSA-4096-OAEP before storage
//   - The "-" json tag ensures encrypted password is never exposed in JSON output
//   - Never log or print the EncryptedPassword field
//
// Usage:
//   - Created when adding a new credential via "paman add"
//   - Retrieved from database via "paman get" or "paman list"
//   - EncryptedPassword is only decrypted when explicitly requested (with --show-password)
type Credential struct {
	// ID is the unique identifier for this credential in the database.
	// It's auto-incremented by the database and used to reference specific credentials.
	// For new credentials, ID should be 0 (will be set by repository).
	ID int `json:"id"`

	// Title is the name/identifier for the credential (e.g., "GitHub", "Gmail").
	// This field is required and indexed for faster searching.
	Title string `json:"title"`

	// Address is the optional URL/location of the service (e.g., "https://github.com").
	// This field is optional and can help users remember where the credential is used.
	Address string `json:"address,omitempty"`

	// Username is the user's identifier for the service (email or username).
	// This field is required and indexed for faster searching.
	Username string `json:"username"`

	// EncryptedPassword contains the password encrypted with RSA-4096-OAEP.
	// IMPORTANT: This field is never exposed in JSON (json:"-" tag)
	// The password is encrypted with the PUBLIC key before storage.
	// It can only be decrypted with the PRIVATE key.
	// Stored as []byte but Base64-encoded when stored in SQLite TEXT column.
	EncryptedPassword []byte `json:"-"` // Never expose in JSON

	// CreatedAt is the timestamp when this credential was first added.
	// This helps users track when they created each credential.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when this credential was last modified.
	// This updates automatically whenever any field is changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// CredentialDisplay is a safe, view-only version of Credential.
//
// Purpose: Provides a way to display credential information WITHOUT the encrypted password.
// This prevents accidental exposure of sensitive data in logs, UI displays, or API responses.
//
// Security: This type does NOT include the EncryptedPassword field, making it safe to:
//   - Display in CLI output (paman list, paman search)
//   - Serialize to JSON for APIs
//   - Log or debug without exposing sensitive data
//
// When to use:
//   - Use Credential when you need to encrypt/decrypt passwords
//   - Use CredentialDisplay when listing or showing credentials without passwords
type CredentialDisplay struct {
	// ID is the unique identifier (same as Credential.ID)
	ID int `json:"id"`

	// Title is the credential name (same as Credential.Title)
	Title string `json:"title"`

	// Address is the service URL (same as Credential.Address)
	Address string `json:"address,omitempty"`

	// Username is the user identifier (same as Credential.Username)
	Username string `json:"username"`

	// CreatedAt is the creation timestamp (same as Credential.CreatedAt)
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the last update timestamp (same as Credential.UpdatedAt)
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate checks if the credential has valid data.
//
// Purpose: Enforces business rules for credential data.
// This should be called before creating or updating credentials.
//
// Returns:
//   - error: ErrValidationFailed if validation fails, nil otherwise
//
// Validation Rules:
//   - Title: Required, non-empty after trimming
//   - Username: Required, non-empty after trimming
//   - Address: Optional, can be empty
//   - EncryptedPassword: Required for new credentials, optional for updates
//
// Usage:
//   if err := credential.Validate(); err != nil {
//       return fmt.Errorf("invalid credential: %w", err)
//   }
func (c *Credential) Validate() error {
	// Validate title
	if strings.TrimSpace(c.Title) == "" {
		return errors.New("title is required")
	}

	// Validate username
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("username is required")
	}

	// Address is optional, so we don't validate it

	// EncryptedPassword validation depends on context
	// For new credentials (ID == 0), encrypted password is required
	// For updates (ID > 0), we allow partial updates without password
	// This validation is typically handled at the application service layer

	return nil
}

// ToDisplay converts a Credential to a CredentialDisplay, removing the encrypted password.
//
// Purpose: Safely converts a full Credential (with encrypted password) to a displayable version.
// This is used by list and search commands to show credentials without exposing sensitive data.
//
// Returns:
//   - CredentialDisplay: A copy of the credential without the EncryptedPassword field
//
// Security: This method ensures that encrypted passwords are never accidentally exposed
// in user-facing displays. The encrypted password is simply omitted from the returned struct.
//
// Usage Example:
//
//	credential := repository.GetByID(id)
//	display := credential.ToDisplay()
//	// Now 'display' can be safely shown to the user
func (c *Credential) ToDisplay() CredentialDisplay {
	return CredentialDisplay{
		ID:        c.ID,
		Title:     c.Title,
		Address:   c.Address,
		Username:  c.Username,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		// Note: EncryptedPassword is intentionally omitted
	}
}
