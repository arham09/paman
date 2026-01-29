// Package port defines the interfaces that the domain layer requires.
// These are the "ports" of the hexagonal architecture - the contracts
// that the domain layer needs from external adapters.
//
// Primary Ports (driven by domain):
// - CredentialRepository: Defines credential storage operations
//
// These interfaces are implemented by adapters in the infrastructure layer.
package port

import (
	"github.com/arham09/paman/internal/domain/entity"
)

// CredentialRepository defines the contract for credential storage operations.
//
// Purpose: This is a primary port interface that defines how the domain layer
// persists and retrieves credentials. It's implemented by adapters like
// SQLiteCredentialRepository and MemoryCredentialRepository.
//
// Design Principles:
//   - Interface depends on domain entities, not concrete types
//   - Methods return domain errors, not database errors
//   - Supports CRUD operations plus search
//   - UpdatePartial allows flexible field updates
//
// Benefits:
//   - Domain logic doesn't depend on concrete database implementations
//   - Easy to swap implementations (SQLite, PostgreSQL, in-memory)
//   - Can mock for testing without real database
type CredentialRepository interface {
	// Create stores a new credential in the repository.
	//
	// Parameters:
	//   - cred: The credential entity to store (with ID = 0)
	//
	// Returns:
	//   - int64: The auto-generated ID of the new credential
	//   - error: Domain error if creation fails
	//
	// Post-condition: The credential's ID field is set to the returned value
	Create(cred *entity.Credential) (int64, error)

	// GetByID retrieves a credential by its unique identifier.
	//
	// Parameters:
	//   - id: The unique credential ID
	//
	// Returns:
	//   - *entity.Credential: The credential, or nil if not found
	//   - error: Domain error if retrieval fails
	//
	// Error cases:
	//   - entity.ErrNotFound: If credential doesn't exist
	GetByID(id int) (*entity.Credential, error)

	// List retrieves all credentials from the repository.
	//
	// Returns:
	//   - []*entity.Credential: All credentials (may be empty)
	//   - error: Domain error if retrieval fails
	//
	// Note: Returns credentials with encrypted passwords intact.
	// Use credential.ToDisplay() for safe display.
	List() ([]*entity.Credential, error)

	// Search performs a full-text search across credentials.
	//
	// Parameters:
	//   - query: Search query string
	//
	// Returns:
	//   - []*entity.Credential: Matching credentials (may be empty)
	//   - error: Domain error if search fails
	//
	// Search scope: title, address, username fields
	// Returns results relevance-ranked by FTS5 (for SQLite adapter)
	Search(query string) ([]*entity.Credential, error)

	// Update replaces all fields of an existing credential.
	//
	// Parameters:
	//   - id: The unique credential ID to update
	//   - cred: The new credential data (ID field is ignored)
	//
	// Returns:
	//   - error: Domain error if update fails
	//
	// Error cases:
	//   - entity.ErrNotFound: If credential doesn't exist
	Update(id int, cred *entity.Credential) error

	// UpdatePartial updates specific fields of a credential.
	//
	// Parameters:
	//   - id: The unique credential ID to update
	//   - updates: Map of field names to new values
	//              Supported keys: "title", "address", "username", "encrypted_password"
	//
	// Returns:
	//   - error: Domain error if update fails
	//
	// Error cases:
	//   - entity.ErrNotFound: If credential doesn't exist
	//   - entity.ErrInvalidInput: If no valid fields provided
	//
	// Note: Only non-nil values in the map are updated.
	// The updated_at timestamp is always updated.
	UpdatePartial(id int, updates map[string]interface{}) error

	// Delete removes a credential from the repository.
	//
	// Parameters:
	//   - id: The unique credential ID to delete
	//
	// Returns:
	//   - error: Domain error if deletion fails
	//
	// Error cases:
	//   - entity.ErrNotFound: If credential doesn't exist
	//
	// Note: This operation is irreversible.
	Delete(id int) error

	// Exists checks if a credential with the given ID exists.
	//
	// Parameters:
	//   - id: The unique credential ID to check
	//
	// Returns:
	//   - bool: true if credential exists, false otherwise
	//   - error: Domain error if check fails
	//
	// Purpose: Lightweight existence check without retrieving full credential.
	// Useful for validation before operations.
	Exists(id int) (bool, error)
}
