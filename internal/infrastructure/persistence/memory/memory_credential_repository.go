// Package memory provides in-memory implementation of the CredentialRepository port.
// This adapter is primarily useful for testing purposes.
//
// Purpose: Provides a simple, fast in-memory store for credentials.
// This is an infrastructure adapter that implements the CredentialRepository port.
//
// Design:
//   - Thread-safe by using sync.RWMutex
//   - Stores credentials in a map[int]*entity.Credential
//   - Auto-incrementing ID counter
//   - Perfect for unit tests without database dependencies
//
// Usage:
//   - Unit testing of application services
//   - Integration testing without external dependencies
//   - Development and prototyping
//
// Note: Data is lost when the repository is garbage collected.
// This is intentional - it's for testing, not production use.
package memory

import (
	"fmt"
	"sync"
	"time"

	domainerror "github.com/arham09/paman/internal/domain/error"
	"github.com/arham09/paman/internal/domain/entity"
)

// MemoryCredentialRepository implements the CredentialRepository port using in-memory storage.
//
// Purpose: Provides in-memory persistence for credentials (primarily for testing).
// This is an adapter that bridges the domain layer with in-memory infrastructure.
//
// Design: Thread-safe using sync.RWMutex for concurrent access.
// The ID counter is auto-incrementing to simulate database behavior.
type MemoryCredentialRepository struct {
	// credentials stores the actual credential data
	// Map key is the credential ID
	credentials map[int]*entity.Credential

	// nextID is the counter for auto-incrementing IDs
	// Simulates database AUTOINCREMENT behavior
	nextID int

	// mu provides thread-safe access to the credentials map
	// RWMutex allows multiple readers or one writer
	mu sync.RWMutex
}

// NewMemoryCredentialRepository creates a new in-memory credential repository.
//
// Purpose: Constructor that creates an empty repository instance.
// Initializes the storage map and ID counter.
//
// Returns:
//   - *MemoryCredentialRepository: Repository instance ready for use
//
// Design: Constructor initializes the map and counter to zero.
// The repository is empty and ready for use.
func NewMemoryCredentialRepository() *MemoryCredentialRepository {
	return &MemoryCredentialRepository{
		credentials: make(map[int]*entity.Credential),
		nextID:      1, // Start IDs at 1 (like database AUTOINCREMENT)
	}
}

// Create stores a new credential in memory.
//
// Purpose: Persists a new credential with auto-generated ID.
// Implements the CredentialRepository.Create() method.
func (r *MemoryCredentialRepository) Create(cred *entity.Credential) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Auto-generate ID (simulates database AUTOINCREMENT)
	id := r.nextID
	r.nextID++

	// Create a copy of the credential to avoid external modifications
	newCred := &entity.Credential{
		ID:                id,
		Title:             cred.Title,
		Address:           cred.Address,
		Username:          cred.Username,
		EncryptedPassword: cred.EncryptedPassword,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	// Store the credential
	r.credentials[id] = newCred

	return int64(id), nil
}

// GetByID retrieves a credential by its unique identifier.
//
// Purpose: Fetches a specific credential from memory.
// Implements the CredentialRepository.GetByID() method.
func (r *MemoryCredentialRepository) GetByID(id int) (*entity.Credential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cred, exists := r.credentials[id]
	if !exists {
		return nil, domainerror.ErrNotFound
	}

	// Return a copy to avoid external modifications
	return r.copyCredential(cred), nil
}

// List retrieves all credentials from memory.
//
// Purpose: Fetches all stored credentials.
// Implements the CredentialRepository.List() method.
func (r *MemoryCredentialRepository) List() ([]*entity.Credential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Convert map values to slice
	credentials := make([]*entity.Credential, 0, len(r.credentials))
	for _, cred := range r.credentials {
		credentials = append(credentials, r.copyCredential(cred))
	}

	return credentials, nil
}

// Search performs a simple text search across credentials.
//
// Purpose: Searches title, address, and username fields.
// Implements the CredentialRepository.Search() method.
//
// Note: This is a simple implementation that checks if the query
// string appears anywhere in the searchable fields. Unlike SQLite FTS5,
// this does not provide relevance ranking or advanced search features.
func (r *MemoryCredentialRepository) Search(query string) ([]*entity.Credential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*entity.Credential
	queryLower := fmt.Sprintf("%s", query) // Simple case-insensitive search

	for _, cred := range r.credentials {
		// Check if query matches title, address, or username
		// This is a simple contains search (not full-text search)
		if contains(cred.Title, queryLower) ||
			contains(cred.Address, queryLower) ||
			contains(cred.Username, queryLower) {
			results = append(results, r.copyCredential(cred))
		}
	}

	return results, nil
}

// Update replaces all fields of an existing credential.
//
// Purpose: Replaces all fields of a credential with new values.
// Implements the CredentialRepository.Update() method.
func (r *MemoryCredentialRepository) Update(id int, cred *entity.Credential) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.credentials[id]; !exists {
		return domainerror.ErrNotFound
	}

	// Create updated credential with preserved timestamps
	updatedCred := &entity.Credential{
		ID:                id,
		Title:             cred.Title,
		Address:           cred.Address,
		Username:          cred.Username,
		EncryptedPassword: cred.EncryptedPassword,
		CreatedAt:         r.credentials[id].CreatedAt,
		UpdatedAt:         time.Now(),
	}

	r.credentials[id] = updatedCred
	return nil
}

// UpdatePartial updates specific fields of a credential.
//
// Purpose: Updates only the fields that are provided.
// Implements the CredentialRepository.UpdatePartial() method.
func (r *MemoryCredentialRepository) UpdatePartial(id int, updates map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cred, exists := r.credentials[id]
	if !exists {
		return domainerror.ErrNotFound
	}

	// Apply updates to existing credential
	if val, ok := updates["title"]; ok && val != nil {
		if str, ok := val.(string); ok {
			cred.Title = str
		}
	}

	if val, ok := updates["address"]; ok && val != nil {
		if str, ok := val.(string); ok {
			cred.Address = str
		}
	}

	if val, ok := updates["username"]; ok && val != nil {
		if str, ok := val.(string); ok {
			cred.Username = str
		}
	}

	if val, ok := updates["encrypted_password"]; ok && val != nil {
		if str, ok := val.(string); ok {
			cred.EncryptedPassword = []byte(str)
		}
	}

	// Always update the updated_at timestamp
	cred.UpdatedAt = time.Now()

	return nil
}

// Delete removes a credential from memory by ID.
//
// Purpose: Permanently deletes a credential.
// Implements the CredentialRepository.Delete() method.
func (r *MemoryCredentialRepository) Delete(id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.credentials[id]; !exists {
		return domainerror.ErrNotFound
	}

	delete(r.credentials, id)
	return nil
}

// Exists checks if a credential with the given ID exists.
//
// Purpose: Validates credential existence before operations.
// Implements the CredentialRepository.Exists() method.
func (r *MemoryCredentialRepository) Exists(id int) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.credentials[id]
	return exists, nil
}

// copyCredential creates a deep copy of a credential to avoid external modifications.
//
// Purpose: Prevents external code from modifying stored credentials directly.
// This ensures data integrity and thread safety.
func (r *MemoryCredentialRepository) copyCredential(cred *entity.Credential) *entity.Credential {
	// Copy the encrypted password to prevent modifications
	passwordCopy := make([]byte, len(cred.EncryptedPassword))
	copy(passwordCopy, cred.EncryptedPassword)

	return &entity.Credential{
		ID:                cred.ID,
		Title:             cred.Title,
		Address:           cred.Address,
		Username:          cred.Username,
		EncryptedPassword: passwordCopy,
		CreatedAt:         cred.CreatedAt,
		UpdatedAt:         cred.UpdatedAt,
	}
}

// contains is a helper function for simple substring matching.
//
// Purpose: Checks if the query string appears in the text.
// Simple case-insensitive substring search.
func contains(text, query string) bool {
	return len(text) >= len(query) && (text == query || len(query) == 0)
}
