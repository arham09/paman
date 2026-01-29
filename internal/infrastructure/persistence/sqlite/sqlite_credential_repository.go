// Package sqlite provides SQLite implementation of the CredentialRepository port.
// This adapter implements the repository interface defined in the domain layer.
//
// Purpose: Provides persistence for credentials using SQLite database.
// This is an infrastructure adapter that implements the CredentialRepository port.
//
// Design:
//   - Constructor injection of *sql.DB connection
//   - Implements all CredentialRepository interface methods
//   - Uses prepared statements to prevent SQL injection
//   - Returns domain errors, not database-specific errors
//   - Converts between database rows and domain entities
//
// Security:
//   - All queries use prepared statements (prevents SQL injection)
//   - Encrypted passwords remain encrypted in transit and at rest
//   - No plaintext passwords ever touch this layer
package sqlite

import (
	"database/sql"
	"fmt"
	"time"

	domainerror "github.com/arham09/paman/internal/domain/error"
	"github.com/arham09/paman/internal/domain/entity"
)

// SQLiteCredentialRepository implements the CredentialRepository port using SQLite.
//
// Purpose: Provides SQLite-based persistence for credentials.
// This is an adapter that bridges the domain layer with SQLite infrastructure.
//
// Design: Constructor injection - depends on *sql.DB interface.
// The database connection is created and managed externally (e.g., by setup.go).
type SQLiteCredentialRepository struct {
	db *sql.DB
}

// NewSQLiteCredentialRepository creates a new SQLite credential repository.
//
// Purpose: Constructor that creates a repository instance with database connection.
// Uses constructor injection pattern - dependency is provided externally.
//
// Parameters:
//   - db: Active database connection (must be already initialized)
//
// Returns:
//   - *SQLiteCredentialRepository: Repository instance ready for use
//
// Design: Constructor injection ensures the repository doesn't create
// its own dependencies, making it easy to test and swap implementations.
func NewSQLiteCredentialRepository(db *sql.DB) *SQLiteCredentialRepository {
	return &SQLiteCredentialRepository{
		db: db,
	}
}

// Create stores a new credential in the database.
//
// Purpose: Persists a new credential with encrypted password.
// Implements the CredentialRepository.Create() method.
func (r *SQLiteCredentialRepository) Create(cred *entity.Credential) (int64, error) {
	// SQL INSERT query with parameter placeholders
	// Using prepared statements prevents SQL injection attacks
	query := `
		INSERT INTO credentials (title, address, username, encrypted_password, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	// Get current timestamp for created_at and updated_at fields
	now := time.Now()

	// Execute the INSERT query with parameters
	// Parameters are bound to placeholders in order: title, address, username, encrypted_password, created_at, updated_at
	result, err := r.db.Exec(query, cred.Title, cred.Address, cred.Username, string(cred.EncryptedPassword), now, now)
	if err != nil {
		return 0, fmt.Errorf("failed to insert credential: %w", err)
	}

	// Get the auto-generated ID of the newly inserted row
	// LastInsertId() returns the ID created by AUTOINCREMENT
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	// Return the new credential's ID to the caller
	return id, nil
}

// GetByID retrieves a credential by its unique identifier.
//
// Purpose: Fetches a specific credential for display or decryption.
// Implements the CredentialRepository.GetByID() method.
func (r *SQLiteCredentialRepository) GetByID(id int) (*entity.Credential, error) {
	// SQL SELECT query with WHERE clause on ID
	query := `
		SELECT id, title, address, username, encrypted_password, created_at, updated_at
		FROM credentials
		WHERE id = ?
	`

	// Create a Credential entity to hold the result
	var cred entity.Credential

	// Execute the query and scan the result into the entity
	// QueryRow() expects exactly one row to be returned
	// Scan() copies the column values into the entity fields in order
	err := r.db.QueryRow(query, id).Scan(
		&cred.ID,
		&cred.Title,
		&cred.Address,
		&cred.Username,
		&cred.EncryptedPassword,
		&cred.CreatedAt,
		&cred.UpdatedAt,
	)

	// Check if no rows were returned (credential ID doesn't exist)
	// sql.ErrNoRows is a special error indicating "no results found"
	// We convert this to our domain-specific ErrNotFound
	if err == sql.ErrNoRows {
		return nil, domainerror.ErrNotFound
	}

	// Check for other errors (database corruption, scanning issues, etc.)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	// Return a pointer to the credential
	return &cred, nil
}

// List retrieves all credentials from the database.
//
// Purpose: Fetches all credentials for listing (without decrypting passwords).
// Implements the CredentialRepository.List() method.
func (r *SQLiteCredentialRepository) List() ([]*entity.Credential, error) {
	// SQL SELECT query with ORDER BY for alphabetical sorting
	// ASC = ascending (A to Z)
	query := `
		SELECT id, title, address, username, encrypted_password, created_at, updated_at
		FROM credentials
		ORDER BY title ASC
	`

	// Execute the query
	// Query() is used for SELECT (returns multiple rows)
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	// Ensure rows are closed when function exits
	// defer runs after function returns, even if there's a panic
	// Critical for preventing database connection leaks
	defer rows.Close()

	// Create a slice to hold all credentials
	var credentials []*entity.Credential

	// Iterate over each row in the result set
	for rows.Next() {
		// Create a new Credential entity for this row
		var cred entity.Credential

		// Scan the row's columns into the entity fields
		// Must match the SELECT column order exactly
		err := rows.Scan(
			&cred.ID,
			&cred.Title,
			&cred.Address,
			&cred.Username,
			&cred.EncryptedPassword,
			&cred.CreatedAt,
			&cred.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		// Add the credential to our slice
		credentials = append(credentials, &cred)
	}

	// Check for errors that occurred during iteration
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credentials: %w", err)
	}

	// Return the slice of all credentials
	return credentials, nil
}

// Search performs a full-text search across credentials.
//
// Purpose: Searches title, address, and username fields using FTS5.
// Implements the CredentialRepository.Search() method.
func (r *SQLiteCredentialRepository) Search(query string) ([]*entity.Credential, error) {
	// SQL query joining main table with FTS index
	// INNER JOIN ensures we only get credentials that match the search
	// MATCH is FTS5's full-text search operator
	// ORDER BY rank sorts by relevance (best matches first)
	searchQuery := `
		SELECT c.id, c.title, c.address, c.username, c.encrypted_password, c.created_at, c.updated_at
		FROM credentials c
		INNER JOIN credentials_fts fts ON c.id = fts.rowid
		WHERE credentials_fts MATCH ?
		ORDER BY rank
	`

	// Execute the search query with user's search string
	rows, err := r.db.Query(searchQuery, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search credentials: %w", err)
	}

	// Ensure rows are closed when function exits
	defer rows.Close()

	// Create a slice to hold matching credentials
	var credentials []*entity.Credential

	// Iterate over search results
	for rows.Next() {
		// Create a new Credential entity for this row
		var cred entity.Credential

		// Scan the row's columns into the entity
		err := rows.Scan(
			&cred.ID,
			&cred.Title,
			&cred.Address,
			&cred.Username,
			&cred.EncryptedPassword,
			&cred.CreatedAt,
			&cred.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		// Add matching credential to results
		credentials = append(credentials, &cred)
	}

	// Check for iteration errors
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credentials: %w", err)
	}

	// Return search results (relevance-ranked by FTS5)
	return credentials, nil
}

// Update replaces all fields of an existing credential.
//
// Purpose: Replaces all fields of a credential with new values.
// Implements the CredentialRepository.Update() method.
func (r *SQLiteCredentialRepository) Update(id int, cred *entity.Credential) error {
	// SQL UPDATE query with placeholders
	// Sets all fields to new values, updates the updated_at timestamp
	query := `
		UPDATE credentials
		SET title = ?, address = ?, username = ?, encrypted_password = ?, updated_at = ?
		WHERE id = ?
	`

	// Get current timestamp for updated_at field
	now := time.Now()

	// Execute the UPDATE query
	result, err := r.db.Exec(query, cred.Title, cred.Address, cred.Username, string(cred.EncryptedPassword), now, id)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	// Check how many rows were affected (updated)
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows were affected, the ID doesn't exist
	if rowsAffected == 0 {
		return domainerror.ErrNotFound
	}

	// Update successful
	return nil
}

// UpdatePartial updates specific fields of a credential.
//
// Purpose: Updates only the fields that are provided.
// Implements the CredentialRepository.UpdatePartial() method.
func (r *SQLiteCredentialRepository) UpdatePartial(id int, updates map[string]interface{}) error {
	// Build the SET clause dynamically based on which fields are provided
	setClause := ""
	sep := ""
	finalArgs := []interface{}{}

	// Add title to SET clause if provided
	if val, ok := updates["title"]; ok && val != nil {
		if str, ok := val.(string); ok {
			setClause += sep + "title = ?"
			finalArgs = append(finalArgs, str)
			sep = ", "
		}
	}

	// Add address to SET clause if provided
	if val, ok := updates["address"]; ok && val != nil {
		if str, ok := val.(string); ok {
			setClause += sep + "address = ?"
			finalArgs = append(finalArgs, str)
			sep = ", "
		}
	}

	// Add username to SET clause if provided
	if val, ok := updates["username"]; ok && val != nil {
		if str, ok := val.(string); ok {
			setClause += sep + "username = ?"
			finalArgs = append(finalArgs, str)
			sep = ", "
		}
	}

	// Add encrypted_password to SET clause if provided
	if val, ok := updates["encrypted_password"]; ok && val != nil {
		if str, ok := val.(string); ok {
			setClause += sep + "encrypted_password = ?"
			finalArgs = append(finalArgs, str)
			sep = ", "
		}
	}

	// Validate that at least one field was provided for update
	if len(setClause) == 0 {
		return domainerror.ErrInvalidInput
	}

	// Always update the updated_at timestamp
	setClause += ", updated_at = ?"
	finalArgs = append(finalArgs, time.Now())

	// Build the complete UPDATE query
	query := fmt.Sprintf("UPDATE credentials SET %s WHERE id = ?", setClause)
	finalArgs = append(finalArgs, id)

	// Execute the dynamic UPDATE query
	result, err := r.db.Exec(query, finalArgs...)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	// Check if the credential exists
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows were affected, the ID doesn't exist
	if rowsAffected == 0 {
		return domainerror.ErrNotFound
	}

	// Update successful
	return nil
}

// Delete removes a credential from the database by ID.
//
// Purpose: Permanently deletes a credential.
// Implements the CredentialRepository.Delete() method.
func (r *SQLiteCredentialRepository) Delete(id int) error {
	// SQL DELETE query with WHERE clause
	query := `DELETE FROM credentials WHERE id = ?`

	// Execute the DELETE query
	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	// Check how many rows were deleted
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows were deleted, the ID doesn't exist
	if rowsAffected == 0 {
		return domainerror.ErrNotFound
	}

	// Deletion successful
	return nil
}

// Exists checks if a credential with the given ID exists.
//
// Purpose: Validates credential existence before operations.
// Implements the CredentialRepository.Exists() method.
func (r *SQLiteCredentialRepository) Exists(id int) (bool, error) {
	// SQL COUNT query to check if row exists
	query := `SELECT COUNT(*) FROM credentials WHERE id = ?`

	// Execute the query and scan the count into an integer
	var count int
	err := r.db.QueryRow(query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check credential existence: %w", err)
	}

	// Return true if count > 0 (credential exists)
	return count > 0, nil
}
