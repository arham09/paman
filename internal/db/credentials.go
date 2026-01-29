// Package db provides CRUD (Create, Read, Update, Delete) operations for credentials.
// This file contains all database access methods for credential management.
//
// All functions use prepared statements with parameterized queries to prevent SQL injection.
// Encrypted passwords are never decrypted in this layer - they're stored and retrieved as-is.
//
// Security:
//   - All queries use prepared statements (prevents SQL injection)
//   - Passwords remain encrypted in transit and at rest
//   - No plaintext passwords ever touch the database layer
//
// Error Handling:
//   - models.ErrNotFound: Credential with given ID doesn't exist
//   - Other errors: Database connection, query execution, or scanning errors
package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/arham09/paman/internal/models"
)

// CreateCredential inserts a new credential into the database.
//
// Purpose: Adds a new credential with encrypted password to the database.
// This is called when users run "paman add" command.
//
// Parameters:
//   - db: Active database connection
//   - title: Credential title/name (e.g., "GitHub", "Gmail")
//   - address: Optional URL/address (e.g., "https://github.com")
//   - username: User's email or username
//   - encryptedPassword: RSA-encrypted password (Base64 encoded string)
//
// Returns:
//   - int64: Auto-generated ID of the new credential (used for future operations)
//   - error: Error if insertion fails
//
// SQL Query:
//
//	INSERT INTO credentials (title, address, username, encrypted_password, created_at, updated_at)
//	VALUES (?, ?, ?, ?, ?, ?)
//
// Security:
//   - Uses prepared statement with parameterized queries
//   - Parameters are properly escaped by the database driver
//   - encryptedPassword is already encrypted before reaching this function
//
// Side Effects:
//   - Auto-increments the ID counter
//   - FTS triggers automatically index the new credential for search
//   - Database file grows by the size of the new credential
//
// When this is called:
//   - During "paman add" command
//   - After password is encrypted with RSA public key
func CreateCredential(db *sql.DB, title, address, username, encryptedPassword string) (int64, error) {
	// SQL INSERT query with parameter placeholders
	// ? is SQLite's placeholder for prepared statement parameters
	// Using prepared statements prevents SQL injection attacks
	query := `
		INSERT INTO credentials (title, address, username, encrypted_password, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	// Get current timestamp for created_at and updated_at fields
	// Using UTC time ensures consistent timestamps across timezones
	now := time.Now()

	// Execute the INSERT query with parameters
	// db.Exec() is used for INSERT/UPDATE/DELETE (no rows returned)
	// Parameters are bound to placeholders in order: title, address, username, encrypted_password, created_at, updated_at
	result, err := db.Exec(query, title, address, username, encryptedPassword, now, now)
	if err != nil {
		// INSERT can fail due to:
		// - Constraint violations (NOT NULL, UNIQUE, etc.)
		// - Database file corruption
		// - Disk full
		return 0, fmt.Errorf("failed to insert credential: %w", err)
	}

	// Get the auto-generated ID of the newly inserted row
	// LastInsertId() returns the ID created by AUTOINCREMENT
	// This ID is needed to reference the credential later (get, update, delete)
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	// Return the new credential's ID to the caller
	// The CLI will display this ID to the user for reference
	return id, nil
}

// GetCredential retrieves a single credential by its ID.
//
// Purpose: Fetches a specific credential from the database for display or decryption.
// Called when users run "paman get <id>" command.
//
// Parameters:
//   - db: Active database connection
//   - id: Unique identifier of the credential to retrieve
//
// Returns:
//   - *models.Credential: The credential with encrypted password (never plaintext)
//   - error: models.ErrNotFound if ID doesn't exist, other errors for database issues
//
// SQL Query:
//
//	SELECT id, title, address, username, encrypted_password, created_at, updated_at
//	FROM credentials
//	WHERE id = ?
//
// Security:
//   - Prepared statement prevents SQL injection
//   - Returns encrypted password only (never decrypts here)
//   - Caller (CLI layer) handles decryption if --show-password flag is used
//
// When this is called:
//   - During "paman get <id>" command
//   - Returns encrypted password, CLI decides whether to decrypt it
func GetCredential(db *sql.DB, id int) (*models.Credential, error) {
	// SQL SELECT query with WHERE clause on ID
	// Only returns the row where id matches the parameter
	query := `
		SELECT id, title, address, username, encrypted_password, created_at, updated_at
		FROM credentials
		WHERE id = ?
	`

	// Create a Credential struct to hold the result
	var cred models.Credential

	// Execute the query and scan the result into the struct
	// QueryRow() expects exactly one row to be returned
	// Scan() copies the column values into the struct fields in order
	// &cred gives us a pointer to modify the struct directly
	err := db.QueryRow(query, id).Scan(
		&cred.ID,                // Column 1: id
		&cred.Title,             // Column 2: title
		&cred.Address,           // Column 3: address (can be NULL/empty)
		&cred.Username,          // Column 4: username
		&cred.EncryptedPassword, // Column 5: encrypted_password (Base64 string -> []byte)
		&cred.CreatedAt,         // Column 6: created_at
		&cred.UpdatedAt,         // Column 7: updated_at
	)

	// Check if no rows were returned (credential ID doesn't exist)
	// sql.ErrNoRows is a special error indicating "no results found"
	// We convert this to our domain-specific models.ErrNotFound
	if err == sql.ErrNoRows {
		return nil, models.ErrNotFound
	}

	// Check for other errors (database corruption, scanning issues, etc.)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	// Return a pointer to the credential
	// Pointer is more efficient than copying the struct
	return &cred, nil
}

// ListCredentials retrieves all credentials from the database, sorted by title.
//
// Purpose: Fetches all credentials for listing (without decrypting passwords).
// Called when users run "paman list" command.
//
// Parameters:
//   - db: Active database connection
//
// Returns:
//   - []*models.Credential: Slice of all credentials (with encrypted passwords)
//   - error: Error if query fails
//
// SQL Query:
//
//	SELECT id, title, address, username, encrypted_password, created_at, updated_at
//	FROM credentials
//	ORDER BY title ASC
//
// Sorting:
//   - Results sorted alphabetically by title (case-insensitive in SQLite)
//   - Makes it easier for users to find credentials in the list
//
// Security:
//   - Returns encrypted passwords only
//   - Caller (CLI) uses ToDisplay() to hide passwords in output
//   - No decryption happens in this function
//
// When this is called:
//   - During "paman list" command
//   - Displays all credentials without showing passwords
func ListCredentials(db *sql.DB) ([]*models.Credential, error) {
	// SQL SELECT query with ORDER BY for alphabetical sorting
	// ASC = ascending (A to Z)
	query := `
		SELECT id, title, address, username, encrypted_password, created_at, updated_at
		FROM credentials
		ORDER BY title ASC
	`

	// Execute the query
	// Query() is used for SELECT (returns multiple rows)
	// Returns a Rows object that we iterate over
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	// Ensure rows are closed when function exits
	// defer runs after function returns, even if there's a panic
	// Critical for preventing database connection leaks
	defer rows.Close()

	// Create a slice to hold all credentials
	// Using pointers (*models.Credential) is more memory efficient
	var credentials []*models.Credential

	// Iterate over each row in the result set
	// rows.Next() advances to the next row, returns false when done
	for rows.Next() {
		// Create a new Credential struct for this row
		var cred models.Credential

		// Scan the row's columns into the struct fields
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
			// Scan can fail if column types don't match struct fields
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		// Add the credential to our slice
		// &cred gives us a pointer to the credential
		credentials = append(credentials, &cred)
	}

	// Check for errors that occurred during iteration
	// rows.Err() returns any error encountered while looping
	// This catches errors that happen after rows.Next() returns false
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credentials: %w", err)
	}

	// Return the slice of all credentials
	return credentials, nil
}

// SearchCredentials performs a full-text search across credentials.
//
// Purpose: Searches title, address, and username fields using FTS5.
// Called when users run "paman search <query>" command.
//
// Parameters:
//   - db: Active database connection
//   - query: Search query string (e.g., "github", "work email")
//
// Returns:
//   - []*models.Credential: Matching credentials (relevance-ranked by FTS5)
//   - error: Error if query fails
//
// SQL Query:
//
//	SELECT c.id, c.title, c.address, c.username, c.encrypted_password, c.created_at, c.updated_at
//	FROM credentials c
//	INNER JOIN credentials_fts fts ON c.id = fts.rowid
//	WHERE credentials_fts MATCH ?
//	ORDER BY rank
//
// FTS5 Features:
//   - Case-insensitive search
//   - Prefix matching (e.g., "git*" matches "github")
//   - Phrase search (e.g., '"work email"')
//   - Boolean operators (AND, OR, NOT)
//   - Relevance ranking (ORDER BY rank)
//
// Performance:
//   - Much faster than LIKE queries on large datasets
//   - Uses FTS5 inverted index for instant results
//
// When this is called:
//   - During "paman search <query>" command
//   - Returns credentials matching the search query
func SearchCredentials(db *sql.DB, query string) ([]*models.Credential, error) {
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
	// The query parameter is bound to the ? placeholder
	rows, err := db.Query(searchQuery, query)
	if err != nil {
		// FTS5 query can fail if:
		// - Invalid FTS5 syntax (special characters not properly quoted)
		// - Corrupted FTS index
		return nil, fmt.Errorf("failed to search credentials: %w", err)
	}

	// Ensure rows are closed when function exits
	defer rows.Close()

	// Create a slice to hold matching credentials
	var credentials []*models.Credential

	// Iterate over search results
	for rows.Next() {
		// Create a new Credential struct for this row
		var cred models.Credential

		// Scan the row's columns into the struct
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

// UpdateCredential updates all fields of an existing credential.
//
// Purpose: Replaces all fields of a credential with new values.
// Used when users need to completely update a credential.
//
// Parameters:
//   - db: Active database connection
//   - id: Unique identifier of the credential to update
//   - title: New title
//   - address: New address
//   - username: New username
//   - encryptedPassword: New encrypted password
//
// Returns:
//   - error: models.ErrNotFound if ID doesn't exist, other errors for failures
//
// SQL Query:
//
//	UPDATE credentials
//	SET title = ?, address = ?, username = ?, encrypted_password = ?, updated_at = ?
//	WHERE id = ?
//
// Side Effects:
//   - Updates the updated_at timestamp automatically
//   - FTS triggers automatically update the search index
//
// When this is called:
//   - Currently not used directly (UpdateCredentialPartial is preferred)
//   - Available for future use if full credential update is needed
func UpdateCredential(db *sql.DB, id int, title, address, username, encryptedPassword string) error {
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
	// Parameters: title, address, username, encryptedPassword, updated_at, id
	result, err := db.Exec(query, title, address, username, encryptedPassword, now, id)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	// Check how many rows were affected (updated)
	// Should be 1 if ID exists, 0 if not found
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows were affected, the ID doesn't exist
	if rowsAffected == 0 {
		return models.ErrNotFound
	}

	// Update successful
	return nil
}

// UpdateCredentialPartial updates specific fields of a credential.
//
// Purpose: Updates only the fields that are provided (non-nil pointers).
// Allows partial updates without changing all fields.
//
// Parameters:
//   - db: Active database connection
//   - id: Unique identifier of the credential to update
//   - title: New title (or nil to keep current)
//   - address: New address (or nil to keep current)
//   - username: New username (or nil to keep current)
//   - encryptedPassword: New encrypted password (or nil to keep current)
//
// Returns:
//   - error: models.ErrNotFound if ID doesn't exist, models.ErrInvalidInput if no fields provided
//
// Dynamic SQL:
//   - Builds UPDATE query dynamically based on which fields are non-nil
//   - Only updates fields that are provided
//   - Always updates updated_at timestamp
//
// Example:
//
//	UpdateCredentialPartial(db, 1, &"NewTitle", nil, nil, nil)
//	Updates only the title, leaves other fields unchanged
//
// When this is called:
//   - During "paman update <id> --title 'X' --username 'Y'"
//   - Only updates fields specified via flags
func UpdateCredentialPartial(db *sql.DB, id int, title, address, username *string, encryptedPassword *string) error {
	// Build the SET clause dynamically based on which fields are provided
	// Using pointers (*string) allows us to distinguish between "not provided" (nil)
	// and "provided empty string" (pointer to empty string)

	// Start building the SET clause (list of field = value pairs)
	setClause := ""
	sep := ""                    // Separator between clauses (comma after first one)
	finalArgs := []interface{}{} // Slice to hold query parameter values

	// Add title to SET clause if provided (non-nil)
	if title != nil {
		setClause += sep + "title = ?"
		finalArgs = append(finalArgs, *title) // Dereference pointer to get value
		sep = ", "                            // Add comma separator after first field
	}

	// Add address to SET clause if provided (non-nil)
	if address != nil {
		setClause += sep + "address = ?"
		finalArgs = append(finalArgs, *address)
		sep = ", "
	}

	// Add username to SET clause if provided (non-nil)
	if username != nil {
		setClause += sep + "username = ?"
		finalArgs = append(finalArgs, *username)
		sep = ", "
	}

	// Add encrypted_password to SET clause if provided (non-nil)
	if encryptedPassword != nil {
		setClause += sep + "encrypted_password = ?"
		finalArgs = append(finalArgs, *encryptedPassword)
		sep = ", "
	}

	// Validate that at least one field was provided for update
	if len(setClause) == 0 {
		// No fields to update - invalid input
		return models.ErrInvalidInput
	}

	// Always update the updated_at timestamp
	setClause += ", updated_at = ?"
	finalArgs = append(finalArgs, time.Now())

	// Build the complete UPDATE query
	// Combines the dynamic SET clause with the WHERE clause
	query := fmt.Sprintf("UPDATE credentials SET %s WHERE id = ?", setClause)
	finalArgs = append(finalArgs, id) // Add ID as the last parameter

	// Execute the dynamic UPDATE query
	// All parameter values are in finalArgs slice
	result, err := db.Exec(query, finalArgs...)
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
		return models.ErrNotFound
	}

	// Update successful
	return nil
}

// DeleteCredential removes a credential from the database by ID.
//
// Purpose: Permanently deletes a credential. This action cannot be undone.
// Called when users run "paman delete <id>" command.
//
// Parameters:
//   - db: Active database connection
//   - id: Unique identifier of the credential to delete
//
// Returns:
//   - error: models.ErrNotFound if ID doesn't exist, other errors for failures
//
// SQL Query:
//
//	DELETE FROM credentials WHERE id = ?
//
// Side Effects:
//   - FTS triggers automatically remove the credential from search index
//   - ID is not reused (AUTOINCREMENT counter keeps increasing)
//   - All credential data is permanently lost (cannot be undone)
//
// Security:
//   - Deletion is irreversible
//   - Users should be cautious with this command
//
// When this is called:
//   - During "paman delete <id>" command
//   - Permanently removes the credential
func DeleteCredential(db *sql.DB, id int) error {
	// SQL DELETE query with WHERE clause
	// Only deletes the row where id matches
	query := `DELETE FROM credentials WHERE id = ?`

	// Execute the DELETE query
	result, err := db.Exec(query, id)
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
		return models.ErrNotFound
	}

	// Deletion successful
	return nil
}

// CredentialExists checks if a credential with the given ID exists.
//
// Purpose: Validates credential existence before operations.
// Useful for checking if an ID is valid before attempting update/delete.
//
// Parameters:
//   - db: Active database connection
//   - id: Unique identifier to check
//
// Returns:
//   - bool: true if credential exists, false otherwise
//   - error: Error if query fails (rare)
//
// SQL Query:
//
//	SELECT COUNT(*) FROM credentials WHERE id = ?
//
// Performance:
//   - COUNT(*) is optimized by SQLite
//   - Faster than selecting the entire row
//   - Index on id makes this very fast
//
// When this is called:
//   - During "paman update" to validate the credential ID exists
//   - Could be used for validation in other commands
func CredentialExists(db *sql.DB, id int) (bool, error) {
	// SQL COUNT query to check if row exists
	// COUNT(*) returns the number of matching rows
	query := `SELECT COUNT(*) FROM credentials WHERE id = ?`

	// Execute the query and scan the count into an integer
	var count int
	err := db.QueryRow(query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check credential existence: %w", err)
	}

	// Return true if count > 0 (credential exists)
	// Return false if count == 0 (credential doesn't exist)
	return count > 0, nil
}
