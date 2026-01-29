// Package db provides database connection and schema management for paman.
// It handles SQLite database operations including connection pooling and schema initialization.
//
// Database: SQLite3 (single-file embedded database)
// Location: ~/.paman/credentials.db (fixed location via config package)
// Permissions: 0600 (owner read/write only)
//
// Why SQLite?
//   - Embedded: No separate database server needed
//   - Portable: Single file that can be easily backed up
//   - Fast: Perfect for CLI application usage patterns
//   - Reliable: ACID compliant, battle-tested
//   - FTS5: Built-in full-text search support
//
// Connection Pooling:
//   - MaxOpenConns: 1 (SQLite doesn't support multiple writers)
//   - MaxIdleConns: 1 (Single connection is sufficient)
//   - This prevents write locking issues
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// schemaFS embeds the SQL schema file into the binary at compile time.
//
// Purpose: Embeds schema.sql directly into the compiled binary.
// Benefits:
//   - No external schema file needed at runtime
//   - Schema version is locked to binary version
//   - Simplifies deployment (single binary)
//   - Prevents accidental schema modifications
//
// How it works:
//   - The //go:embed directive tells Go to embed the file
//   - schemaFS becomes a virtual filesystem containing the file
//   - We can read schema.sql from this embedded filesystem
//   - Works on all platforms without any file path issues
//
//go:embed schema.sql
var schemaFS embed.FS

// OpenDatabase opens an existing SQLite database and returns a connection.
//
// Purpose: Opens a connection to an already-initialized paman database.
// This is used by all commands after the initial setup.
//
// Parameters:
//   - dbPath: Path to the SQLite database file (from config.GetDatabasePath())
//
// Returns:
//   - *sql.DB: Database connection object ready for queries
//   - error: Error if database doesn't exist or connection fails
//
// Connection Configuration:
//   - Single connection (MaxOpenConns=1)
//   - Prevents write locking issues in SQLite
//   - SQLite doesn't support multiple concurrent writers anyway
//
// When this is called:
//   - "paman add" - To insert new credentials
//   - "paman get" - To retrieve specific credentials
//   - "paman list" - To list all credentials
//   - "paman search" - To search credentials
//   - "paman update" - To modify credentials
//   - "paman delete" - To remove credentials
//
// Error Handling:
//   - Returns error if database file doesn't exist
//   - Returns error if connection cannot be established
//   - Caller should check if paman has been initialized
func OpenDatabase(dbPath string) (*sql.DB, error) {
	// Check if database file exists before attempting to open
	// This provides a clearer error message for users
	_, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Database file doesn't exist - paman not initialized
			return nil, fmt.Errorf("database not found at %s", dbPath)
		}
		// Other error (permissions, path issues, etc.)
		return nil, fmt.Errorf("failed to check database: %w", err)
	}

	// Open the SQLite database connection
	// sql.Open() doesn't actually connect here - it just prepares the connection
	// The real connection is established when we Ping() below
	// Driver name "sqlite3" is registered by the _ import above
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for SQLite
	// SQLite has limitations on concurrent writes
	// MaxOpenConns=1 ensures only one write connection at a time
	// This prevents "database is locked" errors
	db.SetMaxOpenConns(1) // SQLite doesn't support multiple writers

	// MaxIdleConns=1 keeps a single connection open
	// Reduces connection overhead for repeated queries
	// Perfect for CLI usage pattern (open, do work, close)
	db.SetMaxIdleConns(1)

	// Test the database connection
	// Ping() actually connects to the database and verifies it's accessible
	// This catches file permission errors, corruption, etc. early
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Return the ready-to-use database connection
	return db, nil
}

// CreateDatabase creates a new SQLite database with the schema and sets permissions.
//
// Purpose: Initializes a brand new paman database during "paman init".
// Creates the database file, applies the schema, and sets secure permissions.
//
// Parameters:
//   - dbPath: Path where the database should be created
//
// Returns:
//   - *sql.DB: Database connection object ready for use
//   - error: Error if database already exists or creation fails
//
// Creation Process:
//  1. Verify database doesn't already exist (prevent overwrites)
//  2. Create/open the database file (sqlite3 creates file if needed)
//  3. Configure connection pool settings
//  4. Read embedded schema.sql from binary
//  5. Execute schema to create tables and indexes
//  6. Set file permissions to 0600 (owner read/write only)
//  7. Return the database connection
//
// Security:
//   - Sets 0600 permissions (owner only, no group/other access)
//   - Critical for security - database contains encrypted passwords
//   - Even though passwords are encrypted, the file should be protected
//
// Error Cleanup:
//   - If any step fails, removes the partially created database file
//   - Prevents leaving corrupted/incomplete databases
//   - User can just run init again
//
// When this is called:
//   - During "paman init" command only
func CreateDatabase(dbPath string) (*sql.DB, error) {
	// Check if database file already exists
	// Prevents accidental overwriting of existing data
	if _, err := os.Stat(dbPath); err == nil {
		return nil, fmt.Errorf("database already exists at %s", dbPath)
	}

	// Open database connection (creates the file if it doesn't exist)
	// SQLite automatically creates the database file on first connection
	// The file will be created at dbPath with default permissions initially
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	// Configure connection pool for SQLite
	// Same settings as OpenDatabase for consistency
	// Single connection to prevent write locking issues
	db.SetMaxOpenConns(1) // SQLite doesn't support multiple writers
	db.SetMaxIdleConns(1)

	// Read the embedded schema.sql file from the binary
	// schemaFS is a virtual filesystem created by go:embed
	// ReadFile() reads schema.sql as bytes
	schemaSQL, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		// Cleanup: Remove the database file if schema read fails
		// Don't leave empty database files lying around
		db.Close()
		os.Remove(dbPath)
		return nil, fmt.Errorf("failed to read schema: %w", err)
	}

	// Execute the schema SQL to create all tables, indexes, and triggers
	// db.Exec() runs the SQL and creates the database structure
	// This creates: credentials table, indexes, FTS table, triggers
	_, err = db.Exec(string(schemaSQL))
	if err != nil {
		// Cleanup: Remove the database file if schema execution fails
		// The database file exists but schema wasn't applied properly
		db.Close()
		os.Remove(dbPath)
		return nil, fmt.Errorf("failed to execute schema: %w", err)
	}

	// Set file permissions to 0600 (owner read/write only)
	// This is CRITICAL for security
	// 0600 means: rw------- (owner can read/write, everyone else: no permission)
	// Even though passwords are encrypted, the database file should be protected
	// Without this, other users on the system could read the encrypted data
	if err := os.Chmod(dbPath, 0600); err != nil {
		// Cleanup: Remove the database file if permission setting fails
		// Database is insecure without proper permissions
		db.Close()
		os.Remove(dbPath)
		return nil, fmt.Errorf("failed to set database permissions: %w", err)
	}

	// Return the ready-to-use database connection
	// Database is now fully initialized and secured
	return db, nil
}

// CloseDatabase closes the database connection and releases resources.
//
// Purpose: Properly closes the database connection when done.
// Prevents resource leaks and ensures all data is written.
//
// Parameters:
//   - db: Database connection to close (can be nil)
//
// Returns:
//   - error: Error if closing fails (rare)
//
// Safety:
//   - Handles nil db gracefully (no-op if db is nil)
//   - Safe to call multiple times (idempotent)
//
// When to call:
//   - After all database operations are complete
//   - In defer statements (defer db.Close())
//   - Before program exit
//
// Note: Database connection should be closed even if errors occur
// defer is typically used: defer db.CloseDatabase(db)
func CloseDatabase(db *sql.DB) error {
	// Handle nil database connection gracefully
	// This prevents panics if Close() is called on a nil DB
	if db == nil {
		return nil
	}

	// Close the database connection
	// Flushes any pending writes and releases file handles
	// Returns error if close fails (e.g., during a transaction)
	return db.Close()
}
