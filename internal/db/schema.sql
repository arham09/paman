-- ============================================================================
-- Paman Password Manager Database Schema
-- ============================================================================
-- This SQL schema defines the structure for storing encrypted credentials.
--
-- Database: SQLite (credentials.db in ~/.paman/)
-- File Permissions: 0600 (owner read/write only)
--
-- Security Architecture:
--   - Passwords are encrypted with RSA-4096-OAEP before storage
--   - encrypted_password column contains Base64-encoded encrypted data
--   - Without the private key, passwords are undecipherable
--   - Even with full database access, passwords remain safe
--
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Main Credentials Table
-- ----------------------------------------------------------------------------
-- Purpose: Stores all user credentials with encrypted passwords
--
-- Columns:
--   - id: Unique auto-increment identifier (primary key)
--   - title: Credential name/title (indexed, required)
--   - address: Optional URL/address of the service
--   - username: User's email/username (indexed, required)
--   - encrypted_password: RSA-encrypted password (Base64 encoded, required)
--   - created_at: Timestamp when credential was created
--   - updated_at: Timestamp when credential was last modified
--
-- Security Note:
--   - encrypted_password is TEXT type storing Base64-encoded RSA-OAEP encrypted data
--   - This column is indexed for search but contains only encrypted data
--   - Actual passwords never touch the disk in plaintext form
--
-- Usage:
--   - INSERT: Adding new credentials (via "paman add")
--   - SELECT: Retrieving credentials (via "paman get", "paman list")
--   - UPDATE: Modifying credentials (via "paman update")
--   - DELETE: Removing credentials (via "paman delete")
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS credentials (
    -- Primary key: Auto-incrementing unique identifier
    -- Used to reference specific credentials in CLI commands
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Title: Name/identifier for the credential (e.g., "GitHub", "Gmail")
    -- NOT NULL constraint ensures every credential has a title
    -- Indexed for faster searching and sorting
    title TEXT NOT NULL,

    -- Address: Optional URL/location of the service (e.g., "https://github.com")
    -- Can be NULL (not required)
    -- Useful for remembering where credentials are used
    address TEXT,

    -- Username: User's identifier for the service (email or username)
    -- NOT NULL constraint ensures every credential has a username
    -- Indexed for faster searching
    username TEXT NOT NULL,

    -- Encrypted Password: RSA-4096-OAEP encrypted password (Base64 encoded)
    -- NOT NULL constraint ensures password is always provided
    -- TEXT type stores Base64 string (e.g., "R2V... encryption...")
    -- CANNOT be decrypted without the private key
    encrypted_password TEXT NOT NULL,

    -- Created At: Automatic timestamp of credential creation
    -- Uses CURRENT_TIMESTAMP which is UTC time in SQLite
    -- Set once when row is created, never changes
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Updated At: Automatic timestamp of last modification
    -- Updated by application code whenever credential changes
    -- Allows users to track when they last modified credentials
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Indexes for Performance
-- ----------------------------------------------------------------------------
-- Purpose: Speed up common queries on frequently searched columns
--
-- Performance Impact:
--   - Faster SELECT queries with WHERE clauses on title or username
--   - Slightly slower INSERT/UPDATE/DELETE (index must be maintained)
--   - Net benefit for read-heavy workloads (password managers are read-heavy)
--
-- Query Examples that benefit from indexes:
--   - SELECT * FROM credentials WHERE title LIKE '%github%'
--   - SELECT * FROM credentials WHERE username = 'user@example.com'
-- ----------------------------------------------------------------------------

-- Index on title column for faster title-based searches
-- Useful when users search by service name or title
CREATE INDEX IF NOT EXISTS idx_title ON credentials(title);

-- Index on username column for faster username-based searches
-- Useful when users search by email or username
CREATE INDEX IF NOT EXISTS idx_username ON credentials(username);

-- ----------------------------------------------------------------------------
-- Full-Text Search (FTS5) Virtual Table
-- ----------------------------------------------------------------------------
-- Purpose: Provides fast, flexible full-text search across multiple columns
--
-- FTS5 Features:
--   - Case-insensitive search
--   - Prefix matching (e.g., "git*" matches "github")
--   - Phrase search (e.g., '"work email"')
--   - Boolean operators (AND, OR, NOT)
--   - Relevance ranking (results sorted by relevance)
--
-- How it works:
--   - FTS5 creates a separate inverted index for fast text search
--   - Automatically tokenizes text into words
--   - Maintains its own index separate from main table
--   - Triggers keep it in sync with main table
--
-- Usage:
--   - Search via "paman search <query>"
--   - Example: "paman search github" matches title, address, or username
--
-- Performance:
--   - Much faster than LIKE queries on large datasets
--   - Scales well to thousands of credentials
-- ----------------------------------------------------------------------------

CREATE VIRTUAL TABLE IF NOT EXISTS credentials_fts USING fts5(
    -- Columns to include in full-text search index
    -- These are the columns users can search across
    title,
    address,
    username,

    -- External content configuration:
    -- FTS table stays in sync with the main credentials table
    -- content='credentials' specifies the source table
    -- content_rowid='id' links FTS rows to credential IDs
    content='credentials',
    content_rowid='id'
);

-- ----------------------------------------------------------------------------
-- Triggers for FTS Synchronization
-- ----------------------------------------------------------------------------
-- Purpose: Automatically keep the FTS index in sync with the main table
--
-- Why triggers?
--   - Ensure FTS index always matches credential data
--   - No manual index maintenance needed
--   - Automatic update on every INSERT/UPDATE/DELETE
--
-- Trigger Types:
--   1. INSERT (ai): Add new entries to FTS when credentials are created
--   2. DELETE (ad): Remove entries from FTS when credentials are deleted
--   3. UPDATE (au): Update FTS entries when credentials are modified
--
-- Naming Convention:
--   - ai: After Insert
--   - ad: After Delete
--   - au: After Update
-- ----------------------------------------------------------------------------

-- Trigger: After Insert
-- Fires: When a new row is inserted into credentials table
-- Action: Inserts corresponding row into FTS index
-- Purpose: Makes new credentials immediately searchable
CREATE TRIGGER IF NOT EXISTS credentials_ai AFTER INSERT ON credentials BEGIN
    INSERT INTO credentials_fts(rowid, title, address, username)
    VALUES (new.id, new.title, new.address, new.username);
END;

-- Trigger: After Delete
-- Fires: When a row is deleted from credentials table
-- Action: Removes corresponding row from FTS index
-- Purpose: Removes deleted credentials from search results
-- Note: FTS5 uses special 'delete' command for removal
CREATE TRIGGER IF NOT EXISTS credentials_ad AFTER DELETE ON credentials BEGIN
    INSERT INTO credentials_fts(credentials_fts, rowid, title, address, username)
    VALUES ('delete', old.id, old.title, old.address, old.username);
END;

-- Trigger: After Update
-- Fires: When a row in credentials table is updated
-- Action: Deletes old FTS entry and inserts new one
-- Purpose: Updates FTS index when credential data changes
-- Reason: FTS5 doesn't have UPDATE, must delete + insert
CREATE TRIGGER IF NOT EXISTS credentials_au AFTER UPDATE ON credentials BEGIN
    -- Remove the old indexed data
    INSERT INTO credentials_fts(credentials_fts, rowid, title, address, username)
    VALUES ('delete', old.id, old.title, old.address, old.username);

    -- Insert the new indexed data
    INSERT INTO credentials_fts(rowid, title, address, username)
    VALUES (new.id, new.title, new.address, new.username);
END;
