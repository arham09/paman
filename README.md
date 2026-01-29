# Paman - Password Manager

A secure CLI password manager written in Go with RSA-4096 encryption and SQLite storage.

## Features

- **RSA-4096 Encryption**: All passwords encrypted using RSA-OAEP
- **Encrypted Private Key**: Private key protected with PBKDF2 (100k iterations) + AES-256-GCM
- **SQLite Storage**: Fast, embedded database with full-text search
- **Secure by Default**: 0600 permissions on sensitive files
- **Full-Text Search**: Search across title, address, and username fields

## Installation

```bash
go build -o paman ./cmd/paman
```

## Usage

### Initialize

First time setup generates RSA keys and creates the database:

```bash
./paman init
```

You'll be prompted for a passphrase (minimum 12 characters). This passphrase encrypts your private key.

### Add Credential

```bash
./paman add --title "GitHub" \
  --address "https://github.com" \
  --username "user@example.com" \
  --password "secret123"
```

### List All Credentials

```bash
./paman list
```

### Get Specific Credential

```bash
./paman get 1 --show-password
```

### Search Credentials

```bash
./paman search github
```

### Update Credential

```bash
./paman update 1 --username "newuser@example.com"
```

### Delete Credential

```bash
./paman delete 1
```

## Project Structure

```
.
├── cmd/paman/main.go              # Entry point
├── internal/
│   ├── cli/                       # CLI commands
│   │   ├── root.go               # Root command
│   │   ├── init.go               # Initialize keys & database
│   │   ├── add.go                # Add credential
│   │   ├── get.go                # Get credential
│   │   ├── list.go               # List all
│   │   ├── search.go             # Search credentials
│   │   ├── update.go             # Update credential
│   │   ├── delete.go             # Delete credential
│   │   └── utils.go              # Helper functions
│   ├── crypto/                    # Cryptography
│   │   ├── rsa.go                # RSA key generation
│   │   ├── keys.go               # Key storage (encrypted)
│   │   ├── encrypt.go            # Password encryption
│   │   └── decrypt.go            # Password decryption
│   ├── db/                        # Database
│   │   ├── sqlite.go             # Connection management
│   │   ├── schema.sql            # Database schema
│   │   └── credentials.go        # CRUD operations
│   └── models/                    # Data models
│       ├── credential.go         # Credential structures
│       └── errors.go             # Custom errors
└── pkg/config/                    # Configuration
    └── paths.go                  # Path resolution
```

## Security Architecture

### Key Storage
- **Location**: `~/.paman/`
- **Private Key**: Encrypted with passphrase (0600 permissions)
- **Public Key**: Stored unencrypted (0644 permissions)
- **Passphrase**: Never stored, only used to derive encryption key

### Encryption Flow
1. **Add Credential**:
   - Password → RSA-OAEP (public key) → Base64 → SQLite
2. **Get Credential**:
   - SQLite → Base64 → RSA-OAEP (private key) → Password
3. **Private Key Protection**:
   - Passphrase → PBKDF2-SHA256 (100k iterations) → AES-256-GCM key

### Database Schema
```sql
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    address TEXT,
    username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE VIRTUAL TABLE credentials_fts USING fts5(
    title, address, username
);
```

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- `github.com/mattn/go-sqlite3` - SQLite driver
- `golang.org/x/term` - Secure terminal input
- `golang.org/x/crypto` - PBKDF2 key derivation

## License

MIT License
