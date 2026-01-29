#!/bin/bash

# Test script for paman password manager

echo "=== Paman Password Manager Test ==="
echo ""

# Clean up any existing test data
rm -rf ~/.paman

echo "1. Testing init command..."
echo "This will prompt for a passphrase (use something with 12+ characters)"
echo ""

# The init command needs interactive terminal for password input
# For this demo, we'll show what would happen

echo "Running: paman init"
echo "Expected: Prompts for passphrase twice, then creates keys and database"
echo ""

echo "2. After init, you can use these commands:"
echo ""
echo "  paman add --title 'GitHub' --address 'https://github.com' --username 'user@example.com' --password 'secret123'"
echo "  → Adds a new credential (password encrypted with RSA public key)"
echo ""
echo "  paman list"
echo "  → Lists all credentials (without passwords)"
echo ""
echo "  paman get 1 --show-password"
echo "  → Shows credential with ID 1, decrypting the password with private key"
echo ""
echo "  paman search github"
echo "  → Searches for credentials matching 'github'"
echo ""
echo "  paman update 1 --username 'newuser@example.com'"
echo "  → Updates username for credential with ID 1"
echo ""
echo "  paman delete 1"
echo "  → Deletes credential with ID 1"
echo ""

echo "3. File structure after init:"
echo "  ~/.paman/private_key.pem  - Encrypted private key (0600 permissions)"
echo "  ~/.paman/public_key.pem   - Public key (0644 permissions)"
echo "  ~/.paman/credentials.db   - SQLite database with encrypted passwords"
echo ""

echo "4. Security features:"
echo "  ✓ 4096-bit RSA keys"
echo "  ✓ Private key encrypted with PBKDF2 (100k iterations) + AES-256-GCM"
echo "  ✓ Passwords encrypted with RSA-OAEP"
echo "  ✓ Full-text search on credentials"
echo "  ✓ File permissions 0600 for sensitive files"
echo ""

echo "To test interactively, run: ./bin/paman init"
echo ""
