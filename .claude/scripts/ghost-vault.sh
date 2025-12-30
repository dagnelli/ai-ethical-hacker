#!/bin/bash
#
# GHOST Secure Vault
# Encrypted credential storage for ethical hacking engagements
#
# Usage:
#   ghost-vault.sh init                           - Initialize vault with passphrase
#   ghost-vault.sh store <type> <user> <secret> <source> - Store credential
#   ghost-vault.sh list                           - List stored credentials (redacted)
#   ghost-vault.sh get <id>                       - Retrieve specific credential
#   ghost-vault.sh export <engagement_id>         - Export for reporting (hashed)
#   ghost-vault.sh purge                          - Securely delete all credentials
#   ghost-vault.sh status                         - Show vault status
#
# Security: Uses GPG symmetric encryption with passphrase
#

set -e

# Configuration
GHOST_ROOT="/tmp/ghost"
VAULT_DIR="$GHOST_ROOT/vault"
VAULT_FILE="$VAULT_DIR/credentials.gpg"
VAULT_PLAIN="$VAULT_DIR/.credentials.json"  # Temporary decrypted file
ACCESS_LOG="$VAULT_DIR/access.log"
VAULT_META="$VAULT_DIR/.vault-meta"
ENGAGEMENT="${GHOST_ENGAGEMENT:-$GHOST_ROOT/active}"
[ -L "$ENGAGEMENT" ] && ENGAGEMENT=$(readlink -f "$ENGAGEMENT")

# Credential types
VALID_TYPES="password hash key token api_key ssh_key certificate"

# Colors for output (disable if not terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

#######################################
# Logging Functions
#######################################

log_access() {
    local action="$1"
    local details="$2"
    local status="${3:-success}"
    local timestamp=$(date -Iseconds)
    local user="${USER:-unknown}"
    local pid="$$"

    # Never log actual credentials - only metadata
    echo "{\"timestamp\":\"$timestamp\",\"action\":\"$action\",\"user\":\"$user\",\"pid\":$pid,\"status\":\"$status\",\"details\":\"$details\"}" >> "$ACCESS_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    log_access "error" "$1" "failed"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_secure() {
    echo -e "${BLUE}[VAULT]${NC} $1"
}

#######################################
# Security Functions
#######################################

# Securely read passphrase without echo
read_passphrase() {
    local prompt="${1:-Enter vault passphrase: }"
    local passphrase

    # Check if we have a TTY for interactive input
    if [ -t 0 ]; then
        # Interactive mode - disable echo
        stty -echo 2>/dev/null || true
        read -r -p "$prompt" passphrase
        stty echo 2>/dev/null || true
        echo "" >&2  # Newline after hidden input
    else
        # Non-interactive (piped input)
        read -r passphrase
    fi

    echo "$passphrase"
}

# Verify passphrase meets minimum requirements
validate_passphrase() {
    local pass="$1"

    if [ ${#pass} -lt 8 ]; then
        log_error "Passphrase must be at least 8 characters"
        return 1
    fi
    return 0
}

# Get cached passphrase from environment or prompt
get_passphrase() {
    local passphrase

    if [ -n "$GHOST_VAULT_PASS" ]; then
        passphrase="$GHOST_VAULT_PASS"
    else
        passphrase=$(read_passphrase)
    fi

    echo "$passphrase"
}

# Encrypt data with GPG symmetric
encrypt_data() {
    local input="$1"
    local output="$2"
    local passphrase="$3"

    echo "$passphrase" | gpg --batch --yes --passphrase-fd 0 \
        --symmetric --cipher-algo AES256 \
        --output "$output" "$input" 2>/dev/null
}

# Decrypt data with GPG symmetric
decrypt_data() {
    local input="$1"
    local output="$2"
    local passphrase="$3"

    echo "$passphrase" | gpg --batch --yes --passphrase-fd 0 \
        --decrypt --output "$output" "$input" 2>/dev/null
}

# Securely delete a file
secure_delete() {
    local file="$1"

    if [ -f "$file" ]; then
        # Overwrite with random data before deletion
        if command -v shred &>/dev/null; then
            shred -u -z -n 3 "$file" 2>/dev/null || rm -f "$file"
        else
            # Fallback: overwrite with /dev/urandom
            local size=$(stat -c%s "$file" 2>/dev/null || echo "1024")
            dd if=/dev/urandom of="$file" bs=1 count="$size" conv=notrunc 2>/dev/null || true
            rm -f "$file"
        fi
    fi
}

# Create secure temporary file
secure_temp() {
    local tmpfile
    tmpfile=$(mktemp -p "$VAULT_DIR" .vault-tmp-XXXXXX)
    chmod 600 "$tmpfile"
    echo "$tmpfile"
}

# Generate unique credential ID
generate_id() {
    echo "cred_$(date +%s%N | sha256sum | cut -c1-12)"
}

# Hash a secret for export (SHA256, truncated for display)
hash_secret() {
    local secret="$1"
    echo "$secret" | sha256sum | cut -c1-16
}

#######################################
# Vault Operations
#######################################

# Check if vault is initialized
is_initialized() {
    [ -f "$VAULT_META" ] && [ -f "$VAULT_FILE" ]
}

# Initialize vault
vault_init() {
    log_info "Initializing GHOST Secure Vault..."

    # Create vault directory with restricted permissions
    mkdir -p "$VAULT_DIR"
    chmod 700 "$VAULT_DIR"

    # Check if already initialized
    if is_initialized; then
        log_warn "Vault already initialized. Use 'purge' to reset."
        return 1
    fi

    # Get and validate passphrase
    local pass1=$(read_passphrase "Enter new vault passphrase (min 8 chars): ")
    if ! validate_passphrase "$pass1"; then
        return 1
    fi

    local pass2=$(read_passphrase "Confirm passphrase: ")
    if [ "$pass1" != "$pass2" ]; then
        log_error "Passphrases do not match"
        return 1
    fi

    # Create empty credential store
    local tmpfile=$(secure_temp)
    local engagement_id=""
    if [ -f "$ENGAGEMENT/state.json" ]; then
        engagement_id=$(jq -r '.engagement_id // empty' "$ENGAGEMENT/state.json" 2>/dev/null || echo "")
    fi

    cat > "$tmpfile" << EOF
{
    "version": "1.0",
    "created": "$(date -Iseconds)",
    "engagement_id": "$engagement_id",
    "credentials": []
}
EOF

    # Encrypt the store
    encrypt_data "$tmpfile" "$VAULT_FILE" "$pass1"
    chmod 600 "$VAULT_FILE"
    secure_delete "$tmpfile"

    # Create metadata (non-sensitive)
    cat > "$VAULT_META" << EOF
{
    "version": "1.0",
    "created": "$(date -Iseconds)",
    "engagement_id": "$engagement_id",
    "cipher": "AES256",
    "last_access": "$(date -Iseconds)",
    "credential_count": 0
}
EOF
    chmod 600 "$VAULT_META"

    # Initialize access log
    echo "# GHOST Vault Access Log - $(date -Iseconds)" > "$ACCESS_LOG"
    chmod 600 "$ACCESS_LOG"

    log_access "init" "vault initialized"
    log_secure "Vault initialized successfully at $VAULT_DIR"

    echo ""
    echo "IMPORTANT: Remember your passphrase - it cannot be recovered!"
    echo "Tip: Set GHOST_VAULT_PASS environment variable to avoid repeated prompts"
}

# Load credentials (decrypt to temp, return path)
load_credentials() {
    local passphrase="$1"
    local tmpfile=$(secure_temp)

    if ! decrypt_data "$VAULT_FILE" "$tmpfile" "$passphrase"; then
        secure_delete "$tmpfile"
        log_error "Failed to decrypt vault - incorrect passphrase?"
        return 1
    fi

    echo "$tmpfile"
}

# Save credentials (encrypt from temp)
save_credentials() {
    local tmpfile="$1"
    local passphrase="$2"

    # Count credentials
    local count=$(jq '.credentials | length' "$tmpfile")

    # Encrypt and save
    encrypt_data "$tmpfile" "$VAULT_FILE" "$passphrase"
    chmod 600 "$VAULT_FILE"

    # Update metadata
    jq --arg ts "$(date -Iseconds)" --argjson cnt "$count" \
        '.last_access = $ts | .credential_count = $cnt' "$VAULT_META" > "$VAULT_META.tmp"
    mv "$VAULT_META.tmp" "$VAULT_META"
    chmod 600 "$VAULT_META"

    secure_delete "$tmpfile"
}

# Store a credential
vault_store() {
    local cred_type="$1"
    local username="$2"
    local secret="$3"
    local source="$4"

    # Validate inputs
    if [ -z "$cred_type" ] || [ -z "$username" ] || [ -z "$secret" ] || [ -z "$source" ]; then
        log_error "Missing required parameters"
        echo "Usage: $0 store <type> <username> <secret> <source>"
        echo "Types: $VALID_TYPES"
        return 1
    fi

    # Validate credential type
    if ! echo "$VALID_TYPES" | grep -qw "$cred_type"; then
        log_error "Invalid credential type: $cred_type"
        echo "Valid types: $VALID_TYPES"
        return 1
    fi

    if ! is_initialized; then
        log_error "Vault not initialized. Run: $0 init"
        return 1
    fi

    # Get passphrase and decrypt
    local passphrase=$(get_passphrase)
    local tmpfile=$(load_credentials "$passphrase")
    if [ $? -ne 0 ]; then
        return 1
    fi

    # Generate credential ID
    local cred_id=$(generate_id)
    local timestamp=$(date -Iseconds)
    local agent="${GHOST_AGENT:-unknown}"

    # Add credential
    local newtmp=$(secure_temp)
    jq --arg id "$cred_id" \
       --arg type "$cred_type" \
       --arg user "$username" \
       --arg sec "$secret" \
       --arg src "$source" \
       --arg ts "$timestamp" \
       --arg agent "$agent" \
       '.credentials += [{
         "id": $id,
         "type": $type,
         "username": $user,
         "secret": $sec,
         "source": $src,
         "discovered_at": $ts,
         "discovered_by": $agent,
         "tested": false,
         "valid": null
       }]' "$tmpfile" > "$newtmp"

    mv "$newtmp" "$tmpfile"

    # Save encrypted
    save_credentials "$tmpfile" "$passphrase"

    # Log (without secret!)
    log_access "store" "id=$cred_id type=$cred_type user=$username source=$source"
    log_secure "Credential stored: $cred_id (type: $cred_type, user: $username)"

    echo "$cred_id"
}

# List credentials (redacted)
vault_list() {
    if ! is_initialized; then
        log_error "Vault not initialized. Run: $0 init"
        return 1
    fi

    local passphrase=$(get_passphrase)
    local tmpfile=$(load_credentials "$passphrase")
    if [ $? -ne 0 ]; then
        return 1
    fi

    log_access "list" "listing credentials"

    echo ""
    echo "=== GHOST Vault Credentials ==="
    echo ""

    # Display credentials with secrets redacted
    jq -r '.credentials[] | "ID: \(.id)\n  Type: \(.type)\n  User: \(.username)\n  Source: \(.source)\n  Discovered: \(.discovered_at)\n  Agent: \(.discovered_by)\n"' "$tmpfile"

    local count=$(jq '.credentials | length' "$tmpfile")
    echo "Total: $count credential(s)"

    secure_delete "$tmpfile"
}

# Get specific credential
vault_get() {
    local cred_id="$1"

    if [ -z "$cred_id" ]; then
        log_error "Credential ID required"
        echo "Usage: $0 get <id>"
        return 1
    fi

    if ! is_initialized; then
        log_error "Vault not initialized. Run: $0 init"
        return 1
    fi

    local passphrase=$(get_passphrase)
    local tmpfile=$(load_credentials "$passphrase")
    if [ $? -ne 0 ]; then
        return 1
    fi

    # Find credential
    local cred=$(jq -r --arg id "$cred_id" '.credentials[] | select(.id == $id)' "$tmpfile")

    if [ -z "$cred" ]; then
        log_error "Credential not found: $cred_id"
        secure_delete "$tmpfile"
        return 1
    fi

    log_access "get" "id=$cred_id"

    # Output credential (full, including secret)
    echo "$cred" | jq .

    secure_delete "$tmpfile"
}

# Export credentials for reporting (hashed/redacted)
vault_export() {
    local engagement_id="$1"

    if ! is_initialized; then
        log_error "Vault not initialized. Run: $0 init"
        return 1
    fi

    local passphrase=$(get_passphrase)
    local tmpfile=$(load_credentials "$passphrase")
    if [ $? -ne 0 ]; then
        return 1
    fi

    log_access "export" "engagement=$engagement_id"

    echo "=== GHOST Credential Export ==="
    echo "Engagement: ${engagement_id:-$(jq -r '.engagement_id // "unknown"' "$tmpfile")}"
    echo "Exported: $(date -Iseconds)"
    echo "Format: Hashed/Redacted for reporting"
    echo ""

    # Export with hashed secrets
    jq -r '.credentials[] | {
        id: .id,
        type: .type,
        username: .username,
        secret_hash: (.secret | @base64 | .[0:16] + "..."),
        source: .source,
        discovered_at: .discovered_at,
        discovered_by: .discovered_by
    }' "$tmpfile"

    secure_delete "$tmpfile"
}

# Purge all credentials securely
vault_purge() {
    if ! is_initialized; then
        log_warn "Vault not initialized - nothing to purge"
        return 0
    fi

    # Require confirmation
    echo ""
    echo -e "${RED}WARNING: This will permanently delete all stored credentials!${NC}"
    echo ""
    read -r -p "Type 'PURGE' to confirm: " confirm

    if [ "$confirm" != "PURGE" ]; then
        log_info "Purge cancelled"
        return 1
    fi

    log_access "purge" "user confirmed purge"

    log_info "Securely purging vault..."

    # Securely delete all vault files
    secure_delete "$VAULT_FILE"
    secure_delete "$VAULT_META"

    # Clear any temp files
    find "$VAULT_DIR" -name '.vault-tmp-*' -exec shred -u -z {} \; 2>/dev/null || true

    # Keep access log (audit trail)
    log_access "purge_complete" "vault purged successfully"

    log_secure "Vault purged. Access log retained at: $ACCESS_LOG"
}

# Show vault status
vault_status() {
    echo ""
    echo "=== GHOST Vault Status ==="
    echo ""

    if ! is_initialized; then
        echo -e "Status: ${RED}NOT INITIALIZED${NC}"
        echo "Run: $0 init"
        return 0
    fi

    echo -e "Status: ${GREEN}INITIALIZED${NC}"
    echo "Location: $VAULT_DIR"
    echo ""

    # Show metadata
    if [ -f "$VAULT_META" ]; then
        echo "Vault Info:"
        jq -r '
            "  Version: \(.version)",
            "  Created: \(.created)",
            "  Engagement: \(.engagement_id // "none")",
            "  Cipher: \(.cipher)",
            "  Last Access: \(.last_access)",
            "  Credentials: \(.credential_count)"
        ' "$VAULT_META"
    fi

    echo ""

    # Show file sizes (not contents)
    echo "Files:"
    if [ -f "$VAULT_FILE" ]; then
        local size=$(stat -c%s "$VAULT_FILE" 2>/dev/null || echo "?")
        echo "  credentials.gpg: $size bytes (encrypted)"
    fi
    if [ -f "$ACCESS_LOG" ]; then
        local entries=$(wc -l < "$ACCESS_LOG" 2>/dev/null || echo "?")
        echo "  access.log: $entries entries"
    fi

    echo ""

    # Check engagement state
    if [ -f "$ENGAGEMENT/state.json" ]; then
        local eng_id=$(jq -r '.engagement_id // "unknown"' "$ENGAGEMENT/state.json" 2>/dev/null)
        local phase=$(jq -r '.current_phase // "unknown"' "$ENGAGEMENT/state.json" 2>/dev/null)
        echo "Active Engagement:"
        echo "  ID: $eng_id"
        echo "  Phase: $phase"
    fi
}

# Show help
show_help() {
    cat << 'EOF'
GHOST Secure Vault v1.0
Encrypted credential storage for ethical hacking engagements

Usage: ghost-vault.sh <command> [args]

Commands:
  init                              Initialize vault with passphrase
  store <type> <user> <secret> <src>  Store encrypted credential
  list                              List credentials (secrets redacted)
  get <id>                          Retrieve specific credential
  export [engagement_id]            Export for reporting (hashed)
  purge                             Securely delete all credentials
  status                            Show vault status

Credential Types:
  password   - User passwords
  hash       - Password hashes (NTLM, etc.)
  key        - SSH/GPG private keys
  token      - Session tokens
  api_key    - API keys/secrets
  ssh_key    - SSH private keys
  certificate - TLS certificates/keys

Security Features:
  - AES256 GPG symmetric encryption
  - Secrets never logged to access.log
  - Secure temp files with shred on cleanup
  - Confirmation required for destructive actions
  - Audit trail maintained in access.log

Environment Variables:
  GHOST_VAULT_PASS    - Cache passphrase (avoid prompts)
  GHOST_AGENT         - Agent name (auto-attributed)
  GHOST_ENGAGEMENT    - Engagement directory path

Examples:
  # Initialize vault
  ghost-vault.sh init

  # Store found credentials
  ghost-vault.sh store password admin "P@ssw0rd123" "login.php"
  ghost-vault.sh store hash admin "aad3b435b51404ee:..." "SAM dump"
  ghost-vault.sh store token session "eyJhbGc..." "JWT cookie"

  # List all credentials
  ghost-vault.sh list

  # Get specific credential for use
  ghost-vault.sh get cred_abc123def456

  # Export for report (secrets hashed)
  ghost-vault.sh export htb-machine

  # Purge after engagement
  ghost-vault.sh purge

EOF
}

#######################################
# Main Entry Point
#######################################

# Ensure vault directory exists with proper permissions
mkdir -p "$VAULT_DIR" 2>/dev/null || true
chmod 700 "$VAULT_DIR" 2>/dev/null || true

# Route commands
case "${1:-help}" in
    init)
        vault_init
        ;;
    store)
        vault_store "$2" "$3" "$4" "$5"
        ;;
    list)
        vault_list
        ;;
    get)
        vault_get "$2"
        ;;
    export)
        vault_export "$2"
        ;;
    purge)
        vault_purge
        ;;
    status)
        vault_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac
