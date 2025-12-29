#!/bin/bash
#
# GHOST Engagement Cleanup Script
# Securely cleans up engagement artifacts after completion
#
# Usage: ./ghost-cleanup.sh [engagement_directory]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# GHOST Banner
print_banner() {
    echo -e "${CYAN}"
    echo "   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗"
    echo "  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝"
    echo "  ██║  ███╗███████║██║   ██║███████╗   ██║   "
    echo "  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   "
    echo "  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   "
    echo "   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   "
    echo -e "${NC}"
    echo -e "${YELLOW}Engagement Cleanup Utility${NC}"
    echo ""
}

# Print status message
status() {
    echo -e "${GREEN}[+]${NC} $1"
}

# Print warning message
warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Print error message
error() {
    echo -e "${RED}[!]${NC} $1"
}

# Print info message
info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Secure delete function
secure_delete() {
    local target="$1"

    if command -v shred &> /dev/null; then
        shred -u -z -n 3 "$target" 2>/dev/null || rm -f "$target"
    else
        rm -f "$target"
    fi
}

# Secure delete directory
secure_delete_dir() {
    local dir="$1"

    if [ -d "$dir" ]; then
        # Shred all files first
        find "$dir" -type f -exec sh -c '
            if command -v shred &> /dev/null; then
                shred -u -z -n 3 "$1" 2>/dev/null || rm -f "$1"
            else
                rm -f "$1"
            fi
        ' _ {} \;

        # Remove directory structure
        rm -rf "$dir"
    fi
}

# Get engagement directory
get_engagement_dir() {
    if [ -n "$1" ]; then
        ENGAGEMENT_DIR="$1"
    else
        echo -e "${CYAN}Enter engagement directory path:${NC}"
        read -p "> " ENGAGEMENT_DIR
    fi

    # Expand path
    ENGAGEMENT_DIR=$(realpath "$ENGAGEMENT_DIR" 2>/dev/null || echo "$ENGAGEMENT_DIR")

    if [ ! -d "$ENGAGEMENT_DIR" ]; then
        error "Directory does not exist: $ENGAGEMENT_DIR"
        exit 1
    fi
}

# Verify engagement directory
verify_engagement() {
    # Check for characteristic files
    if [ ! -f "${ENGAGEMENT_DIR}/SCOPE.md" ] && [ ! -f "${ENGAGEMENT_DIR}/README.md" ]; then
        warning "This doesn't look like a GHOST engagement directory"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Show what will be deleted
preview_cleanup() {
    info "The following will be cleaned up:"
    echo ""

    # Count files
    local file_count=$(find "$ENGAGEMENT_DIR" -type f | wc -l)
    local dir_count=$(find "$ENGAGEMENT_DIR" -type d | wc -l)
    local total_size=$(du -sh "$ENGAGEMENT_DIR" 2>/dev/null | cut -f1)

    echo "  Directory: ${ENGAGEMENT_DIR}"
    echo "  Files: ${file_count}"
    echo "  Directories: ${dir_count}"
    echo "  Total size: ${total_size}"
    echo ""

    # List sensitive directories
    info "Sensitive data locations:"

    if [ -d "${ENGAGEMENT_DIR}/loot" ]; then
        echo "  - loot/ (credentials, hashes, keys)"
    fi

    if [ -d "${ENGAGEMENT_DIR}/evidence" ]; then
        echo "  - evidence/ (screenshots, logs)"
    fi

    if [ -d "${ENGAGEMENT_DIR}/exploitation" ]; then
        echo "  - exploitation/ (exploits, payloads)"
    fi

    echo ""
}

# Archive before deletion (optional)
archive_engagement() {
    local archive_name="${ENGAGEMENT_DIR}_archive_$(date +%Y%m%d_%H%M%S).tar.gz"

    read -p "Create archive before cleanup? (y/N) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        status "Creating archive: ${archive_name}"
        tar -czf "${archive_name}" -C "$(dirname "$ENGAGEMENT_DIR")" "$(basename "$ENGAGEMENT_DIR")"
        status "Archive created successfully"

        # Encrypt archive
        read -p "Encrypt archive with GPG? (y/N) " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if command -v gpg &> /dev/null; then
                gpg -c "${archive_name}"
                secure_delete "${archive_name}"
                status "Archive encrypted: ${archive_name}.gpg"
            else
                warning "GPG not found, archive left unencrypted"
            fi
        fi
    fi
}

# Cleanup sensitive files
cleanup_sensitive() {
    status "Securely deleting sensitive files..."

    # Loot directory (credentials, hashes, keys)
    if [ -d "${ENGAGEMENT_DIR}/loot" ]; then
        info "Cleaning loot directory..."
        secure_delete_dir "${ENGAGEMENT_DIR}/loot"
    fi

    # Exploitation directory
    if [ -d "${ENGAGEMENT_DIR}/exploitation" ]; then
        info "Cleaning exploitation directory..."
        secure_delete_dir "${ENGAGEMENT_DIR}/exploitation"
    fi

    # Post-exploitation directory
    if [ -d "${ENGAGEMENT_DIR}/post-exploitation" ]; then
        info "Cleaning post-exploitation directory..."
        secure_delete_dir "${ENGAGEMENT_DIR}/post-exploitation"
    fi

    # Evidence directory
    if [ -d "${ENGAGEMENT_DIR}/evidence" ]; then
        info "Cleaning evidence directory..."
        secure_delete_dir "${ENGAGEMENT_DIR}/evidence"
    fi

    # Tools directory (may contain custom exploits)
    if [ -d "${ENGAGEMENT_DIR}/tools" ]; then
        info "Cleaning tools directory..."
        secure_delete_dir "${ENGAGEMENT_DIR}/tools"
    fi

    status "Sensitive files cleaned"
}

# Full cleanup
full_cleanup() {
    status "Performing full cleanup..."
    secure_delete_dir "$ENGAGEMENT_DIR"
    status "Full cleanup complete"
}

# Clear bash history of engagement-related commands
clear_history() {
    read -p "Clear bash history entries? (y/N) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # This removes current session history
        history -c

        # Optionally clear history file
        read -p "Also clear ~/.bash_history? (y/N) " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cat /dev/null > ~/.bash_history
            status "Bash history cleared"
        fi
    fi
}

# Main cleanup function
perform_cleanup() {
    echo ""
    echo -e "${YELLOW}Select cleanup level:${NC}"
    echo "  1) Sensitive only - Delete loot, exploitation, evidence"
    echo "  2) Full cleanup   - Delete entire engagement directory"
    echo "  3) Cancel"
    echo ""

    read -p "Choice [1-3]: " choice

    case $choice in
        1)
            cleanup_sensitive
            status "Remaining files in: ${ENGAGEMENT_DIR}"
            ;;
        2)
            read -p "Are you SURE you want to delete everything? Type 'DELETE' to confirm: " confirm
            if [ "$confirm" == "DELETE" ]; then
                full_cleanup
            else
                warning "Cleanup cancelled"
                exit 0
            fi
            ;;
        3|*)
            info "Cleanup cancelled"
            exit 0
            ;;
    esac
}

# Final confirmation
final_confirm() {
    echo ""
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    warning "THIS ACTION CANNOT BE UNDONE"
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    echo ""

    read -p "Proceed with cleanup? (yes/N) " confirm

    if [ "$confirm" != "yes" ]; then
        info "Cleanup cancelled"
        exit 0
    fi
}

# Main function
main() {
    print_banner

    # Get and verify engagement directory
    get_engagement_dir "$1"
    verify_engagement

    # Show preview
    preview_cleanup

    # Offer archive
    archive_engagement

    # Final confirmation
    final_confirm

    # Perform cleanup
    perform_cleanup

    # Optionally clear history
    clear_history

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    status "Cleanup complete!"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    warning "Remember to also:"
    echo "  - Remove any cloud storage copies"
    echo "  - Clear browser history/saved passwords"
    echo "  - Remove VPN configurations"
    echo "  - Update engagement tracking system"
    echo ""
}

# Run main function
main "$@"
