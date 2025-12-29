#!/bin/bash
#
# GHOST Engagement Initialization Script
# Creates workspace structure for new penetration testing engagement
#
# Usage: ./ghost-init.sh [engagement_name]
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
    echo -e "${YELLOW}Guided Hacking Operations & Security Testing${NC}"
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

# Get engagement name
get_engagement_name() {
    if [ -n "$1" ]; then
        ENGAGEMENT_NAME="$1"
    else
        echo -e "${CYAN}Enter engagement name:${NC}"
        read -p "> " ENGAGEMENT_NAME
    fi

    # Sanitize name
    ENGAGEMENT_NAME=$(echo "$ENGAGEMENT_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')

    if [ -z "$ENGAGEMENT_NAME" ]; then
        error "Engagement name cannot be empty"
        exit 1
    fi
}

# Create directory structure
create_directories() {
    local BASE_DIR="${ENGAGEMENT_DIR}"

    status "Creating engagement directory structure..."

    mkdir -p "${BASE_DIR}/recon"
    mkdir -p "${BASE_DIR}/enumeration"
    mkdir -p "${BASE_DIR}/exploitation"
    mkdir -p "${BASE_DIR}/post-exploitation"
    mkdir -p "${BASE_DIR}/evidence/screenshots"
    mkdir -p "${BASE_DIR}/evidence/logs"
    mkdir -p "${BASE_DIR}/evidence/requests"
    mkdir -p "${BASE_DIR}/loot/credentials"
    mkdir -p "${BASE_DIR}/loot/hashes"
    mkdir -p "${BASE_DIR}/loot/keys"
    mkdir -p "${BASE_DIR}/tools"
    mkdir -p "${BASE_DIR}/reports"
    mkdir -p "${BASE_DIR}/notes"

    status "Directory structure created"
}

# Create scope document
create_scope_doc() {
    local SCOPE_FILE="${ENGAGEMENT_DIR}/SCOPE.md"

    status "Creating scope document..."

    cat > "${SCOPE_FILE}" << 'EOF'
# Engagement Scope Document

## Engagement Information

| Field | Value |
|-------|-------|
| **Engagement Name** | [NAME] |
| **Client** | [CLIENT] |
| **Start Date** | [DATE] |
| **End Date** | [DATE] |
| **Tester** | [TESTER] |

## Authorization

- [ ] Written authorization received
- [ ] Scope document signed
- [ ] Rules of engagement agreed
- [ ] Emergency contacts documented

## In-Scope Assets

### IP Ranges
```
[Enter IP ranges]
```

### Domains
```
[Enter domains]
```

### Web Applications
```
[Enter web applications]
```

### APIs
```
[Enter APIs]
```

## Out-of-Scope

```
[Enter out-of-scope assets]
```

## Testing Restrictions

- [ ] Testing hours: [HOURS]
- [ ] Prohibited techniques: [TECHNIQUES]
- [ ] Rate limiting: [LIMITS]

## Emergency Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Client Contact | | | |
| Technical Contact | | | |
| Emergency | | | |

## Rules of Engagement

1. [ ] No denial of service attacks
2. [ ] No social engineering without approval
3. [ ] No data exfiltration beyond PoC
4. [ ] Immediate notification of critical findings
5. [ ] [Additional rules]

---

**Signature**: _________________________ **Date**: _____________
EOF

    # Replace placeholder with engagement name
    sed -i "s/\[NAME\]/${ENGAGEMENT_NAME}/" "${SCOPE_FILE}"
    sed -i "s/\[DATE\]/$(date +%Y-%m-%d)/" "${SCOPE_FILE}"

    status "Scope document created: ${SCOPE_FILE}"
}

# Create notes template
create_notes() {
    local NOTES_FILE="${ENGAGEMENT_DIR}/notes/engagement-notes.md"

    status "Creating notes template..."

    cat > "${NOTES_FILE}" << 'EOF'
# Engagement Notes

## Quick Reference

| Item | Value |
|------|-------|
| Target | |
| Current Phase | Recon |
| Priority Findings | |

## Timeline

### [DATE]
- [ ] Started engagement
- [ ] Initial reconnaissance
- [ ]

## Findings Log

### Critical

### High

### Medium

### Low

## Credentials Discovered

| Username | Password/Hash | Source | Service |
|----------|---------------|--------|---------|
| | | | |

## Access Achieved

| System | Access Level | Method |
|--------|--------------|--------|
| | | |

## Todo

- [ ]
- [ ]
- [ ]

## Questions/Blockers

-

## Daily Summary

### Day 1
**Progress**:
**Findings**:
**Next Steps**:

EOF

    sed -i "s/\[DATE\]/$(date +%Y-%m-%d)/" "${NOTES_FILE}"

    status "Notes template created"
}

# Create README
create_readme() {
    local README="${ENGAGEMENT_DIR}/README.md"

    cat > "${README}" << EOF
# ${ENGAGEMENT_NAME}

**Created**: $(date +%Y-%m-%d)
**Status**: Active

## Quick Links

- [Scope Document](SCOPE.md)
- [Engagement Notes](notes/engagement-notes.md)
- [Evidence](evidence/)
- [Reports](reports/)

## Directory Structure

\`\`\`
${ENGAGEMENT_NAME}/
├── recon/              # Reconnaissance data
├── enumeration/        # Service/application enumeration
├── exploitation/       # Exploitation attempts and PoCs
├── post-exploitation/  # Post-exploitation activities
├── evidence/           # Screenshots, logs, requests
│   ├── screenshots/
│   ├── logs/
│   └── requests/
├── loot/               # Credentials, hashes, keys
│   ├── credentials/
│   ├── hashes/
│   └── keys/
├── tools/              # Custom tools and scripts
├── reports/            # Final deliverables
└── notes/              # Running notes
\`\`\`

## Workflow

1. Review SCOPE.md - Verify authorization
2. Start recon with @SHADOW
3. Document findings in notes/
4. Save evidence appropriately
5. Generate report with @SCRIBE

---

*GHOST - Guided Hacking Operations & Security Testing*
EOF

    status "README created"
}

# Main function
main() {
    print_banner

    # Get engagement name
    get_engagement_name "$1"

    # Set engagement directory
    ENGAGEMENT_DIR="${PWD}/${ENGAGEMENT_NAME}"

    # Check if directory exists
    if [ -d "${ENGAGEMENT_DIR}" ]; then
        warning "Directory ${ENGAGEMENT_DIR} already exists"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    info "Initializing engagement: ${ENGAGEMENT_NAME}"
    info "Location: ${ENGAGEMENT_DIR}"
    echo ""

    # Create structure
    create_directories
    create_scope_doc
    create_notes
    create_readme

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    status "Engagement workspace initialized successfully!"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    info "Next steps:"
    echo "  1. cd ${ENGAGEMENT_NAME}"
    echo "  2. Edit SCOPE.md with engagement details"
    echo "  3. Begin with @COMMAND to start the assessment"
    echo ""
    warning "Remember: Verify authorization before ANY testing!"
    echo ""
}

# Run main function
main "$@"
