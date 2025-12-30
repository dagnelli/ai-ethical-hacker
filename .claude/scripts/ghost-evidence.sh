#!/bin/bash
#
# GHOST Evidence Auto-Capture
# Automatically captures and organizes evidence during engagements
#
# Usage:
#   ghost-evidence.sh screenshot <name> [description]   - Capture screenshot
#   ghost-evidence.sh request <name> <file>             - Store HTTP request/response
#   ghost-evidence.sh output <name> <command>           - Capture command output
#   ghost-evidence.sh link <finding_id> <evidence_file> - Link evidence to finding
#   ghost-evidence.sh list                              - List all evidence
#

set -e

GHOST_ROOT="/tmp/ghost"
ENGAGEMENT="${GHOST_ENGAGEMENT:-$GHOST_ROOT/active}"
[ -L "$ENGAGEMENT" ] && ENGAGEMENT=$(readlink -f "$ENGAGEMENT")

EVIDENCE_DIR="$ENGAGEMENT/evidence"
FINDINGS_FILE="$ENGAGEMENT/findings.json"
RUNLOG="$ENGAGEMENT/runlog.jsonl"

# Agent-specific evidence dir
AGENT="${GHOST_AGENT:-manual}"
HUNTER_EVIDENCE="$ENGAGEMENT/hunters/$AGENT/evidence"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_event() {
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"$1\",$2}" >> "$RUNLOG"
}

# Ensure evidence directories exist
ensure_dirs() {
    mkdir -p "$EVIDENCE_DIR/screenshots"
    mkdir -p "$EVIDENCE_DIR/requests"
    mkdir -p "$EVIDENCE_DIR/outputs"
    mkdir -p "$HUNTER_EVIDENCE" 2>/dev/null || true
}

# Generate evidence ID
gen_evidence_id() {
    echo "evidence_$(date +%s%N | cut -c1-13)"
}

# Capture screenshot (if display available)
capture_screenshot() {
    local name="$1"
    local description="${2:-}"
    local evidence_id=$(gen_evidence_id)
    local filename="${evidence_id}_${name}.png"
    local filepath="$EVIDENCE_DIR/screenshots/$filename"

    ensure_dirs

    # Try different screenshot methods
    if command -v scrot &>/dev/null; then
        scrot "$filepath"
    elif command -v gnome-screenshot &>/dev/null; then
        gnome-screenshot -f "$filepath"
    elif command -v import &>/dev/null; then
        import -window root "$filepath"
    else
        echo "No screenshot tool available (install scrot, gnome-screenshot, or imagemagick)"
        echo "Saving placeholder..."
        echo "Screenshot placeholder: $name - $description" > "${filepath%.png}.txt"
        filepath="${filepath%.png}.txt"
    fi

    echo -e "${GREEN}[+]${NC} Screenshot saved: $filepath"
    log_event "evidence_captured" "\"type\":\"screenshot\",\"id\":\"$evidence_id\",\"file\":\"$filename\""

    echo "$filepath"
}

# Store HTTP request/response
store_request() {
    local name="$1"
    local source_file="$2"
    local evidence_id=$(gen_evidence_id)
    local filename="${evidence_id}_${name}.txt"
    local filepath="$EVIDENCE_DIR/requests/$filename"

    ensure_dirs

    if [ -f "$source_file" ]; then
        cp "$source_file" "$filepath"
    elif [ -p /dev/stdin ]; then
        cat > "$filepath"
    else
        echo "Provide file path or pipe content"
        exit 1
    fi

    echo -e "${GREEN}[+]${NC} Request stored: $filepath"
    log_event "evidence_captured" "\"type\":\"request\",\"id\":\"$evidence_id\",\"file\":\"$filename\""

    echo "$filepath"
}

# Capture command output
capture_output() {
    local name="$1"
    shift
    local command="$*"
    local evidence_id=$(gen_evidence_id)
    local filename="${evidence_id}_${name}.txt"
    local filepath="$EVIDENCE_DIR/outputs/$filename"

    ensure_dirs

    {
        echo "# Command: $command"
        echo "# Captured: $(date -Iseconds)"
        echo "# Agent: $AGENT"
        echo "---"
        echo ""
        eval "$command" 2>&1
    } > "$filepath"

    echo -e "${GREEN}[+]${NC} Output captured: $filepath"
    log_event "evidence_captured" "\"type\":\"output\",\"id\":\"$evidence_id\",\"command\":\"$(echo "$command" | head -c 100)\""

    echo "$filepath"
}

# Capture output from stdin
capture_stdin() {
    local name="$1"
    local description="${2:-}"
    local evidence_id=$(gen_evidence_id)
    local filename="${evidence_id}_${name}.txt"
    local filepath="$EVIDENCE_DIR/outputs/$filename"

    ensure_dirs

    {
        echo "# Evidence: $name"
        echo "# Description: $description"
        echo "# Captured: $(date -Iseconds)"
        echo "# Agent: $AGENT"
        echo "---"
        echo ""
        cat
    } > "$filepath"

    echo -e "${GREEN}[+]${NC} Evidence captured: $filepath"
    log_event "evidence_captured" "\"type\":\"stdin\",\"id\":\"$evidence_id\",\"name\":\"$name\""

    echo "$filepath"
}

# Link evidence to a finding
link_evidence() {
    local finding_id="$1"
    local evidence_file="$2"

    if [ ! -f "$evidence_file" ]; then
        echo "Evidence file not found: $evidence_file"
        exit 1
    fi

    # Add to finding's evidence array
    local tmp=$(mktemp)
    local rel_path=$(realpath --relative-to="$ENGAGEMENT" "$evidence_file")

    jq --arg fid "$finding_id" --arg efile "$rel_path" '
        .findings = [.findings[] |
            if .id == $fid then
                .evidence += [$efile]
            else
                .
            end
        ]
    ' "$FINDINGS_FILE" > "$tmp"
    mv "$tmp" "$FINDINGS_FILE"

    echo -e "${GREEN}[+]${NC} Linked $evidence_file to finding $finding_id"
    log_event "evidence_linked" "\"finding\":\"$finding_id\",\"file\":\"$rel_path\""
}

# List all evidence
list_evidence() {
    echo -e "${CYAN}Evidence Files:${NC}"
    echo ""

    echo "Screenshots:"
    ls -la "$EVIDENCE_DIR/screenshots" 2>/dev/null || echo "  (none)"
    echo ""

    echo "HTTP Requests:"
    ls -la "$EVIDENCE_DIR/requests" 2>/dev/null || echo "  (none)"
    echo ""

    echo "Command Outputs:"
    ls -la "$EVIDENCE_DIR/outputs" 2>/dev/null || echo "  (none)"
    echo ""

    # Hunter-specific evidence
    if [ -d "$ENGAGEMENT/hunters" ]; then
        echo "Hunter Evidence:"
        for hunter_dir in "$ENGAGEMENT/hunters"/*/evidence; do
            [ -d "$hunter_dir" ] || continue
            local hunter=$(basename "$(dirname "$hunter_dir")")
            local count=$(ls -1 "$hunter_dir" 2>/dev/null | wc -l)
            echo "  $hunter: $count files"
        done
    fi
}

# Collect all evidence into single directory
collect_all() {
    local output_dir="${1:-$ENGAGEMENT/evidence-collection}"
    mkdir -p "$output_dir"

    echo "Collecting all evidence to $output_dir..."

    # Copy main evidence
    cp -r "$EVIDENCE_DIR"/* "$output_dir/" 2>/dev/null || true

    # Copy hunter evidence
    for hunter_dir in "$ENGAGEMENT/hunters"/*/evidence; do
        [ -d "$hunter_dir" ] || continue
        local hunter=$(basename "$(dirname "$hunter_dir")")
        mkdir -p "$output_dir/hunters/$hunter"
        cp -r "$hunter_dir"/* "$output_dir/hunters/$hunter/" 2>/dev/null || true
    done

    echo -e "${GREEN}[+]${NC} Evidence collected to: $output_dir"
    log_event "evidence_collected" "\"output_dir\":\"$output_dir\""
}

# Main
case "${1:-help}" in
    screenshot|ss)
        [ -z "$2" ] && { echo "Usage: $0 screenshot <name> [description]"; exit 1; }
        capture_screenshot "$2" "${3:-}"
        ;;
    request|req)
        [ -z "$2" ] && { echo "Usage: $0 request <name> <file>"; exit 1; }
        store_request "$2" "${3:-/dev/stdin}"
        ;;
    output|cmd)
        [ -z "$2" ] && { echo "Usage: $0 output <name> <command>"; exit 1; }
        name="$2"
        shift 2
        capture_output "$name" "$@"
        ;;
    stdin|pipe)
        [ -z "$2" ] && { echo "Usage: $0 stdin <name> [description]"; exit 1; }
        capture_stdin "$2" "${3:-}"
        ;;
    link)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 link <finding_id> <evidence_file>"; exit 1; }
        link_evidence "$2" "$3"
        ;;
    list|ls)
        list_evidence
        ;;
    collect)
        collect_all "$2"
        ;;
    *)
        echo "GHOST Evidence Auto-Capture"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  screenshot <name> [desc]    - Capture screenshot"
        echo "  request <name> [file]       - Store HTTP request (pipe or file)"
        echo "  output <name> <command>     - Capture command output"
        echo "  stdin <name> [desc]         - Capture from stdin"
        echo "  link <finding_id> <file>    - Link evidence to finding"
        echo "  list                        - List all evidence"
        echo "  collect [dir]               - Collect all evidence"
        echo ""
        echo "Environment:"
        echo "  GHOST_ENGAGEMENT - Engagement directory"
        echo "  GHOST_AGENT      - Current agent name"
        echo ""
        echo "Examples:"
        echo "  $0 screenshot sqli-poc \"SQL injection proof\""
        echo "  curl -v http://target | $0 stdin bola-test \"BOLA PoC\""
        echo "  $0 output nmap-scan nmap -sC -sV \$TARGET"
        echo "  $0 link finding_123456 evidence/outputs/sqli.txt"
        ;;
esac
