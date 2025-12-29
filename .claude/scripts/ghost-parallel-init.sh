#!/bin/bash
#
# GHOST Parallel Mode Initialization
# Sets up /tmp/ghost structure for hunter-gather operations
#
# Usage: ./ghost-parallel-init.sh <engagement_name> [target]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

GHOST_ROOT="/tmp/ghost"
ENGAGEMENT_NAME="${1:-$(date +%Y%m%d_%H%M%S)}"
TARGET="${2:-}"

print_banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║     GHOST PARALLEL MODE - Hunter/Gather Init      ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

status() { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

# Create base structure
init_ghost_root() {
    if [ ! -d "$GHOST_ROOT" ]; then
        status "Creating GHOST root: $GHOST_ROOT"
        mkdir -p "$GHOST_ROOT/engagements"
    fi
}

# Create engagement directory
init_engagement() {
    local ENGAGEMENT_DIR="$GHOST_ROOT/engagements/$ENGAGEMENT_NAME"

    if [ -d "$ENGAGEMENT_DIR" ]; then
        warn "Engagement '$ENGAGEMENT_NAME' exists. Appending timestamp."
        ENGAGEMENT_NAME="${ENGAGEMENT_NAME}_$(date +%H%M%S)"
        ENGAGEMENT_DIR="$GHOST_ROOT/engagements/$ENGAGEMENT_NAME"
    fi

    # Core directories - create first
    mkdir -p "$ENGAGEMENT_DIR/tasks/pending"
    mkdir -p "$ENGAGEMENT_DIR/tasks/running"
    mkdir -p "$ENGAGEMENT_DIR/tasks/completed"
    mkdir -p "$ENGAGEMENT_DIR/tasks/failed"

    # Hunter working directories
    for agent in shadow spider interceptor mindbender phantom skybreaker breaker persistence scribe; do
        mkdir -p "$ENGAGEMENT_DIR/hunters/$agent"
    done

    # Evidence directories
    mkdir -p "$ENGAGEMENT_DIR/evidence/screenshots"
    mkdir -p "$ENGAGEMENT_DIR/evidence/requests"
    mkdir -p "$ENGAGEMENT_DIR/evidence/outputs"

    status "Creating engagement: $ENGAGEMENT_NAME" >&2
    echo "$ENGAGEMENT_DIR"
}

# Initialize state.json
init_state() {
    local ENGAGEMENT_DIR="$1"
    local STATE_FILE="$ENGAGEMENT_DIR/state.json"

    cat > "$STATE_FILE" << EOF
{
  "engagement_id": "$ENGAGEMENT_NAME",
  "target": "$TARGET",
  "created_at": "$(date -Iseconds)",
  "phase": "init",
  "phases_completed": [],
  "active_hunters": [],
  "pending_hunters": [],
  "findings_count": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "flags": {
    "user": null,
    "root": null
  }
}
EOF
    status "Created state.json"
}

# Initialize plan.json with default attack graph
init_plan() {
    local ENGAGEMENT_DIR="$1"
    local PLAN_FILE="$ENGAGEMENT_DIR/plan.json"

    cat > "$PLAN_FILE" << 'EOF'
{
  "version": "1.0",
  "strategy": "smart",
  "phases": [
    {
      "id": 1,
      "name": "recon",
      "parallel": true,
      "tasks": [
        {"id": "recon-ports", "agent": "shadow", "action": "port_scan", "priority": 1},
        {"id": "recon-subs", "agent": "shadow", "action": "subdomain_enum", "priority": 1},
        {"id": "recon-tech", "agent": "shadow", "action": "tech_detect", "priority": 2}
      ]
    },
    {
      "id": 2,
      "name": "enumeration",
      "parallel": true,
      "depends_on": ["recon"],
      "triggers": {
        "port_80_443": {"agent": "spider", "action": "web_enum"},
        "port_445": {"agent": "phantom", "action": "smb_enum"},
        "port_22": {"agent": "phantom", "action": "ssh_enum"},
        "api_detected": {"agent": "interceptor", "action": "api_enum"},
        "llm_detected": {"agent": "mindbender", "action": "llm_probe"}
      }
    },
    {
      "id": 3,
      "name": "vulnerability",
      "parallel": true,
      "depends_on": ["enumeration"],
      "triggers": {
        "web_app": {"agent": "spider", "action": "vuln_scan"},
        "api_endpoint": {"agent": "interceptor", "action": "api_test"},
        "smb_share": {"agent": "phantom", "action": "smb_attack"},
        "ad_detected": {"agent": "phantom", "action": "ad_enum"}
      }
    },
    {
      "id": 4,
      "name": "exploitation",
      "parallel": false,
      "depends_on": ["vulnerability"],
      "requires_approval": true
    },
    {
      "id": 5,
      "name": "post_exploitation",
      "parallel": true,
      "depends_on": ["exploitation"]
    },
    {
      "id": 6,
      "name": "reporting",
      "parallel": false,
      "depends_on": ["post_exploitation"]
    }
  ]
}
EOF
    status "Created plan.json"
}

# Initialize empty findings.json
init_findings() {
    local ENGAGEMENT_DIR="$1"
    local FINDINGS_FILE="$ENGAGEMENT_DIR/findings.json"

    cat > "$FINDINGS_FILE" << EOF
{
  "engagement_id": "$ENGAGEMENT_NAME",
  "findings": [],
  "assets": [],
  "credentials": [],
  "last_updated": "$(date -Iseconds)"
}
EOF
    status "Created findings.json"
}

# Initialize runlog
init_runlog() {
    local ENGAGEMENT_DIR="$1"
    local RUNLOG="$ENGAGEMENT_DIR/runlog.jsonl"

    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"engagement_init\",\"engagement\":\"$ENGAGEMENT_NAME\",\"target\":\"$TARGET\"}" > "$RUNLOG"
    status "Created runlog.jsonl"
}

# Create active symlink
set_active() {
    local ENGAGEMENT_DIR="$1"
    rm -f "$GHOST_ROOT/active"
    ln -s "$ENGAGEMENT_DIR" "$GHOST_ROOT/active"
    status "Set active engagement symlink"
}

# Export environment
export_env() {
    local ENGAGEMENT_DIR="$1"

    echo ""
    echo -e "${CYAN}Export these variables:${NC}"
    echo "export GHOST_ENGAGEMENT=\"$ENGAGEMENT_DIR\""
    echo "export GHOST_STATE=\"$ENGAGEMENT_DIR/state.json\""
    echo "export GHOST_FINDINGS=\"$ENGAGEMENT_DIR/findings.json\""
    echo "export GHOST_RUNLOG=\"$ENGAGEMENT_DIR/runlog.jsonl\""
    [ -n "$TARGET" ] && echo "export TARGET=\"$TARGET\""
}

# Main
main() {
    print_banner

    info "Engagement: $ENGAGEMENT_NAME"
    [ -n "$TARGET" ] && info "Target: $TARGET"
    echo ""

    init_ghost_root
    ENGAGEMENT_DIR=$(init_engagement)
    init_state "$ENGAGEMENT_DIR"
    init_plan "$ENGAGEMENT_DIR"
    init_findings "$ENGAGEMENT_DIR"
    init_runlog "$ENGAGEMENT_DIR"
    set_active "$ENGAGEMENT_DIR"

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    status "Parallel mode initialized!"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"

    export_env "$ENGAGEMENT_DIR"

    echo ""
    info "Start hunting with: @command - Begin parallel engagement"
}

main "$@"
