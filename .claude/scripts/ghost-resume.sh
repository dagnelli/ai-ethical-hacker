#!/bin/bash
#
# GHOST Resume - Resume Interrupted Engagements
# Restores state and continues from where the engagement left off
#
# Usage:
#   ghost-resume.sh                    - Resume active engagement
#   ghost-resume.sh <engagement_name>  - Resume specific engagement
#   ghost-resume.sh list               - List available engagements
#

set -e

GHOST_ROOT="/tmp/ghost"
ENGAGEMENTS_DIR="$GHOST_ROOT/engagements"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║          GHOST Resume - Continue Engagement       ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

status() { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[!]${NC} $1"; }

# List all engagements
list_engagements() {
    echo -e "${CYAN}Available Engagements:${NC}"
    echo ""

    if [ ! -d "$ENGAGEMENTS_DIR" ]; then
        echo "No engagements found."
        return
    fi

    for dir in "$ENGAGEMENTS_DIR"/*/; do
        [ -d "$dir" ] || continue
        local name=$(basename "$dir")
        local state_file="$dir/state.json"

        if [ -f "$state_file" ]; then
            local target=$(jq -r '.target // "unknown"' "$state_file")
            local phase=$(jq -r '.phase // "unknown"' "$state_file")
            local created=$(jq -r '.created_at // "unknown"' "$state_file")
            local findings=$(jq '.findings_count | add // 0' "$state_file")

            # Check if active
            local active=""
            if [ -L "$GHOST_ROOT/active" ]; then
                local active_path=$(readlink -f "$GHOST_ROOT/active")
                [ "$active_path" = "$(readlink -f "$dir")" ] && active=" ${GREEN}[ACTIVE]${NC}"
            fi

            echo -e "  ${YELLOW}$name${NC}$active"
            echo "    Target: $target"
            echo "    Phase: $phase"
            echo "    Findings: $findings"
            echo "    Created: $created"
            echo ""
        fi
    done
}

# Resume an engagement
resume_engagement() {
    local engagement_name="$1"
    local engagement_dir="$ENGAGEMENTS_DIR/$engagement_name"

    if [ ! -d "$engagement_dir" ]; then
        error "Engagement not found: $engagement_name"
        echo ""
        list_engagements
        exit 1
    fi

    local state_file="$engagement_dir/state.json"
    if [ ! -f "$state_file" ]; then
        error "Invalid engagement: missing state.json"
        exit 1
    fi

    # Read current state
    local target=$(jq -r '.target' "$state_file")
    local phase=$(jq -r '.phase' "$state_file")
    local critical=$(jq -r '.findings_count.critical // 0' "$state_file")
    local high=$(jq -r '.findings_count.high // 0' "$state_file")
    local medium=$(jq -r '.findings_count.medium // 0' "$state_file")
    local low=$(jq -r '.findings_count.low // 0' "$state_file")

    # Update active symlink
    rm -f "$GHOST_ROOT/active"
    ln -s "$engagement_dir" "$GHOST_ROOT/active"

    # Log resume event
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"engagement_resumed\",\"engagement\":\"$engagement_name\"}" >> "$engagement_dir/runlog.jsonl"

    print_banner

    status "Resumed engagement: $engagement_name"
    echo ""
    info "Target: $target"
    info "Current Phase: $phase"
    info "Findings: $critical critical, $high high, $medium medium, $low low"
    echo ""

    # Check for incomplete tasks
    local pending=$(ls -1 "$engagement_dir/tasks/pending" 2>/dev/null | wc -l)
    local running=$(ls -1 "$engagement_dir/tasks/running" 2>/dev/null | wc -l)

    if [ "$running" -gt 0 ]; then
        warn "Found $running tasks marked as running (may have been interrupted)"
        warn "Consider requeuing these tasks or marking them failed"
        echo ""
        echo "Running tasks:"
        for f in "$engagement_dir/tasks/running"/*.json; do
            [ -f "$f" ] || continue
            local agent=$(jq -r '.agent' "$f")
            local action=$(jq -r '.action' "$f")
            local task_id=$(jq -r '.task_id' "$f")
            echo "  - $agent:$action ($task_id)"
        done
        echo ""
    fi

    if [ "$pending" -gt 0 ]; then
        info "$pending tasks pending in queue"
    fi

    # Export environment
    echo -e "${CYAN}Export these variables:${NC}"
    echo "export GHOST_ENGAGEMENT=\"$engagement_dir\""
    echo "export TARGET=\"$target\""
    echo ""

    # Suggest next steps based on phase
    echo -e "${CYAN}Suggested Next Steps:${NC}"
    case "$phase" in
        init)
            echo "  - Start with: @command - Begin parallel engagement"
            ;;
        recon)
            echo "  - Continue recon: @shadow - Continue reconnaissance"
            echo "  - Or check status: ~/.claude/scripts/ghost-dispatch.sh status"
            ;;
        enumeration)
            echo "  - Continue enumeration based on findings"
            echo "  - Check triggers: ~/.claude/scripts/ghost-watchdog.sh check"
            ;;
        vulnerability)
            echo "  - Continue vulnerability testing"
            echo "  - Review findings: ~/.claude/scripts/ghost-findings.sh list"
            ;;
        exploitation_pending)
            echo "  - Review findings before exploitation"
            echo "  - Approve exploitation: ~/.claude/scripts/ghost-watchdog.sh approve-exploit"
            ;;
        exploitation)
            echo "  - Continue exploitation: @breaker - Continue exploitation"
            ;;
        post_exploitation)
            echo "  - Continue post-exploitation: @persistence - Continue post-exploitation"
            ;;
        reporting)
            echo "  - Generate report: ~/.claude/scripts/ghost-gather.sh markdown"
            ;;
        complete)
            echo "  - Engagement complete! Generate final report."
            ;;
    esac
}

# Requeue interrupted running tasks
requeue_running() {
    local engagement_dir="${GHOST_ENGAGEMENT:-$GHOST_ROOT/active}"
    [ -L "$engagement_dir" ] && engagement_dir=$(readlink -f "$engagement_dir")

    local running_dir="$engagement_dir/tasks/running"
    local pending_dir="$engagement_dir/tasks/pending"

    local count=0
    for f in "$running_dir"/*.json; do
        [ -f "$f" ] || continue

        # Reset task status
        local tmp=$(mktemp)
        jq '.status = "pending" | .attempts += 0' "$f" > "$tmp"
        mv "$tmp" "$pending_dir/$(basename "$f")"
        rm -f "$f"

        ((count++))
    done

    if [ "$count" -gt 0 ]; then
        status "Requeued $count interrupted tasks"
    else
        info "No running tasks to requeue"
    fi
}

# Main
case "${1:-}" in
    "")
        # Resume active engagement
        if [ -L "$GHOST_ROOT/active" ]; then
            local active_name=$(basename "$(readlink -f "$GHOST_ROOT/active")")
            resume_engagement "$active_name"
        else
            error "No active engagement found"
            echo ""
            list_engagements
            exit 1
        fi
        ;;
    list|ls)
        list_engagements
        ;;
    requeue)
        requeue_running
        ;;
    help|--help|-h)
        echo "GHOST Resume - Resume Interrupted Engagements"
        echo ""
        echo "Usage: $0 [command|engagement_name]"
        echo ""
        echo "Commands:"
        echo "  (none)              - Resume active engagement"
        echo "  <engagement_name>   - Resume specific engagement"
        echo "  list                - List all engagements"
        echo "  requeue             - Requeue interrupted running tasks"
        echo "  help                - Show this help"
        ;;
    *)
        resume_engagement "$1"
        ;;
esac
