#!/bin/bash
#
# GHOST Watchdog - Auto-Dispatch Monitor
# Watches findings and dispatches agents based on triggers
#
# Usage:
#   ghost-watchdog.sh start       - Start monitoring (background)
#   ghost-watchdog.sh stop        - Stop monitoring
#   ghost-watchdog.sh check       - One-time trigger check
#   ghost-watchdog.sh dispatch    - Force dispatch based on current findings
#

set -e

GHOST_ROOT="/tmp/ghost"
ENGAGEMENT="${GHOST_ENGAGEMENT:-$GHOST_ROOT/active}"
[ -L "$ENGAGEMENT" ] && ENGAGEMENT=$(readlink -f "$ENGAGEMENT")

SCRIPTS_DIR="$(dirname "$0")"
DISPATCH="$SCRIPTS_DIR/ghost-dispatch.sh"
FINDINGS="$SCRIPTS_DIR/ghost-findings.sh"

STATE_FILE="$ENGAGEMENT/state.json"
PLAN_FILE="$ENGAGEMENT/plan.json"
RUNLOG="$ENGAGEMENT/runlog.jsonl"
PID_FILE="$ENGAGEMENT/.watchdog.pid"
DISPATCHED_FILE="$ENGAGEMENT/.dispatched"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_event() {
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"watchdog_$1\",$2}" >> "$RUNLOG"
}

# Check if already dispatched
already_dispatched() {
    local key="$1"
    [ -f "$DISPATCHED_FILE" ] && grep -q "^$key$" "$DISPATCHED_FILE"
}

# Mark as dispatched
mark_dispatched() {
    local key="$1"
    echo "$key" >> "$DISPATCHED_FILE"
}

# Get current phase
get_phase() {
    jq -r '.phase' "$STATE_FILE"
}

# Set phase
set_phase() {
    local phase="$1"
    local tmp=$(mktemp)
    jq --arg phase "$phase" '.phase = $phase' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"
    log_event "phase_change" "\"phase\":\"$phase\""
}

# Check and dispatch based on triggers
check_and_dispatch() {
    local phase=$(get_phase)
    local triggers=$("$FINDINGS" triggers)
    local running=$("$DISPATCH" running)
    local pending=$("$DISPATCH" pending)

    echo -e "${CYAN}[Watchdog]${NC} Phase: $phase | Running: $running | Pending: $pending"

    # Phase-based dispatch logic
    case "$phase" in
        init)
            # Start recon phase
            set_phase "recon"
            echo -e "${GREEN}[Dispatch]${NC} Starting recon phase..."

            if ! already_dispatched "shadow:ports"; then
                "$DISPATCH" queue shadow port_scan 1
                mark_dispatched "shadow:ports"
            fi
            if ! already_dispatched "shadow:subs"; then
                "$DISPATCH" queue shadow subdomain_enum 1
                mark_dispatched "shadow:subs"
            fi
            if ! already_dispatched "shadow:tech"; then
                "$DISPATCH" queue shadow tech_detect 2
                mark_dispatched "shadow:tech"
            fi
            ;;

        recon)
            # Check if recon complete, move to enumeration
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ]; then
                set_phase "enumeration"
                check_and_dispatch  # Recurse to handle new phase
                return
            fi
            ;;

        enumeration)
            # Dispatch based on findings
            for trigger in $triggers; do
                case "$trigger" in
                    web)
                        if ! already_dispatched "spider:enum"; then
                            echo -e "${GREEN}[Dispatch]${NC} Web ports detected -> @spider"
                            "$DISPATCH" queue spider web_enum 2
                            mark_dispatched "spider:enum"
                        fi
                        ;;
                    smb)
                        if ! already_dispatched "phantom:smb"; then
                            echo -e "${GREEN}[Dispatch]${NC} SMB detected -> @phantom"
                            "$DISPATCH" queue phantom smb_enum 2
                            mark_dispatched "phantom:smb"
                        fi
                        ;;
                    ssh)
                        if ! already_dispatched "phantom:ssh"; then
                            echo -e "${GREEN}[Dispatch]${NC} SSH detected -> @phantom"
                            "$DISPATCH" queue phantom ssh_enum 3
                            mark_dispatched "phantom:ssh"
                        fi
                        ;;
                    api)
                        if ! already_dispatched "interceptor:enum"; then
                            echo -e "${GREEN}[Dispatch]${NC} API detected -> @interceptor"
                            "$DISPATCH" queue interceptor api_enum 2
                            mark_dispatched "interceptor:enum"
                        fi
                        ;;
                esac
            done

            # Check for phase completion
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ] && [ -f "$DISPATCHED_FILE" ]; then
                local enum_tasks=$(grep -c "enum" "$DISPATCHED_FILE" 2>/dev/null || echo 0)
                if [ "$enum_tasks" -gt 0 ]; then
                    set_phase "vulnerability"
                fi
            fi
            ;;

        vulnerability)
            # Queue vulnerability scans based on what was enumerated
            if already_dispatched "spider:enum" && ! already_dispatched "spider:vuln"; then
                echo -e "${GREEN}[Dispatch]${NC} Web enumerated -> Vulnerability scan"
                "$DISPATCH" queue spider vuln_scan 3
                mark_dispatched "spider:vuln"
            fi

            if already_dispatched "interceptor:enum" && ! already_dispatched "interceptor:vuln"; then
                echo -e "${GREEN}[Dispatch]${NC} API enumerated -> API testing"
                "$DISPATCH" queue interceptor api_test 3
                mark_dispatched "interceptor:vuln"
            fi

            if already_dispatched "phantom:smb" && ! already_dispatched "phantom:vuln"; then
                echo -e "${GREEN}[Dispatch]${NC} SMB enumerated -> SMB attacks"
                "$DISPATCH" queue phantom smb_attack 3
                mark_dispatched "phantom:vuln"
            fi

            # Check for phase completion
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ]; then
                local vuln_count=$(jq '.findings | length' "$ENGAGEMENT/findings.json")
                if [ "$vuln_count" -gt 0 ]; then
                    echo -e "${YELLOW}[Watchdog]${NC} Vulnerability phase complete. $vuln_count findings."
                    echo -e "${YELLOW}[Watchdog]${NC} Review findings before exploitation phase."
                    set_phase "exploitation_pending"
                fi
            fi
            ;;

        exploitation_pending)
            echo -e "${YELLOW}[Watchdog]${NC} Awaiting approval for exploitation phase."
            echo -e "${YELLOW}[Watchdog]${NC} Run: ghost-watchdog.sh approve-exploit"
            ;;

        exploitation)
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ]; then
                set_phase "post_exploitation"
            fi
            ;;

        post_exploitation)
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ]; then
                set_phase "reporting"
                if ! already_dispatched "scribe:report"; then
                    "$DISPATCH" queue scribe generate_report 5
                    mark_dispatched "scribe:report"
                fi
            fi
            ;;

        reporting)
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ]; then
                set_phase "complete"
                echo -e "${GREEN}[Watchdog]${NC} Engagement complete!"
            fi
            ;;
    esac
}

# File watcher for findings.json changes
LAST_FINDINGS_HASH=""

get_findings_hash() {
    if [ -f "$ENGAGEMENT/findings.json" ]; then
        md5sum "$ENGAGEMENT/findings.json" 2>/dev/null | cut -d' ' -f1
    else
        echo ""
    fi
}

check_findings_changes() {
    local current_hash=$(get_findings_hash)
    if [ -n "$current_hash" ] && [ "$current_hash" != "$LAST_FINDINGS_HASH" ]; then
        if [ -n "$LAST_FINDINGS_HASH" ]; then
            echo -e "${CYAN}[Watchdog]${NC} findings.json changed, checking triggers..."
            log_event "findings_changed" "\"hash\":\"$current_hash\""
            check_and_dispatch
        fi
        LAST_FINDINGS_HASH="$current_hash"
    fi
}

# Start background monitoring with file watcher
start_watchdog() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Watchdog already running (PID: $pid)"
            return 1
        fi
    fi

    echo -e "${GREEN}Starting GHOST Watchdog with file watcher...${NC}"

    # Initialize findings hash
    LAST_FINDINGS_HASH=$(get_findings_hash)

    (
        while true; do
            # Check for findings.json changes (fast poll)
            check_findings_changes 2>/dev/null

            # Full dispatch check every 10 seconds
            if [ $((SECONDS % 10)) -eq 0 ]; then
                check_and_dispatch 2>/dev/null
            fi

            sleep 2  # Check for file changes every 2 seconds
        done
    ) &

    echo $! > "$PID_FILE"
    echo "Watchdog started (PID: $!)"
    log_event "started" "\"pid\":$!,\"file_watcher\":true"
}

# Stop monitoring
stop_watchdog() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            rm -f "$PID_FILE"
            echo "Watchdog stopped"
            log_event "stopped" "\"pid\":$pid"
        else
            rm -f "$PID_FILE"
            echo "Watchdog was not running"
        fi
    else
        echo "No watchdog running"
    fi
}

# Approve exploitation phase
approve_exploit() {
    local phase=$(get_phase)
    if [ "$phase" = "exploitation_pending" ]; then
        set_phase "exploitation"
        echo -e "${GREEN}[Watchdog]${NC} Exploitation phase approved!"
        "$DISPATCH" queue breaker exploit 4
        mark_dispatched "breaker:exploit"
    else
        echo "Not in exploitation_pending phase (current: $phase)"
    fi
}

# Main
case "${1:-check}" in
    start)
        start_watchdog
        ;;
    stop)
        stop_watchdog
        ;;
    check)
        check_and_dispatch
        ;;
    dispatch)
        check_and_dispatch
        ;;
    approve-exploit)
        approve_exploit
        ;;
    status)
        if [ -f "$PID_FILE" ]; then
            local pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Watchdog running (PID: $pid)"
            else
                echo "Watchdog not running (stale PID file)"
            fi
        else
            echo "Watchdog not running"
        fi
        ;;
    *)
        echo "GHOST Watchdog - Auto-Dispatch Monitor"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start           - Start background monitoring"
        echo "  stop            - Stop monitoring"
        echo "  check           - One-time trigger check"
        echo "  dispatch        - Force dispatch check"
        echo "  approve-exploit - Approve exploitation phase"
        echo "  status          - Check if watchdog is running"
        ;;
esac
