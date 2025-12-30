#!/bin/bash
#
# GHOST Watchdog v2.0 - Auto-Dispatch with PTES Phase Sequencing
# Watches findings, enforces completion criteria, handles auto-regression
#
# Usage:
#   ghost-watchdog.sh start       - Start monitoring (background)
#   ghost-watchdog.sh stop        - Stop monitoring
#   ghost-watchdog.sh check       - One-time trigger check
#   ghost-watchdog.sh dispatch    - Force dispatch based on current findings
#   ghost-watchdog.sh phase       - Show current phase and metrics
#   ghost-watchdog.sh regress <phase> - Force regression to phase
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
FINDINGS_FILE="$ENGAGEMENT/findings.json"
RUNLOG="$ENGAGEMENT/runlog.jsonl"
PID_FILE="$ENGAGEMENT/.watchdog.pid"
DISPATCHED_FILE="$ENGAGEMENT/.dispatched"
REGRESSION_FILE="$ENGAGEMENT/.last_regression"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

log_event() {
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"watchdog_$1\",$2}" >> "$RUNLOG"
}

# Track previous asset/finding counts for regression detection
PREV_PORT_COUNT=0
PREV_ASSET_COUNT=0
PREV_FINDING_COUNT=0

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

# Set phase with history tracking
set_phase() {
    local new_phase="$1"
    local reason="${2:-auto_progress}"
    local current_phase=$(get_phase)
    local tmp=$(mktemp)

    # Update phase and add to history
    jq --arg new_phase "$new_phase" \
       --arg old_phase "$current_phase" \
       --arg reason "$reason" \
       --arg ts "$(date -Iseconds)" \
       '
       # Close previous phase in history
       .phase_history = (.phase_history | map(
         if .phase == $old_phase and .exited_at == null
         then . + {"exited_at": $ts, "exit_reason": $reason}
         else .
         end
       )) |
       # Add new phase to history
       .phase_history += [{"phase": $new_phase, "entered_at": $ts, "exited_at": null, "exit_reason": null}] |
       # Update current phase
       .phase = $new_phase |
       # Add to completed if not already there and not current
       (if (.phases_completed | index($old_phase)) == null and $old_phase != "init"
        then .phases_completed += [$old_phase]
        else . end)
       ' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"

    echo -e "${GREEN}[Phase]${NC} $current_phase → $new_phase ($reason)"
    log_event "phase_change" "\"from\":\"$current_phase\",\"to\":\"$new_phase\",\"reason\":\"$reason\""
}

# Check phase completion criteria
check_completion_criteria() {
    local phase="$1"
    local running=$("$DISPATCH" running 2>/dev/null || echo 0)
    local pending=$("$DISPATCH" pending 2>/dev/null || echo 0)

    # Get metrics from state
    local ports_found=$(jq -r '.phase_metrics.recon.ports_found // 0' "$STATE_FILE" 2>/dev/null || echo 0)
    local assets_found=$(jq -r '.phase_metrics.recon.assets_discovered // 0' "$STATE_FILE" 2>/dev/null || echo 0)
    local vulns_found=$(jq -r '.phase_metrics.vulnerability.vulns_found // 0' "$STATE_FILE" 2>/dev/null || echo 0)
    local findings_count=$(jq '.findings | length' "$FINDINGS_FILE" 2>/dev/null || echo 0)

    case "$phase" in
        recon)
            # Recon complete when: no tasks running AND at least 1 port found
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ] && [ "$ports_found" -ge 1 ]; then
                return 0
            fi
            ;;
        enumeration)
            # Enumeration complete when: no tasks running AND services enumerated
            local services_enum=$(jq -r '.phase_metrics.enumeration.services_enumerated // 0' "$STATE_FILE" 2>/dev/null || echo 0)
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ] && [ -f "$DISPATCHED_FILE" ]; then
                local enum_tasks=$(grep -c "enum" "$DISPATCHED_FILE" 2>/dev/null || echo 0)
                if [ "$enum_tasks" -gt 0 ]; then
                    return 0
                fi
            fi
            ;;
        vulnerability)
            # Vulnerability complete when: no tasks running
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ]; then
                return 0
            fi
            ;;
        exploitation)
            # Exploitation complete when: shell obtained OR no more exploits
            local shell_obtained=$(jq -r '.flags.user != null or .flags.root != null' "$STATE_FILE" 2>/dev/null || echo false)
            if [ "$shell_obtained" = "true" ] || ([ "$running" -eq 0 ] && [ "$pending" -eq 0 ]); then
                return 0
            fi
            ;;
        post_exploitation)
            # Post-exploitation complete when: root obtained OR exhausted
            local root_obtained=$(jq -r '.flags.root != null' "$STATE_FILE" 2>/dev/null || echo false)
            if [ "$root_obtained" = "true" ] || ([ "$running" -eq 0 ] && [ "$pending" -eq 0 ]); then
                return 0
            fi
            ;;
        reporting)
            if [ "$running" -eq 0 ] && [ "$pending" -eq 0 ]; then
                return 0
            fi
            ;;
    esac
    return 1
}

# Check for regression triggers
check_regression_triggers() {
    local phase="$1"

    # Get current counts
    local curr_port_count=$(jq '.assets | map(select(.type == "port")) | length' "$FINDINGS_FILE" 2>/dev/null || echo 0)
    local curr_asset_count=$(jq '.assets | length' "$FINDINGS_FILE" 2>/dev/null || echo 0)
    local curr_finding_count=$(jq '.findings | length' "$FINDINGS_FILE" 2>/dev/null || echo 0)

    # Detect significant new discoveries
    local new_ports=$((curr_port_count - PREV_PORT_COUNT))
    local new_assets=$((curr_asset_count - PREV_ASSET_COUNT))

    # Update previous counts
    PREV_PORT_COUNT=$curr_port_count
    PREV_ASSET_COUNT=$curr_asset_count
    PREV_FINDING_COUNT=$curr_finding_count

    case "$phase" in
        enumeration|vulnerability)
            # If significant new ports discovered during enum/vuln, consider regressing to recon
            if [ "$new_ports" -ge 3 ]; then
                echo -e "${YELLOW}[Regression]${NC} $new_ports new ports discovered - expanding recon"
                log_event "regression_trigger" "\"phase\":\"$phase\",\"trigger\":\"new_ports\",\"count\":$new_ports"

                # Record regression but don't block - just dispatch more recon
                if ! already_dispatched "shadow:expanded_scan"; then
                    "$DISPATCH" queue shadow expanded_scan 1
                    mark_dispatched "shadow:expanded_scan"
                fi
            fi
            ;;
        exploitation)
            # If exploitation reveals new networks/hosts, expand scope
            if [ "$new_assets" -ge 5 ]; then
                echo -e "${YELLOW}[Regression]${NC} $new_assets new assets during exploitation - lateral expansion"
                log_event "regression_trigger" "\"phase\":\"$phase\",\"trigger\":\"new_assets\",\"count\":$new_assets"
            fi
            ;;
    esac
}

# Show current phase status
show_phase_status() {
    local phase=$(get_phase)
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo -e "${CYAN}GHOST Phase Status${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo ""
    echo -e "Current Phase: ${GREEN}$phase${NC}"
    echo ""
    echo "Phase Metrics:"
    jq -r '.phase_metrics | to_entries[] | "  \(.key): \(.value | to_entries | map("\(.key)=\(.value)") | join(", "))"' "$STATE_FILE" 2>/dev/null
    echo ""
    echo "Findings Count:"
    jq -r '.findings_count | to_entries[] | "  \(.key): \(.value)"' "$STATE_FILE" 2>/dev/null
    echo ""
    echo "Completed Phases:"
    jq -r '.phases_completed | join(" → ")' "$STATE_FILE" 2>/dev/null
    echo ""
}

# Check and dispatch based on triggers (PTES v2.0 with auto-progression)
check_and_dispatch() {
    local phase=$(get_phase)
    local triggers=$("$FINDINGS" triggers 2>/dev/null || echo "")
    local running=$("$DISPATCH" running 2>/dev/null || echo 0)
    local pending=$("$DISPATCH" pending 2>/dev/null || echo 0)

    echo -e "${CYAN}[Watchdog]${NC} Phase: $phase | Running: $running | Pending: $pending"

    # Check for regression triggers (new discoveries that warrant going back)
    check_regression_triggers "$phase"

    # Export current phase for findings attribution
    export GHOST_PHASE="$phase"

    # Phase-based dispatch logic with completion criteria
    case "$phase" in
        init)
            # Start recon phase
            set_phase "recon" "engagement_start"
            echo -e "${GREEN}[Dispatch]${NC} Starting PTES Intelligence Gathering phase..."

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
            # Check completion criteria for recon
            if check_completion_criteria "recon"; then
                echo -e "${GREEN}[Criteria Met]${NC} Recon phase complete - auto-progressing"
                set_phase "enumeration" "criteria_met"
                check_and_dispatch  # Recurse to handle new phase
                return
            fi
            ;;

        enumeration)
            # Dispatch based on findings (trigger-based)
            for trigger in $triggers; do
                case "$trigger" in
                    web)
                        if ! already_dispatched "spider:enum"; then
                            echo -e "${GREEN}[Dispatch]${NC} Web ports detected → @spider"
                            "$DISPATCH" queue spider web_enum 2
                            mark_dispatched "spider:enum"
                        fi
                        ;;
                    smb)
                        if ! already_dispatched "phantom:smb"; then
                            echo -e "${GREEN}[Dispatch]${NC} SMB detected → @phantom"
                            "$DISPATCH" queue phantom smb_enum 2
                            mark_dispatched "phantom:smb"
                        fi
                        ;;
                    ssh)
                        if ! already_dispatched "phantom:ssh"; then
                            echo -e "${GREEN}[Dispatch]${NC} SSH detected → @phantom"
                            "$DISPATCH" queue phantom ssh_enum 3
                            mark_dispatched "phantom:ssh"
                        fi
                        ;;
                    api)
                        if ! already_dispatched "interceptor:enum"; then
                            echo -e "${GREEN}[Dispatch]${NC} API detected → @interceptor"
                            "$DISPATCH" queue interceptor api_enum 2
                            mark_dispatched "interceptor:enum"
                        fi
                        ;;
                esac
            done

            # Check completion criteria
            if check_completion_criteria "enumeration"; then
                echo -e "${GREEN}[Criteria Met]${NC} Enumeration phase complete - auto-progressing"
                set_phase "vulnerability" "criteria_met"
            fi
            ;;

        vulnerability)
            # Queue vulnerability scans based on what was enumerated
            if already_dispatched "spider:enum" && ! already_dispatched "spider:vuln"; then
                echo -e "${GREEN}[Dispatch]${NC} Web enumerated → Vulnerability scan"
                "$DISPATCH" queue spider vuln_scan 3
                mark_dispatched "spider:vuln"
            fi

            if already_dispatched "interceptor:enum" && ! already_dispatched "interceptor:vuln"; then
                echo -e "${GREEN}[Dispatch]${NC} API enumerated → API testing"
                "$DISPATCH" queue interceptor api_test 3
                mark_dispatched "interceptor:vuln"
            fi

            if already_dispatched "phantom:smb" && ! already_dispatched "phantom:vuln"; then
                echo -e "${GREEN}[Dispatch]${NC} SMB enumerated → SMB attacks"
                "$DISPATCH" queue phantom smb_attack 3
                mark_dispatched "phantom:vuln"
            fi

            # Check completion criteria - auto-progress to exploitation
            if check_completion_criteria "vulnerability"; then
                local vuln_count=$(jq '.findings | length' "$FINDINGS_FILE" 2>/dev/null || echo 0)
                echo -e "${GREEN}[Criteria Met]${NC} Vulnerability phase complete. $vuln_count findings."

                # Auto-progress (no approval gate per user request)
                if [ "$vuln_count" -gt 0 ]; then
                    set_phase "exploitation" "vulns_found"
                    if ! already_dispatched "breaker:exploit"; then
                        "$DISPATCH" queue breaker exploit 4
                        mark_dispatched "breaker:exploit"
                    fi
                else
                    echo -e "${YELLOW}[Watchdog]${NC} No vulnerabilities found - moving to reporting"
                    set_phase "reporting" "no_vulns"
                fi
            fi
            ;;

        exploitation)
            # Check completion criteria
            if check_completion_criteria "exploitation"; then
                local shell_obtained=$(jq -r '.flags.user != null' "$STATE_FILE" 2>/dev/null || echo false)
                if [ "$shell_obtained" = "true" ]; then
                    echo -e "${GREEN}[Criteria Met]${NC} Shell obtained - auto-progressing to post-exploitation"
                    set_phase "post_exploitation" "shell_obtained"
                    if ! already_dispatched "persistence:privesc"; then
                        "$DISPATCH" queue persistence privilege_escalation 1
                        mark_dispatched "persistence:privesc"
                    fi
                else
                    echo -e "${YELLOW}[Watchdog]${NC} Exploitation exhausted without shell - moving to reporting"
                    set_phase "reporting" "exploits_exhausted"
                fi
            fi
            ;;

        post_exploitation)
            # Dispatch post-exploitation tasks
            if ! already_dispatched "persistence:creds"; then
                "$DISPATCH" queue persistence credential_harvest 2
                mark_dispatched "persistence:creds"
            fi

            # Check completion criteria
            if check_completion_criteria "post_exploitation"; then
                local root_obtained=$(jq -r '.flags.root != null' "$STATE_FILE" 2>/dev/null || echo false)
                if [ "$root_obtained" = "true" ]; then
                    echo -e "${GREEN}[Criteria Met]${NC} Root obtained - engagement successful!"
                fi
                set_phase "reporting" "post_exploit_complete"
                if ! already_dispatched "scribe:report"; then
                    "$DISPATCH" queue scribe generate_report 5
                    mark_dispatched "scribe:report"
                fi
            fi
            ;;

        reporting)
            if check_completion_criteria "reporting"; then
                set_phase "complete" "report_generated"
                echo -e "${GREEN}════════════════════════════════════════════${NC}"
                echo -e "${GREEN}[GHOST] Engagement Complete!${NC}"
                echo -e "${GREEN}════════════════════════════════════════════${NC}"
                show_phase_status
            fi
            ;;

        complete)
            echo -e "${GREEN}[Watchdog]${NC} Engagement already complete."
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

# Approve exploitation phase (legacy - kept for compatibility)
approve_exploit() {
    local phase=$(get_phase)
    if [ "$phase" = "exploitation_pending" ] || [ "$phase" = "vulnerability" ]; then
        set_phase "exploitation" "manual_approval"
        echo -e "${GREEN}[Watchdog]${NC} Exploitation phase approved!"
        "$DISPATCH" queue breaker exploit 4
        mark_dispatched "breaker:exploit"
    else
        echo "Not in exploitation_pending/vulnerability phase (current: $phase)"
    fi
}

# Force regression to a specific phase
force_regress() {
    local target_phase="$1"
    local current_phase=$(get_phase)

    # Validate target phase
    case "$target_phase" in
        recon|enumeration|vulnerability|exploitation|post_exploitation)
            set_phase "$target_phase" "manual_regression"
            echo -e "${YELLOW}[Regression]${NC} Forced regression from $current_phase to $target_phase"

            # Clear dispatched markers for the regressed phase
            case "$target_phase" in
                recon)
                    sed -i '/shadow:/d' "$DISPATCHED_FILE" 2>/dev/null || true
                    ;;
                enumeration)
                    sed -i '/spider:enum/d' "$DISPATCHED_FILE" 2>/dev/null || true
                    sed -i '/phantom:.*enum/d' "$DISPATCHED_FILE" 2>/dev/null || true
                    sed -i '/interceptor:enum/d' "$DISPATCHED_FILE" 2>/dev/null || true
                    ;;
                vulnerability)
                    sed -i '/vuln/d' "$DISPATCHED_FILE" 2>/dev/null || true
                    ;;
            esac
            ;;
        *)
            echo "Invalid phase: $target_phase"
            echo "Valid phases: recon, enumeration, vulnerability, exploitation, post_exploitation"
            return 1
            ;;
    esac
}

# Set flag (user or root obtained)
set_flag() {
    local flag_type="$1"  # user or root
    local flag_value="$2"
    local tmp=$(mktemp)

    jq --arg type "$flag_type" --arg val "$flag_value" \
       '.flags[$type] = $val' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"

    echo -e "${GREEN}[Flag]${NC} $flag_type flag set: $flag_value"
    log_event "flag_captured" "\"type\":\"$flag_type\",\"value\":\"$flag_value\""
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
    phase)
        show_phase_status
        ;;
    regress)
        [ -z "$2" ] && { echo "Usage: $0 regress <phase>"; exit 1; }
        force_regress "$2"
        ;;
    flag)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 flag <user|root> <value>"; exit 1; }
        set_flag "$2" "$3"
        ;;
    status)
        if [ -f "$PID_FILE" ]; then
            pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Watchdog running (PID: $pid)"
                echo ""
                show_phase_status
            else
                echo "Watchdog not running (stale PID file)"
            fi
        else
            echo "Watchdog not running"
            echo ""
            show_phase_status
        fi
        ;;
    *)
        echo "GHOST Watchdog v2.0 - PTES Auto-Dispatch with Phase Sequencing"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start              - Start background monitoring"
        echo "  stop               - Stop monitoring"
        echo "  check              - One-time trigger check"
        echo "  dispatch           - Force dispatch check"
        echo "  phase              - Show current phase and metrics"
        echo "  regress <phase>    - Force regression to phase"
        echo "  flag <type> <val>  - Set user/root flag"
        echo "  approve-exploit    - Manual approval for exploitation"
        echo "  status             - Check watchdog and show phase"
        echo ""
        echo "Phases: init → recon → enumeration → vulnerability → exploitation → post_exploitation → reporting → complete"
        echo ""
        echo "Auto-Progression:"
        echo "  - Phases auto-progress when completion criteria are met"
        echo "  - Auto-regression triggered by new significant discoveries"
        echo "  - No approval gates (per configuration)"
        ;;
esac
