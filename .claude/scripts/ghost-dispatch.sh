#!/bin/bash
#
# GHOST Task Dispatcher
# Manages parallel task execution for hunter-gather operations
#
# Usage:
#   ghost-dispatch.sh queue <agent> <action> [priority]
#   ghost-dispatch.sh run <task_id>
#   ghost-dispatch.sh status
#   ghost-dispatch.sh next
#   ghost-dispatch.sh complete <task_id> <status>
#

set -e

GHOST_ROOT="/tmp/ghost"
ENGAGEMENT="${GHOST_ENGAGEMENT:-$GHOST_ROOT/active}"

# Resolve symlink
[ -L "$ENGAGEMENT" ] && ENGAGEMENT=$(readlink -f "$ENGAGEMENT")

TASKS_DIR="$ENGAGEMENT/tasks"
STATE_FILE="$ENGAGEMENT/state.json"
RUNLOG="$ENGAGEMENT/runlog.jsonl"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_event() {
    local event="$1"
    local data="$2"
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"$event\",$data}" >> "$RUNLOG"
}

# Queue a new task
queue_task() {
    local agent="$1"
    local action="$2"
    local priority="${3:-5}"
    local task_id="${agent}_${action}_$(date +%s%N | cut -c1-13)"

    local task_file="$TASKS_DIR/pending/${priority}_${task_id}.json"

    cat > "$task_file" << EOF
{
  "task_id": "$task_id",
  "agent": "$agent",
  "action": "$action",
  "priority": $priority,
  "queued_at": "$(date -Iseconds)",
  "status": "pending",
  "attempts": 0
}
EOF

    log_event "task_queued" "\"task_id\":\"$task_id\",\"agent\":\"$agent\",\"action\":\"$action\""
    echo "$task_id"
}

# Start a task (move to running)
start_task() {
    local task_id="$1"
    local pending_file=$(find "$TASKS_DIR/pending" -name "*${task_id}*.json" 2>/dev/null | head -1)

    if [ -z "$pending_file" ]; then
        echo "Task not found: $task_id" >&2
        return 1
    fi

    local running_file="$TASKS_DIR/running/$(basename "$pending_file")"
    mv "$pending_file" "$running_file"

    # Update task status
    local tmp=$(mktemp)
    jq --arg ts "$(date -Iseconds)" '.status = "running" | .started_at = $ts | .attempts += 1' "$running_file" > "$tmp"
    mv "$tmp" "$running_file"

    # Update state.json active_hunters
    local agent=$(jq -r '.agent' "$running_file")
    tmp=$(mktemp)
    jq --arg hunter "$agent:$task_id" '.active_hunters += [$hunter]' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"

    log_event "task_started" "\"task_id\":\"$task_id\""
    echo "$running_file"
}

# Complete a task
complete_task() {
    local task_id="$1"
    local status="${2:-success}"  # success, failed, skipped
    local running_file=$(find "$TASKS_DIR/running" -name "*${task_id}*.json" 2>/dev/null | head -1)

    if [ -z "$running_file" ]; then
        echo "Running task not found: $task_id" >&2
        return 1
    fi

    local dest_dir="$TASKS_DIR/completed"
    [ "$status" = "failed" ] && dest_dir="$TASKS_DIR/failed"

    local dest_file="$dest_dir/$(basename "$running_file")"
    mv "$running_file" "$dest_file"

    # Update task
    local tmp=$(mktemp)
    jq --arg ts "$(date -Iseconds)" --arg st "$status" '.status = $st | .completed_at = $ts' "$dest_file" > "$tmp"
    mv "$tmp" "$dest_file"

    # Remove from active_hunters
    local agent=$(jq -r '.agent' "$dest_file")
    tmp=$(mktemp)
    jq --arg hunter "$agent:$task_id" '.active_hunters -= [$hunter]' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"

    log_event "task_completed" "\"task_id\":\"$task_id\",\"status\":\"$status\""
}

# Get next pending task
next_task() {
    # Sort by priority (filename prefix) and get first
    local next=$(ls -1 "$TASKS_DIR/pending" 2>/dev/null | sort | head -1)
    if [ -n "$next" ]; then
        cat "$TASKS_DIR/pending/$next"
    else
        echo "{}"
    fi
}

# List all pending tasks
list_pending() {
    echo -e "${CYAN}Pending Tasks:${NC}"
    local files=$(ls "$TASKS_DIR/pending"/*.json 2>/dev/null || true)
    for f in $files; do
        [ -f "$f" ] || continue
        local agent=$(jq -r '.agent' "$f")
        local action=$(jq -r '.action' "$f")
        local priority=$(jq -r '.priority' "$f")
        echo "  [$priority] $agent:$action"
    done
}

# List running tasks
list_running() {
    echo -e "${GREEN}Running Tasks:${NC}"
    local files=$(ls "$TASKS_DIR/running"/*.json 2>/dev/null || true)
    for f in $files; do
        [ -f "$f" ] || continue
        local agent=$(jq -r '.agent' "$f")
        local action=$(jq -r '.action' "$f")
        local started=$(jq -r '.started_at' "$f")
        echo "  $agent:$action (started: $started)"
    done
}

# Full status
show_status() {
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}       GHOST Dispatch Status            ${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo ""

    local phase=$(jq -r '.phase' "$STATE_FILE")
    local target=$(jq -r '.target' "$STATE_FILE")
    echo -e "Phase: ${GREEN}$phase${NC}"
    echo -e "Target: ${YELLOW}$target${NC}"
    echo ""

    local pending=$(ls -1 "$TASKS_DIR/pending" 2>/dev/null | wc -l)
    local running=$(ls -1 "$TASKS_DIR/running" 2>/dev/null | wc -l)
    local completed=$(ls -1 "$TASKS_DIR/completed" 2>/dev/null | wc -l)
    local failed=$(ls -1 "$TASKS_DIR/failed" 2>/dev/null | wc -l)

    echo "Tasks: ${YELLOW}$pending pending${NC} | ${GREEN}$running running${NC} | ${GREEN}$completed done${NC} | ${RED}$failed failed${NC}"
    echo ""

    list_running
    echo ""
    list_pending
}

# Get count of running tasks
running_count() {
    ls -1 "$TASKS_DIR/running" 2>/dev/null | wc -l
}

# Get count of pending tasks
pending_count() {
    ls -1 "$TASKS_DIR/pending" 2>/dev/null | wc -l
}

# Main
case "${1:-status}" in
    queue)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 queue <agent> <action> [priority]"; exit 1; }
        queue_task "$2" "$3" "${4:-5}"
        ;;
    start)
        [ -z "$2" ] && { echo "Usage: $0 start <task_id>"; exit 1; }
        start_task "$2"
        ;;
    complete)
        [ -z "$2" ] && { echo "Usage: $0 complete <task_id> [status]"; exit 1; }
        complete_task "$2" "${3:-success}"
        ;;
    next)
        next_task
        ;;
    status)
        show_status
        ;;
    pending)
        pending_count
        ;;
    running)
        running_count
        ;;
    *)
        echo "Usage: $0 {queue|start|complete|next|status|pending|running}"
        exit 1
        ;;
esac
