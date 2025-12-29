#!/bin/bash
#
# GHOST Findings Manager
# Append, query, and manage findings in parallel operations
#
# Usage:
#   ghost-findings.sh add <severity> <title> [description]
#   ghost-findings.sh asset <type> <value> [info]
#   ghost-findings.sh cred <username> <password_or_hash> <source>
#   ghost-findings.sh port <port> <service> [version]
#   ghost-findings.sh list [severity]
#   ghost-findings.sh count
#   ghost-findings.sh export <format>
#

set -e

GHOST_ROOT="/tmp/ghost"
ENGAGEMENT="${GHOST_ENGAGEMENT:-$GHOST_ROOT/active}"
[ -L "$ENGAGEMENT" ] && ENGAGEMENT=$(readlink -f "$ENGAGEMENT")

FINDINGS_FILE="$ENGAGEMENT/findings.json"
STATE_FILE="$ENGAGEMENT/state.json"
RUNLOG="$ENGAGEMENT/runlog.jsonl"

log_event() {
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"$1\",$2}" >> "$RUNLOG"
}

update_timestamp() {
    local tmp=$(mktemp)
    jq --arg ts "$(date -Iseconds)" '.last_updated = $ts' "$FINDINGS_FILE" > "$tmp"
    mv "$tmp" "$FINDINGS_FILE"
}

# Add a finding
add_finding() {
    local severity="$1"
    local title="$2"
    local description="${3:-}"
    local agent="${GHOST_AGENT:-unknown}"
    local finding_id="finding_$(date +%s%N | cut -c1-13)"

    local tmp=$(mktemp)
    jq --arg id "$finding_id" \
       --arg sev "$severity" \
       --arg title "$title" \
       --arg desc "$description" \
       --arg agent "$agent" \
       --arg ts "$(date -Iseconds)" \
       '.findings += [{
         "id": $id,
         "severity": $sev,
         "title": $title,
         "description": $desc,
         "agent": $agent,
         "discovered_at": $ts,
         "status": "new",
         "evidence": []
       }]' "$FINDINGS_FILE" > "$tmp"
    mv "$tmp" "$FINDINGS_FILE"

    # Update counts in state
    tmp=$(mktemp)
    jq --arg sev "$severity" '.findings_count[$sev] += 1' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"

    update_timestamp
    log_event "finding_added" "\"id\":\"$finding_id\",\"severity\":\"$severity\",\"title\":\"$title\""

    echo "$finding_id"
}

# Add an asset (discovered host, subdomain, etc.)
add_asset() {
    local type="$1"      # host, subdomain, url, email, etc.
    local value="$2"
    local info="${3:-}"
    local agent="${GHOST_AGENT:-unknown}"

    local tmp=$(mktemp)
    jq --arg type "$type" \
       --arg value "$value" \
       --arg info "$info" \
       --arg agent "$agent" \
       --arg ts "$(date -Iseconds)" \
       '.assets += [{
         "type": $type,
         "value": $value,
         "info": $info,
         "discovered_by": $agent,
         "discovered_at": $ts
       }]' "$FINDINGS_FILE" > "$tmp"
    mv "$tmp" "$FINDINGS_FILE"

    update_timestamp
    log_event "asset_discovered" "\"type\":\"$type\",\"value\":\"$value\""
}

# Add credential
add_credential() {
    local username="$1"
    local secret="$2"
    local source="$3"
    local cred_type="${4:-password}"  # password, hash, key

    local tmp=$(mktemp)
    jq --arg user "$username" \
       --arg secret "$secret" \
       --arg src "$source" \
       --arg type "$cred_type" \
       --arg ts "$(date -Iseconds)" \
       '.credentials += [{
         "username": $user,
         "secret": $secret,
         "type": $type,
         "source": $src,
         "discovered_at": $ts,
         "tested": false
       }]' "$FINDINGS_FILE" > "$tmp"
    mv "$tmp" "$FINDINGS_FILE"

    update_timestamp
    log_event "credential_found" "\"username\":\"$username\",\"source\":\"$source\""
}

# Add discovered port/service
add_port() {
    local port="$1"
    local service="$2"
    local version="${3:-}"
    local host="${4:-${TARGET:-unknown}}"

    # Add as asset with port info
    add_asset "port" "$host:$port" "$service $version"

    # Also log specific event
    log_event "port_discovered" "\"host\":\"$host\",\"port\":\"$port\",\"service\":\"$service\""
}

# List findings
list_findings() {
    local severity="${1:-all}"

    if [ "$severity" = "all" ]; then
        jq -r '.findings[] | "\(.severity | ascii_upcase): \(.title)"' "$FINDINGS_FILE"
    else
        jq -r --arg sev "$severity" '.findings[] | select(.severity == $sev) | "\(.severity | ascii_upcase): \(.title)"' "$FINDINGS_FILE"
    fi
}

# Count findings
count_findings() {
    jq -r '.findings_count | to_entries[] | "\(.key): \(.value)"' "$STATE_FILE"
}

# Get findings as JSON
export_findings() {
    local format="${1:-json}"

    case "$format" in
        json)
            cat "$FINDINGS_FILE"
            ;;
        csv)
            echo "id,severity,title,agent,discovered_at"
            jq -r '.findings[] | [.id, .severity, .title, .agent, .discovered_at] | @csv' "$FINDINGS_FILE"
            ;;
        summary)
            echo "=== GHOST Findings Summary ==="
            echo ""
            count_findings
            echo ""
            echo "=== Findings ==="
            list_findings
            ;;
        *)
            echo "Unknown format: $format" >&2
            exit 1
            ;;
    esac
}

# Check for triggers (used by auto-dispatch)
check_triggers() {
    local triggers=""

    # Check for web ports
    if jq -e '.assets[] | select(.type == "port") | select(.value | test(":80$|:443$|:8080$|:8443$"))' "$FINDINGS_FILE" >/dev/null 2>&1; then
        triggers="$triggers web"
    fi

    # Check for SMB
    if jq -e '.assets[] | select(.type == "port") | select(.value | test(":445$|:139$"))' "$FINDINGS_FILE" >/dev/null 2>&1; then
        triggers="$triggers smb"
    fi

    # Check for SSH
    if jq -e '.assets[] | select(.type == "port") | select(.value | test(":22$"))' "$FINDINGS_FILE" >/dev/null 2>&1; then
        triggers="$triggers ssh"
    fi

    # Check for API indicators
    if jq -e '.assets[] | select(.type == "url") | select(.value | test("/api/|swagger|graphql"))' "$FINDINGS_FILE" >/dev/null 2>&1; then
        triggers="$triggers api"
    fi

    echo "$triggers"
}

# Get all unique ports discovered
get_ports() {
    jq -r '.assets[] | select(.type == "port") | .value' "$FINDINGS_FILE" | cut -d: -f2 | sort -n | uniq
}

# Get all assets of a type
get_assets() {
    local type="$1"
    jq -r --arg type "$type" '.assets[] | select(.type == $type) | .value' "$FINDINGS_FILE"
}

# Main
case "${1:-help}" in
    add)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 add <severity> <title> [description]"; exit 1; }
        add_finding "$2" "$3" "${4:-}"
        ;;
    asset)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 asset <type> <value> [info]"; exit 1; }
        add_asset "$2" "$3" "${4:-}"
        ;;
    cred)
        [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ] && { echo "Usage: $0 cred <username> <secret> <source>"; exit 1; }
        add_credential "$2" "$3" "$4" "${5:-password}"
        ;;
    port)
        [ -z "$2" ] || [ -z "$3" ] && { echo "Usage: $0 port <port> <service> [version]"; exit 1; }
        add_port "$2" "$3" "${4:-}"
        ;;
    list)
        list_findings "${2:-all}"
        ;;
    count)
        count_findings
        ;;
    export)
        export_findings "${2:-json}"
        ;;
    triggers)
        check_triggers
        ;;
    ports)
        get_ports
        ;;
    assets)
        get_assets "${2:-host}"
        ;;
    *)
        echo "GHOST Findings Manager"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  add <severity> <title> [desc]  - Add a finding"
        echo "  asset <type> <value> [info]    - Add discovered asset"
        echo "  cred <user> <secret> <source>  - Add credential"
        echo "  port <port> <service> [ver]    - Add discovered port"
        echo "  list [severity]                - List findings"
        echo "  count                          - Count by severity"
        echo "  export [json|csv|summary]      - Export findings"
        echo "  triggers                       - Check for dispatch triggers"
        echo "  ports                          - List discovered ports"
        echo "  assets <type>                  - List assets by type"
        ;;
esac
