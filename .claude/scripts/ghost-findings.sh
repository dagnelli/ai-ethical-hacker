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

# Add a finding (enhanced with ATT&CK, CVSS 4.0, CWE/CVE)
# Usage: add_finding <severity> <title> [description] [mitre_tid] [cwe_id] [cvss_score] [cve_id]
add_finding() {
    local severity="$1"
    local title="$2"
    local description="${3:-}"
    local mitre_tid="${4:-}"      # e.g., T1190
    local cwe_id="${5:-}"          # e.g., CWE-89
    local cvss_score="${6:-}"      # e.g., 9.8
    local cve_id="${7:-}"          # e.g., CVE-2024-1234
    local agent="${GHOST_AGENT:-unknown}"
    local phase="${GHOST_PHASE:-unknown}"
    local finding_id="finding_$(date +%s%N | cut -c1-13)"

    # Build attack object if MITRE T-code provided
    local attack_json="null"
    if [ -n "$mitre_tid" ]; then
        attack_json="{\"mitre_technique\":\"$mitre_tid\",\"mitre_url\":\"https://attack.mitre.org/techniques/$mitre_tid\"}"
    fi

    # Build classification object
    local class_json="{}"
    if [ -n "$cwe_id" ] || [ -n "$cve_id" ]; then
        class_json=$(jq -n \
            --arg cwe "$cwe_id" \
            --arg cve "$cve_id" \
            '{cwe_id: (if $cwe != "" then $cwe else null end), cve_id: (if $cve != "" then $cve else null end)}')
    fi

    # Build CVSS object if score provided
    local cvss_json="null"
    if [ -n "$cvss_score" ]; then
        local cvss_severity="None"
        if (( $(echo "$cvss_score >= 9.0" | bc -l) )); then cvss_severity="Critical"
        elif (( $(echo "$cvss_score >= 7.0" | bc -l) )); then cvss_severity="High"
        elif (( $(echo "$cvss_score >= 4.0" | bc -l) )); then cvss_severity="Medium"
        elif (( $(echo "$cvss_score >= 0.1" | bc -l) )); then cvss_severity="Low"
        fi
        cvss_json="{\"version\":\"4.0\",\"score\":$cvss_score,\"severity\":\"$cvss_severity\"}"
    fi

    local tmp=$(mktemp)
    jq --arg id "$finding_id" \
       --arg sev "$severity" \
       --arg title "$title" \
       --arg desc "$description" \
       --arg agent "$agent" \
       --arg phase "$phase" \
       --arg ts "$(date -Iseconds)" \
       --argjson attack "$attack_json" \
       --argjson class "$class_json" \
       --argjson cvss "$cvss_json" \
       '.findings += [{
         "id": $id,
         "severity": $sev,
         "title": $title,
         "description": $desc,
         "agent": $agent,
         "phase": $phase,
         "discovered_at": $ts,
         "status": "new",
         "evidence": [],
         "attack": $attack,
         "classification": $class,
         "cvss": $cvss
       }]' "$FINDINGS_FILE" > "$tmp"
    mv "$tmp" "$FINDINGS_FILE"

    # Update counts in state
    tmp=$(mktemp)
    jq --arg sev "$severity" '.findings_count[$sev] += 1' "$STATE_FILE" > "$tmp"
    mv "$tmp" "$STATE_FILE"

    # Update phase metrics
    tmp=$(mktemp)
    jq '.phase_metrics.vulnerability.vulns_found += 1' "$STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE" || true

    update_timestamp
    log_event "finding_added" "\"id\":\"$finding_id\",\"severity\":\"$severity\",\"title\":\"$title\",\"mitre\":\"$mitre_tid\",\"cwe\":\"$cwe_id\",\"cvss\":\"$cvss_score\""

    echo "$finding_id"
}

# Add an asset (discovered host, subdomain, etc.)
# Usage: add_asset <type> <value> [info] [tags]
add_asset() {
    local type="$1"      # host, subdomain, url, endpoint, service, email, user
    local value="$2"
    local info="${3:-}"
    local tags="${4:-}"   # comma-separated: web,api,smb,ssh,ad,cloud,llm
    local agent="${GHOST_AGENT:-unknown}"
    local phase="${GHOST_PHASE:-unknown}"

    # Convert tags to JSON array
    local tags_json="[]"
    if [ -n "$tags" ]; then
        tags_json=$(echo "$tags" | tr ',' '\n' | jq -R . | jq -s .)
    fi

    local tmp=$(mktemp)
    jq --arg type "$type" \
       --arg value "$value" \
       --arg info "$info" \
       --arg agent "$agent" \
       --arg phase "$phase" \
       --arg ts "$(date -Iseconds)" \
       --argjson tags "$tags_json" \
       '.assets += [{
         "type": $type,
         "value": $value,
         "info": $info,
         "discovered_by": $agent,
         "phase": $phase,
         "discovered_at": $ts,
         "tags": $tags
       }]' "$FINDINGS_FILE" > "$tmp"
    mv "$tmp" "$FINDINGS_FILE"

    # Update phase metrics for assets
    tmp=$(mktemp)
    jq '.phase_metrics.recon.assets_discovered += 1' "$STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE" || true

    update_timestamp
    log_event "asset_discovered" "\"type\":\"$type\",\"value\":\"$value\",\"phase\":\"$phase\""
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

    # Determine tags based on port
    local tags=""
    case "$port" in
        80|443|8080|8443) tags="web" ;;
        445|139) tags="smb" ;;
        22) tags="ssh" ;;
        3389) tags="rdp" ;;
        389|636|3268|3269) tags="ad,ldap" ;;
        88) tags="ad,kerberos" ;;
        53) tags="dns" ;;
        21) tags="ftp" ;;
        25|587|465) tags="smtp" ;;
        *) tags="" ;;
    esac

    # Add as asset with port info and tags
    add_asset "port" "$host:$port" "$service $version" "$tags"

    # Update phase metrics for ports
    local tmp=$(mktemp)
    jq '.phase_metrics.recon.ports_found += 1' "$STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE" || true

    # Also log specific event
    log_event "port_discovered" "\"host\":\"$host\",\"port\":\"$port\",\"service\":\"$service\",\"tags\":\"$tags\""
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
        echo "GHOST Findings Manager v2.0 (PTES Enhanced)"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  add <sev> <title> [desc] [T-code] [CWE] [CVSS] [CVE]"
        echo "                                 - Add finding with ATT&CK/CVSS/CWE"
        echo "  asset <type> <value> [info] [tags]"
        echo "                                 - Add asset with tags (web,api,smb,ssh,ad,cloud)"
        echo "  cred <user> <secret> <source>  - Add credential"
        echo "  port <port> <service> [ver]    - Add port (auto-tagged)"
        echo "  list [severity]                - List findings"
        echo "  count                          - Count by severity"
        echo "  export [json|csv|summary]      - Export findings"
        echo "  triggers                       - Check for dispatch triggers"
        echo "  ports                          - List discovered ports"
        echo "  assets <type>                  - List assets by type"
        echo ""
        echo "Examples:"
        echo "  $0 add critical 'SQL Injection' 'Login form' T1190 CWE-89 9.8 CVE-2024-1234"
        echo "  $0 asset endpoint '/api/users' 'REST API' api,auth"
        echo "  $0 port 443 https 'nginx 1.24'"
        echo ""
        echo "Environment:"
        echo "  GHOST_AGENT   - Agent name (auto-attributed)"
        echo "  GHOST_PHASE   - Current phase (auto-tracked)"
        ;;
esac
