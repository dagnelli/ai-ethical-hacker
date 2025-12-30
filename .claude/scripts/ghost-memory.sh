#!/bin/bash
#
# GHOST Memory Cortex Manager
# Long-term memory for engagements, techniques, and learned patterns
#
# Usage:
#   ghost-memory.sh engagement start <name> <type> <target>
#   ghost-memory.sh engagement end <id> <success> <access_level>
#   ghost-memory.sh technique record <mitre_id> <success> <context>
#   ghost-memory.sh pattern match <ports> <services> <tech>
#   ghost-memory.sh suggest <context_json>
#   ghost-memory.sh recall <query>
#   ghost-memory.sh stats
#
# Environment:
#   GHOST_MEMORY_DIR - Memory storage directory (default: ~/.claude/memory)
#

set -e

# Configuration
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
MEMORY_DIR="${GHOST_MEMORY_DIR:-$SCRIPT_DIR/../memory}"
CORTEX_FILE="$MEMORY_DIR/cortex.json"

# Ensure memory directory exists
mkdir -p "$MEMORY_DIR"

# Initialize cortex if missing
if [ ! -f "$CORTEX_FILE" ]; then
    echo "Initializing new memory cortex..."
    cat > "$CORTEX_FILE" << 'EOF'
{
  "metadata": {
    "version": "1.0.0",
    "created_at": "$(date -Iseconds)",
    "last_updated": "$(date -Iseconds)",
    "total_engagements": 0,
    "total_techniques_tracked": 0
  },
  "engagements": [],
  "techniques": {},
  "patterns": [],
  "insights": []
}
EOF
fi

# Update last_updated timestamp
update_timestamp() {
    local tmp=$(mktemp)
    jq --arg ts "$(date -Iseconds)" '.metadata.last_updated = $ts' "$CORTEX_FILE" > "$tmp"
    mv "$tmp" "$CORTEX_FILE"
}

# ============================================================================
# ENGAGEMENT MANAGEMENT
# ============================================================================

# Start a new engagement
# Usage: start_engagement <name> <type> <target>
start_engagement() {
    local name="$1"
    local type="$2"  # ctf, pentest, bug_bounty, red_team, training
    local target="$3"
    local id="eng_$(date +%s)"

    local tmp=$(mktemp)
    jq --arg id "$id" \
       --arg name "$name" \
       --arg type "$type" \
       --arg target "$target" \
       --arg ts "$(date -Iseconds)" \
       '.engagements += [{
         "id": $id,
         "name": $name,
         "type": $type,
         "target": {
           "primary": $target,
           "scope": [$target],
           "platform": "unknown",
           "fingerprint": {
             "services": [],
             "technologies": [],
             "ports": [],
             "cms": null,
             "framework": null
           }
         },
         "timeline": {
           "started_at": $ts,
           "completed_at": null,
           "duration_hours": 0
         },
         "outcome": {
           "success": false,
           "access_level": "none",
           "flags_captured": {"user": false, "root": false},
           "findings_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
         },
         "attack_path": [],
         "lessons_learned": [],
         "key_findings": []
       }] | .metadata.total_engagements += 1' "$CORTEX_FILE" > "$tmp"
    mv "$tmp" "$CORTEX_FILE"

    update_timestamp

    # Save current engagement ID for reference
    echo "$id" > "$MEMORY_DIR/.current_engagement"

    echo "$id"
}

# End an engagement with outcome
# Usage: end_engagement <id> <success> <access_level>
end_engagement() {
    local id="$1"
    local success="$2"  # true/false
    local access_level="$3"  # none, user, root, admin, system

    local started_at=$(jq -r --arg id "$id" '.engagements[] | select(.id == $id) | .timeline.started_at' "$CORTEX_FILE")
    local started_epoch=$(date -d "$started_at" +%s 2>/dev/null || echo "0")
    local now_epoch=$(date +%s)
    local duration_hours=$(echo "scale=2; ($now_epoch - $started_epoch) / 3600" | bc)

    local tmp=$(mktemp)
    jq --arg id "$id" \
       --argjson success "$success" \
       --arg level "$access_level" \
       --arg ts "$(date -Iseconds)" \
       --argjson hours "$duration_hours" \
       '(.engagements[] | select(.id == $id)) |= . + {
         "timeline": (.timeline + {"completed_at": $ts, "duration_hours": $hours}),
         "outcome": (.outcome + {"success": $success, "access_level": $level})
       }' "$CORTEX_FILE" > "$tmp"
    mv "$tmp" "$CORTEX_FILE"

    update_timestamp
    rm -f "$MEMORY_DIR/.current_engagement"

    echo "Engagement $id completed. Duration: ${duration_hours}h, Access: $access_level"
}

# Update engagement fingerprint
# Usage: update_fingerprint <id> <field> <value>
update_fingerprint() {
    local id="${1:-$(cat "$MEMORY_DIR/.current_engagement" 2>/dev/null)}"
    local field="$2"  # ports, services, technologies, platform, cms, framework
    local value="$3"

    [ -z "$id" ] && { echo "No active engagement"; exit 1; }

    local tmp=$(mktemp)

    case "$field" in
        ports|services|technologies)
            # Append to array (deduplicated)
            jq --arg id "$id" \
               --arg field "$field" \
               --arg val "$value" \
               '(.engagements[] | select(.id == $id) | .target.fingerprint[$field]) |= (. + [$val] | unique)' \
               "$CORTEX_FILE" > "$tmp"
            ;;
        platform|cms|framework)
            # Set scalar value
            jq --arg id "$id" \
               --arg field "$field" \
               --arg val "$value" \
               '(.engagements[] | select(.id == $id) | .target[$field]) = $val' \
               "$CORTEX_FILE" > "$tmp"
            ;;
    esac

    mv "$tmp" "$CORTEX_FILE"
    update_timestamp
}

# Add attack path step
# Usage: add_attack_step <technique> <mitre_id> <agent> <success> [notes]
add_attack_step() {
    local id="${GHOST_ENGAGEMENT_ID:-$(cat "$MEMORY_DIR/.current_engagement" 2>/dev/null)}"
    local technique="$1"
    local mitre_id="$2"
    local agent="$3"
    local success="$4"
    local notes="${5:-}"
    local phase="${GHOST_PHASE:-unknown}"

    [ -z "$id" ] && { echo "No active engagement"; exit 1; }

    local tmp=$(mktemp)
    jq --arg id "$id" \
       --arg phase "$phase" \
       --arg tech "$technique" \
       --arg mitre "$mitre_id" \
       --arg agent "$agent" \
       --argjson success "$success" \
       --arg notes "$notes" \
       '(.engagements[] | select(.id == $id) | .attack_path) += [{
         "phase": $phase,
         "technique": $tech,
         "mitre_id": $mitre,
         "agent": $agent,
         "success": $success,
         "notes": $notes,
         "timestamp": now | todate
       }]' "$CORTEX_FILE" > "$tmp"
    mv "$tmp" "$CORTEX_FILE"

    # Also update technique stats
    record_technique "$mitre_id" "$success" "${GHOST_CONTEXT:-general}"

    update_timestamp
}

# ============================================================================
# TECHNIQUE TRACKING
# ============================================================================

# Record technique usage and outcome
# Usage: record_technique <mitre_id> <success> <context>
record_technique() {
    local mitre_id="$1"
    local success="$2"  # true/false
    local context="${3:-general}"  # linux, windows, web_apps, active_directory, cloud

    local tmp=$(mktemp)

    # Initialize technique if not exists
    if ! jq -e --arg id "$mitre_id" '.techniques[$id]' "$CORTEX_FILE" >/dev/null 2>&1; then
        jq --arg id "$mitre_id" \
           '.techniques[$id] = {
             "mitre_id": $id,
             "name": "Unknown",
             "category": "unknown",
             "stats": {
               "times_used": 0,
               "times_successful": 0,
               "success_rate": 0.0,
               "last_used": null,
               "last_success": null
             },
             "context_effectiveness": {},
             "prerequisites": [],
             "common_blockers": []
           }' "$CORTEX_FILE" > "$tmp"
        mv "$tmp" "$CORTEX_FILE"
    fi

    # Update stats
    jq --arg id "$mitre_id" \
       --argjson success "$success" \
       --arg ctx "$context" \
       --arg ts "$(date -Iseconds)" \
       '
       # Increment times_used
       .techniques[$id].stats.times_used += 1 |

       # Increment times_successful if success
       (if $success then .techniques[$id].stats.times_successful += 1 else . end) |

       # Update success rate
       .techniques[$id].stats.success_rate = (
         .techniques[$id].stats.times_successful / .techniques[$id].stats.times_used
       ) |

       # Update last_used
       .techniques[$id].stats.last_used = $ts |

       # Update last_success if success
       (if $success then .techniques[$id].stats.last_success = $ts else . end) |

       # Update context effectiveness
       .techniques[$id].context_effectiveness[$ctx] = (
         ((.techniques[$id].context_effectiveness[$ctx] // 0) *
          ((.techniques[$id].stats.times_used - 1) | if . < 0 then 0 else . end) +
          (if $success then 1 else 0 end)) /
         .techniques[$id].stats.times_used
       ) |

       # Update total techniques tracked
       .metadata.total_techniques_tracked = (.techniques | keys | length)
       ' "$CORTEX_FILE" > "$tmp"
    mv "$tmp" "$CORTEX_FILE"

    update_timestamp
}

# Get technique effectiveness for a context
# Usage: get_technique_effectiveness <mitre_id> [context]
get_technique_effectiveness() {
    local mitre_id="$1"
    local context="${2:-}"

    if [ -n "$context" ]; then
        jq -r --arg id "$mitre_id" --arg ctx "$context" \
           '.techniques[$id].context_effectiveness[$ctx] // 0' "$CORTEX_FILE"
    else
        jq --arg id "$mitre_id" '.techniques[$id].stats' "$CORTEX_FILE"
    fi
}

# ============================================================================
# PATTERN MATCHING & SUGGESTIONS
# ============================================================================

# Match current target against known patterns
# Usage: match_patterns <ports_csv> <services_csv> <tech_csv>
match_patterns() {
    local ports="$1"    # comma-separated: 80,443,3306
    local services="$2" # comma-separated: http,mysql
    local tech="$3"     # comma-separated: php,apache

    # Convert to JSON arrays
    local ports_json=$(echo "$ports" | tr ',' '\n' | grep -v '^$' | jq -R 'tonumber' | jq -s '.')
    local services_json=$(echo "$services" | tr ',' '\n' | grep -v '^$' | jq -R '.' | jq -s '.')
    local tech_json=$(echo "$tech" | tr ',' '\n' | grep -v '^$' | jq -R '.' | jq -s '.')

    # Find matching patterns
    jq --argjson ports "$ports_json" \
       --argjson services "$services_json" \
       --argjson tech "$tech_json" \
       '
       .patterns | map(
         select(
           # Check if any ports match
           ((.fingerprint_match.ports // []) | any(. as $p | $ports | any(. == $p))) or
           # Check if any services match
           ((.fingerprint_match.services // []) | any(. as $s | $services | any(. == $s))) or
           # Check if any tech matches
           ((.fingerprint_match.technologies // []) | any(. as $t | $tech | any(. == $t)))
         )
       ) | sort_by(-.success_rate)
       ' "$CORTEX_FILE"
}

# Suggest techniques based on context
# Usage: suggest_techniques <context>
suggest_techniques() {
    local context="$1"  # linux, windows, web_apps, active_directory, cloud

    jq --arg ctx "$context" \
       '
       # Get techniques sorted by context effectiveness
       [.techniques | to_entries[] |
        select(.value.context_effectiveness[$ctx] != null and .value.context_effectiveness[$ctx] > 0)] |
       sort_by(-.value.context_effectiveness[$ctx]) |
       map({
         mitre_id: .key,
         name: .value.name,
         success_rate: .value.context_effectiveness[$ctx],
         times_used: .value.stats.times_used,
         prerequisites: .value.prerequisites
       }) |
       .[0:10]  # Top 10
       ' "$CORTEX_FILE"
}

# Get recommended attack path based on patterns and techniques
# Usage: recommend_attack_path <ports> <services> <tech> <platform>
recommend_attack_path() {
    local ports="$1"
    local services="$2"
    local tech="$3"
    local platform="${4:-unknown}"

    echo "=== GHOST Memory: Attack Path Recommendation ==="
    echo ""
    echo "Target Profile:"
    echo "  Ports: $ports"
    echo "  Services: $services"
    echo "  Technologies: $tech"
    echo "  Platform: $platform"
    echo ""

    # Find matching patterns
    echo "Matching Patterns:"
    match_patterns "$ports" "$services" "$tech" | jq -r '
      .[] | "  - \(.name) (success rate: \(.success_rate | . * 100 | floor)%)"
    '
    echo ""

    # Get pattern recommendations
    echo "Recommended Techniques (from patterns):"
    match_patterns "$ports" "$services" "$tech" | jq -r '
      .[0].recommended_techniques // [] | .[] |
      "  \(.priority). \(.technique) - \(.reason)"
    '
    echo ""

    # Get learned technique suggestions
    echo "Top Techniques for $platform (from experience):"
    suggest_techniques "$platform" | jq -r '
      .[] | "  - \(.name) [\(.mitre_id)] (success: \(.success_rate | . * 100 | floor)%, used: \(.times_used)x)"
    '
}

# ============================================================================
# RECALL & SEARCH
# ============================================================================

# Search engagements by query
# Usage: recall <query>
recall() {
    local query="$1"

    jq --arg q "$query" '
      .engagements | map(
        select(
          (.name | test($q; "i")) or
          (.target.primary | test($q; "i")) or
          (.target.fingerprint.technologies | any(test($q; "i"))) or
          (.target.fingerprint.services | any(test($q; "i")))
        )
      ) | map({
        id,
        name,
        target: .target.primary,
        outcome: .outcome.access_level,
        success: .outcome.success,
        duration: .timeline.duration_hours
      })
    ' "$CORTEX_FILE"
}

# Find similar engagements based on fingerprint
# Usage: find_similar <ports> <services> <tech>
find_similar() {
    local ports="$1"
    local services="$2"
    local tech="$3"

    local ports_json=$(echo "$ports" | tr ',' '\n' | grep -v '^$' | jq -R 'tonumber' 2>/dev/null | jq -s '.' 2>/dev/null || echo "[]")
    local services_json=$(echo "$services" | tr ',' '\n' | grep -v '^$' | jq -R '.' | jq -s '.')
    local tech_json=$(echo "$tech" | tr ',' '\n' | grep -v '^$' | jq -R '.' | jq -s '.')

    jq --argjson ports "$ports_json" \
       --argjson services "$services_json" \
       --argjson tech "$tech_json" \
       '
       .engagements | map(
         # Calculate similarity score
         . as $eng |
         {
           engagement: {id: .id, name: .name, target: .target.primary, outcome: .outcome},
           similarity: (
             ([$eng.target.fingerprint.ports[]? | . as $p | $ports | map(select(. == $p)) | length] | add // 0) +
             ([$eng.target.fingerprint.services[]? | . as $s | $services | map(select(. == $s)) | length] | add // 0) +
             ([$eng.target.fingerprint.technologies[]? | . as $t | $tech | map(select(. == $t)) | length] | add // 0)
           )
         }
       ) | map(select(.similarity > 0)) | sort_by(-.similarity) | .[0:5]
       ' "$CORTEX_FILE"
}

# ============================================================================
# STATISTICS & REPORTING
# ============================================================================

# Show memory statistics
show_stats() {
    echo "=== GHOST Memory Cortex Statistics ==="
    echo ""

    local version=$(jq -r '.metadata.version' "$CORTEX_FILE")
    local created=$(jq -r '.metadata.created_at' "$CORTEX_FILE")
    local updated=$(jq -r '.metadata.last_updated' "$CORTEX_FILE")
    local total_eng=$(jq -r '.metadata.total_engagements' "$CORTEX_FILE")
    local successful=$(jq '[.engagements[]? | select(.outcome.success == true)] | length' "$CORTEX_FILE")
    local root_access=$(jq '[.engagements[]? | select(.outcome.access_level == "root")] | length' "$CORTEX_FILE")
    local tech_tracked=$(jq -r '.metadata.total_techniques_tracked' "$CORTEX_FILE")
    local most_used=$(jq -r '(.techniques | to_entries | sort_by(-.value.stats.times_used) | .[0].key) // "N/A"' "$CORTEX_FILE")
    local highest_success=$(jq -r '(.techniques | to_entries | sort_by(-.value.stats.success_rate) | .[0].key) // "N/A"' "$CORTEX_FILE")
    local patterns=$(jq '.patterns | length' "$CORTEX_FILE")

    echo "Metadata:"
    echo "  Version: $version"
    echo "  Created: $created"
    echo "  Last Updated: $updated"
    echo ""
    echo "Engagements:"
    echo "  Total: $total_eng"
    echo "  Successful: $successful"
    echo "  Root Access: $root_access"
    echo ""
    echo "Techniques:"
    echo "  Tracked: $tech_tracked"
    echo "  Most Used: $most_used"
    echo "  Highest Success: $highest_success"
    echo ""
    echo "Patterns:"
    echo "  Defined: $patterns"
}

# Export memory for backup
export_memory() {
    local format="${1:-json}"
    local output="${2:-/tmp/ghost-memory-backup-$(date +%Y%m%d).json}"

    case "$format" in
        json)
            cp "$CORTEX_FILE" "$output"
            echo "Exported to: $output"
            ;;
        summary)
            {
                echo "# GHOST Memory Export - $(date)"
                echo ""
                echo "## Engagements"
                jq -r '.engagements[] | "- \(.name) [\(.id)]: \(.outcome.access_level) access"' "$CORTEX_FILE"
                echo ""
                echo "## Top Techniques"
                jq -r '.techniques | to_entries | sort_by(-.value.stats.success_rate) | .[0:10] | .[] |
                  "- \(.key): \(.value.stats.success_rate * 100 | floor)% success (\(.value.stats.times_used) uses)"' "$CORTEX_FILE"
            } > "${output%.json}.md"
            echo "Exported to: ${output%.json}.md"
            ;;
    esac
}

# ============================================================================
# ADD INSIGHT
# ============================================================================

# Add a learned insight
# Usage: add_insight <category> <insight> <confidence>
add_insight() {
    local category="$1"
    local insight="$2"
    local confidence="${3:-0.5}"
    local id="${GHOST_ENGAGEMENT_ID:-$(cat "$MEMORY_DIR/.current_engagement" 2>/dev/null || echo "")}"

    local insight_id="insight_$(date +%s%N | cut -c1-13)"

    local tmp=$(mktemp)
    jq --arg iid "$insight_id" \
       --arg cat "$category" \
       --arg insight "$insight" \
       --argjson conf "$confidence" \
       --arg eng "$id" \
       --arg ts "$(date -Iseconds)" \
       '.insights += [{
         "id": $iid,
         "category": $cat,
         "insight": $insight,
         "confidence": $conf,
         "source_engagements": (if $eng != "" then [$eng] else [] end),
         "created_at": $ts
       }]' "$CORTEX_FILE" > "$tmp"
    mv "$tmp" "$CORTEX_FILE"

    update_timestamp
    echo "$insight_id"
}

# ============================================================================
# MAIN
# ============================================================================

case "${1:-help}" in
    engagement)
        case "${2:-}" in
            start)
                [ -z "$3" ] || [ -z "$4" ] || [ -z "$5" ] && {
                    echo "Usage: $0 engagement start <name> <type> <target>"; exit 1;
                }
                start_engagement "$3" "$4" "$5"
                ;;
            end)
                [ -z "$3" ] || [ -z "$4" ] || [ -z "$5" ] && {
                    echo "Usage: $0 engagement end <id> <success> <access_level>"; exit 1;
                }
                end_engagement "$3" "$4" "$5"
                ;;
            fingerprint)
                update_fingerprint "$3" "$4" "$5"
                ;;
            step)
                add_attack_step "$3" "$4" "$5" "$6" "${7:-}"
                ;;
            *)
                echo "Usage: $0 engagement {start|end|fingerprint|step}"
                ;;
        esac
        ;;
    technique)
        case "${2:-}" in
            record)
                [ -z "$3" ] || [ -z "$4" ] && {
                    echo "Usage: $0 technique record <mitre_id> <success> [context]"; exit 1;
                }
                record_technique "$3" "$4" "${5:-general}"
                ;;
            effectiveness)
                get_technique_effectiveness "$3" "${4:-}"
                ;;
            *)
                echo "Usage: $0 technique {record|effectiveness}"
                ;;
        esac
        ;;
    pattern)
        case "${2:-}" in
            match)
                match_patterns "$3" "$4" "$5"
                ;;
            *)
                echo "Usage: $0 pattern match <ports> <services> <tech>"
                ;;
        esac
        ;;
    suggest)
        suggest_techniques "${2:-general}"
        ;;
    recommend)
        recommend_attack_path "$2" "$3" "$4" "$5"
        ;;
    recall)
        recall "$2"
        ;;
    similar)
        find_similar "$2" "$3" "$4"
        ;;
    insight)
        add_insight "$2" "$3" "${4:-0.5}"
        ;;
    stats)
        show_stats
        ;;
    export)
        export_memory "${2:-json}" "${3:-}"
        ;;
    help|*)
        echo "GHOST Memory Cortex v1.0"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Engagement Commands:"
        echo "  engagement start <name> <type> <target>  - Start new engagement"
        echo "  engagement end <id> <success> <access>   - End engagement with outcome"
        echo "  engagement fingerprint <id> <field> <val>- Update target fingerprint"
        echo "  engagement step <tech> <mitre> <agent> <success> [notes]"
        echo "                                           - Add attack path step"
        echo ""
        echo "Technique Commands:"
        echo "  technique record <mitre_id> <success> [context]"
        echo "                                           - Record technique usage"
        echo "  technique effectiveness <mitre_id> [ctx] - Get effectiveness stats"
        echo ""
        echo "Pattern & Suggestion Commands:"
        echo "  pattern match <ports> <services> <tech>  - Match against patterns"
        echo "  suggest <context>                        - Suggest techniques"
        echo "  recommend <ports> <svcs> <tech> <platform>"
        echo "                                           - Full attack path recommendation"
        echo ""
        echo "Search & Recall:"
        echo "  recall <query>                           - Search past engagements"
        echo "  similar <ports> <services> <tech>        - Find similar engagements"
        echo ""
        echo "Other:"
        echo "  insight <category> <insight> [confidence]- Add learned insight"
        echo "  stats                                    - Show memory statistics"
        echo "  export [json|summary] [output]           - Export memory"
        echo ""
        echo "Types: ctf, pentest, bug_bounty, red_team, training"
        echo "Contexts: linux, windows, web_apps, active_directory, cloud"
        echo "Access levels: none, user, root, admin, system"
        ;;
esac
