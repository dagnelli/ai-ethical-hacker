#!/bin/bash
#
# GHOST Adaptive TTP Engine
# Recommends techniques based on context, learned effectiveness, and rule-based knowledge
#
# Usage:
#   ghost-ttp.sh analyze <target_profile.json>     - Analyze target and recommend TTPs
#   ghost-ttp.sh prioritize <phase> <context>      - Get prioritized technique list
#   ghost-ttp.sh chain <initial_access>            - Suggest attack chain from initial access
#   ghost-ttp.sh blockers <technique>              - Get common blockers and bypasses
#   ghost-ttp.sh alternatives <technique>          - Get alternative techniques if blocked
#   ghost-ttp.sh lookup <mitre_id>                 - Lookup technique details
#   ghost-ttp.sh contexts                          - List all supported contexts
#
# Environment:
#   GHOST_MEMORY_DIR - Memory storage directory (default: script_dir/../memory)
#
# The engine combines:
#   1. Learned effectiveness scores from cortex.json
#   2. Rule-based knowledge from ttp-rules.json
#   3. Context-aware prioritization
#

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
MEMORY_DIR="${GHOST_MEMORY_DIR:-$SCRIPT_DIR/../memory}"
CORTEX_FILE="$MEMORY_DIR/cortex.json"
TTP_RULES_FILE="$MEMORY_DIR/ttp-rules.json"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Check if required files exist
check_files() {
    if [ ! -f "$TTP_RULES_FILE" ]; then
        echo -e "${RED}Error: TTP rules file not found at $TTP_RULES_FILE${NC}" >&2
        exit 1
    fi
    # Cortex file is optional - we work without learned data
    if [ ! -f "$CORTEX_FILE" ]; then
        echo -e "${YELLOW}Warning: Cortex file not found, using rule-based recommendations only${NC}" >&2
    fi
}

# Get learned success rate for a technique in a context
get_learned_rate() {
    local mitre_id="$1"
    local context="${2:-general}"

    if [ -f "$CORTEX_FILE" ]; then
        jq -r --arg id "$mitre_id" --arg ctx "$context" \
            '.techniques[$id].context_effectiveness[$ctx] // 0' "$CORTEX_FILE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Get technique usage count from cortex
get_usage_count() {
    local mitre_id="$1"

    if [ -f "$CORTEX_FILE" ]; then
        jq -r --arg id "$mitre_id" \
            '.techniques[$id].stats.times_used // 0' "$CORTEX_FILE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Detect context from target profile indicators
detect_contexts() {
    local profile_json="$1"

    # Read indicators from profile
    local ports=$(echo "$profile_json" | jq -r '.ports // [] | .[]' 2>/dev/null | tr '\n' ' ')
    local services=$(echo "$profile_json" | jq -r '.services // [] | .[]' 2>/dev/null | tr '\n' ' ')
    local technologies=$(echo "$profile_json" | jq -r '.technologies // [] | .[]' 2>/dev/null | tr '\n' ' ')
    local all_indicators="$ports $services $technologies"

    local detected_contexts=""

    # Check each context profile
    for context in $(jq -r '.context_profiles | keys[]' "$TTP_RULES_FILE"); do
        local indicators=$(jq -r --arg ctx "$context" \
            '.context_profiles[$ctx].indicators | .[]' "$TTP_RULES_FILE" 2>/dev/null)

        for indicator in $indicators; do
            if echo "$all_indicators" | grep -iq "$indicator"; then
                if [ -z "$detected_contexts" ]; then
                    detected_contexts="$context"
                else
                    detected_contexts="$detected_contexts $context"
                fi
                break
            fi
        done
    done

    # Remove duplicates and return
    echo "$detected_contexts" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# ============================================================================
# ANALYZE COMMAND
# Analyze target profile and recommend TTPs
# ============================================================================

cmd_analyze() {
    local profile_file="$1"

    if [ -z "$profile_file" ]; then
        echo -e "${RED}Usage: ghost-ttp.sh analyze <target_profile.json>${NC}" >&2
        echo "" >&2
        echo "Target profile JSON format:" >&2
        echo '  {' >&2
        echo '    "ports": [80, 443, 22],' >&2
        echo '    "services": ["http", "https", "ssh"],' >&2
        echo '    "technologies": ["php", "apache", "mysql"],' >&2
        echo '    "platform": "linux"' >&2
        echo '  }' >&2
        exit 1
    fi

    # Read profile - can be file or JSON string
    local profile_json
    if [ -f "$profile_file" ]; then
        profile_json=$(cat "$profile_file")
    else
        profile_json="$profile_file"
    fi

    # Validate JSON
    if ! echo "$profile_json" | jq empty 2>/dev/null; then
        echo -e "${RED}Error: Invalid JSON in profile${NC}" >&2
        exit 1
    fi

    # Detect contexts from profile
    local contexts=$(detect_contexts "$profile_json")
    local platform=$(echo "$profile_json" | jq -r '.platform // "unknown"')

    # If no contexts detected, use platform
    if [ -z "$contexts" ]; then
        contexts="$platform"
    fi

    echo -e "${BOLD}=== GHOST Adaptive TTP Engine ===${NC}"
    echo ""
    echo -e "${CYAN}Target Profile Analysis${NC}"
    echo "  Ports: $(echo "$profile_json" | jq -r '.ports // [] | join(", ")')"
    echo "  Services: $(echo "$profile_json" | jq -r '.services // [] | join(", ")')"
    echo "  Technologies: $(echo "$profile_json" | jq -r '.technologies // [] | join(", ")')"
    echo "  Platform: $platform"
    echo ""
    echo -e "${CYAN}Detected Contexts:${NC} $contexts"
    echo ""

    # Build recommended techniques list
    local techniques_json="[]"
    local priority=1

    # For each detected context, get high priority techniques
    for context in $contexts; do
        local high_priority=$(jq -r --arg ctx "$context" \
            '.context_technique_priority[$ctx].high_priority // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null)

        for mitre_id in $high_priority; do
            # Get technique details from rules
            local name=$(jq -r --arg id "$mitre_id" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
            local prereqs=$(jq -c --arg id "$mitre_id" '.techniques[$id].prerequisites // []' "$TTP_RULES_FILE")

            # Get learned effectiveness
            local learned_rate=$(get_learned_rate "$mitre_id" "$context")
            local usage_count=$(get_usage_count "$mitre_id")

            # Calculate combined score (base 80 + learned bonus up to 20)
            local base_score=80
            local learned_bonus=$(echo "scale=0; $learned_rate * 20" | bc 2>/dev/null || echo "0")
            local combined_score=$((base_score + ${learned_bonus%.*}))

            # Build reason string
            local reason=""
            if [ "$usage_count" -gt 0 ] && [ "$learned_rate" != "0" ]; then
                local pct=$(echo "scale=0; $learned_rate * 100" | bc 2>/dev/null || echo "0")
                reason="High priority for $context context, ${pct%.*}% success rate in similar contexts (${usage_count}x used)"
            else
                reason="High priority for $context context (rule-based)"
            fi

            # Add to techniques array (avoiding duplicates)
            if ! echo "$techniques_json" | jq -e --arg id "$mitre_id" '.[] | select(.mitre == $id)' >/dev/null 2>&1; then
                techniques_json=$(echo "$techniques_json" | jq \
                    --arg tech "$name" \
                    --arg mitre "$mitre_id" \
                    --argjson pri "$priority" \
                    --arg reason "$reason" \
                    --argjson prereqs "$prereqs" \
                    --argjson score "$combined_score" \
                    '. += [{"technique": $tech, "mitre": $mitre, "priority": $pri, "reason": $reason, "prerequisites": $prereqs, "score": $score}]')
                priority=$((priority + 1))
            fi
        done
    done

    # Add medium priority techniques
    for context in $contexts; do
        local med_priority=$(jq -r --arg ctx "$context" \
            '.context_technique_priority[$ctx].medium_priority // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null)

        for mitre_id in $med_priority; do
            if ! echo "$techniques_json" | jq -e --arg id "$mitre_id" '.[] | select(.mitre == $id)' >/dev/null 2>&1; then
                local name=$(jq -r --arg id "$mitre_id" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
                local prereqs=$(jq -c --arg id "$mitre_id" '.techniques[$id].prerequisites // []' "$TTP_RULES_FILE")
                local learned_rate=$(get_learned_rate "$mitre_id" "$context")

                local reason="Medium priority for $context context"

                techniques_json=$(echo "$techniques_json" | jq \
                    --arg tech "$name" \
                    --arg mitre "$mitre_id" \
                    --argjson pri "$priority" \
                    --arg reason "$reason" \
                    --argjson prereqs "$prereqs" \
                    --argjson score 60 \
                    '. += [{"technique": $tech, "mitre": $mitre, "priority": $pri, "reason": $reason, "prerequisites": $prereqs, "score": 60}]')
                priority=$((priority + 1))
            fi
        done
    done

    # Sort by score descending and renumber priorities
    techniques_json=$(echo "$techniques_json" | jq 'sort_by(-.score) | to_entries | map(.value.priority = .key + 1 | .value)')

    # Get suggested attack chain based on primary context
    local primary_context=$(echo "$contexts" | awk '{print $1}')
    local attack_chain=""

    # Find matching attack chain
    for chain_id in $(jq -r '.attack_chains | keys[]' "$TTP_RULES_FILE"); do
        local chain_contexts=$(jq -r --arg id "$chain_id" '.attack_chains[$id].contexts | .[]' "$TTP_RULES_FILE" 2>/dev/null)
        if echo "$chain_contexts" | grep -q "$primary_context"; then
            attack_chain=$(jq -r --arg id "$chain_id" '.attack_chains[$id].chain | join(" -> ")' "$TTP_RULES_FILE")
            break
        fi
    done

    # Build if_blocked mappings for top techniques
    local if_blocked="{}"
    for mitre_id in $(echo "$techniques_json" | jq -r '.[0:5] | .[].mitre'); do
        local blockers=$(jq -c --arg id "$mitre_id" '.techniques[$id].common_blockers // []' "$TTP_RULES_FILE")
        local alternatives="[]"

        # Get bypass alternatives from blockers
        for blocker in $(echo "$blockers" | jq -r '.[]' 2>/dev/null); do
            local alt_techs=$(jq -c --arg b "$blocker" '.blocker_to_bypass[$b].alternative_techniques // []' "$TTP_RULES_FILE" 2>/dev/null)
            alternatives=$(echo "$alternatives $alt_techs" | jq -s 'add | unique')
        done

        if_blocked=$(echo "$if_blocked" | jq --arg id "$mitre_id" --argjson alts "$alternatives" '. + {($id): $alts}')
    done

    # Build final output
    local output=$(jq -n \
        --argjson techniques "$techniques_json" \
        --arg chain "$attack_chain" \
        --argjson blocked "$if_blocked" \
        --arg contexts "$contexts" \
        '{
            "analyzed_contexts": ($contexts | split(" ")),
            "recommended_techniques": $techniques,
            "attack_chain": ($chain | split(" -> ")),
            "if_blocked": $blocked
        }')

    echo -e "${CYAN}Recommended Techniques:${NC}"
    echo "$output" | jq -r '.recommended_techniques | .[] | "  \(.priority). [\(.mitre)] \(.technique)\n     Reason: \(.reason)\n     Prerequisites: \(.prerequisites | join(", "))\n"'

    echo -e "${CYAN}Suggested Attack Chain:${NC}"
    echo "  $attack_chain"
    echo ""

    echo -e "${CYAN}If Blocked Alternatives:${NC}"
    echo "$output" | jq -r '.if_blocked | to_entries[] | "  \(.key): \(.value | join(", "))"'
    echo ""

    echo -e "${CYAN}Full JSON Output:${NC}"
    echo "$output" | jq '.'
}

# ============================================================================
# PRIORITIZE COMMAND
# Get prioritized technique list for a phase and context
# ============================================================================

cmd_prioritize() {
    local phase="$1"
    local context="${2:-general}"

    if [ -z "$phase" ]; then
        echo -e "${RED}Usage: ghost-ttp.sh prioritize <phase> [context]${NC}" >&2
        echo "" >&2
        echo "Phases: recon, enumeration, exploitation, privilege_escalation, credential_access, lateral_movement, persistence" >&2
        echo "Contexts: linux, windows, macos, web_apps, api, active_directory, cloud_aws, cloud_azure, cloud_gcp, iot, embedded" >&2
        exit 1
    fi

    # Get techniques for the phase
    local phase_techniques=$(jq -r --arg p "$phase" '.phase_techniques[$p].techniques // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null)

    if [ -z "$phase_techniques" ]; then
        echo -e "${YELLOW}No techniques defined for phase: $phase${NC}" >&2
        exit 1
    fi

    echo -e "${BOLD}=== Prioritized Techniques for $phase ($context) ===${NC}"
    echo ""

    local result="[]"
    local priority=1

    for mitre_id in $phase_techniques; do
        local name=$(jq -r --arg id "$mitre_id" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
        local category=$(jq -r --arg id "$mitre_id" '.techniques[$id].category // "unknown"' "$TTP_RULES_FILE")
        local prereqs=$(jq -c --arg id "$mitre_id" '.techniques[$id].prerequisites // []' "$TTP_RULES_FILE")
        local blockers=$(jq -c --arg id "$mitre_id" '.techniques[$id].common_blockers // []' "$TTP_RULES_FILE")
        local tools=$(jq -c --arg id "$mitre_id" '.techniques[$id].tools // []' "$TTP_RULES_FILE")
        local agents=$(jq -c --arg id "$mitre_id" '.techniques[$id].agents // []' "$TTP_RULES_FILE")

        # Get learned effectiveness
        local learned_rate=$(get_learned_rate "$mitre_id" "$context")
        local usage_count=$(get_usage_count "$mitre_id")

        # Calculate priority score
        local context_priority=$(jq -r --arg ctx "$context" --arg id "$mitre_id" \
            'if .context_technique_priority[$ctx].high_priority | index($id) then "high"
             elif .context_technique_priority[$ctx].medium_priority | index($id) then "medium"
             else "low" end' "$TTP_RULES_FILE" 2>/dev/null)

        local base_score=50
        case "$context_priority" in
            high) base_score=90 ;;
            medium) base_score=70 ;;
            low) base_score=50 ;;
        esac

        local learned_bonus=$(echo "scale=0; $learned_rate * 10" | bc 2>/dev/null || echo "0")
        local final_score=$((base_score + ${learned_bonus%.*}))

        result=$(echo "$result" | jq \
            --arg mitre "$mitre_id" \
            --arg name "$name" \
            --arg category "$category" \
            --argjson prereqs "$prereqs" \
            --argjson blockers "$blockers" \
            --argjson tools "$tools" \
            --argjson agents "$agents" \
            --argjson score "$final_score" \
            --argjson usage "$usage_count" \
            --arg learned "$learned_rate" \
            --arg ctx_pri "$context_priority" \
            '. += [{
                "mitre_id": $mitre,
                "name": $name,
                "category": $category,
                "context_priority": $ctx_pri,
                "score": $score,
                "learned_rate": ($learned | tonumber),
                "times_used": $usage,
                "prerequisites": $prereqs,
                "common_blockers": $blockers,
                "tools": $tools,
                "agents": $agents
            }]')

        priority=$((priority + 1))
    done

    # Sort by score and display
    result=$(echo "$result" | jq 'sort_by(-.score)')

    echo "$result" | jq -r '.[] |
        "[\(.mitre_id)] \(.name) (score: \(.score))
   Category: \(.category)
   Context Priority: \(.context_priority)
   Learned Rate: \(.learned_rate | . * 100 | floor)% (\(.times_used)x used)
   Prerequisites: \(.prerequisites | join(", ") | if . == "" then "none" else . end)
   Blockers: \(.common_blockers | join(", "))
   Tools: \(.tools | join(", "))
   Agents: \(.agents | join(", "))
"'

    echo -e "${CYAN}JSON Output:${NC}"
    echo "$result" | jq '.'
}

# ============================================================================
# CHAIN COMMAND
# Suggest attack chain from initial access technique
# ============================================================================

cmd_chain() {
    local initial="$1"

    if [ -z "$initial" ]; then
        echo -e "${RED}Usage: ghost-ttp.sh chain <initial_access_technique>${NC}" >&2
        echo "" >&2
        echo "Examples:" >&2
        echo "  ghost-ttp.sh chain T1190    # From Exploit Public-Facing App" >&2
        echo "  ghost-ttp.sh chain T1566    # From Phishing" >&2
        echo "  ghost-ttp.sh chain T1133    # From External Remote Services" >&2
        exit 1
    fi

    echo -e "${BOLD}=== Attack Chain from $initial ===${NC}"
    echo ""

    # Get what this technique enables
    local enables=$(jq -c --arg id "$initial" '.techniques[$id].enables // []' "$TTP_RULES_FILE")
    local name=$(jq -r --arg id "$initial" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")

    echo -e "${GREEN}Initial Access:${NC} [$initial] $name"
    echo ""

    # Build chain by following enables
    local chain="[$initial]"
    local current="$initial"
    local depth=0
    local max_depth=6

    while [ $depth -lt $max_depth ]; do
        local next_techniques=$(jq -r --arg id "$current" '.techniques[$id].enables // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null | head -1)

        if [ -z "$next_techniques" ]; then
            break
        fi

        current="$next_techniques"
        local current_name=$(jq -r --arg id "$current" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
        chain="$chain -> [$current]"

        depth=$((depth + 1))
    done

    echo -e "${CYAN}Suggested Chain:${NC}"
    echo "  $chain"
    echo ""

    # Build detailed chain with all options
    echo -e "${CYAN}Detailed Chain Options:${NC}"

    local visited="$initial"
    local queue="$initial"
    local result_chains="[]"

    build_chain_recursive() {
        local tech="$1"
        local path="$2"
        local indent="$3"

        local tech_name=$(jq -r --arg id "$tech" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
        echo "${indent}[$tech] $tech_name"

        local enables=$(jq -r --arg id "$tech" '.techniques[$id].enables // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null)

        for next in $enables; do
            if [ ${#indent} -lt 20 ]; then
                build_chain_recursive "$next" "$path -> $next" "  $indent"
            fi
        done
    }

    build_chain_recursive "$initial" "$initial" ""
    echo ""

    # Find matching predefined chains
    echo -e "${CYAN}Matching Predefined Attack Chains:${NC}"
    jq -r --arg init "$initial" '
        .attack_chains | to_entries[] |
        select(.value.chain | index($init)) |
        "  \(.value.name): \(.value.chain | join(" -> "))\n    Contexts: \(.value.contexts | join(", "))\n    Success Indicators: \(.value.success_indicators | join(", "))\n"
    ' "$TTP_RULES_FILE"
}

# ============================================================================
# BLOCKERS COMMAND
# Get common blockers and bypasses for a technique
# ============================================================================

cmd_blockers() {
    local technique="$1"

    if [ -z "$technique" ]; then
        echo -e "${RED}Usage: ghost-ttp.sh blockers <technique>${NC}" >&2
        echo "" >&2
        echo "Example: ghost-ttp.sh blockers T1190" >&2
        exit 1
    fi

    local name=$(jq -r --arg id "$technique" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
    local blockers=$(jq -c --arg id "$technique" '.techniques[$id].common_blockers // []' "$TTP_RULES_FILE")
    local bypass_map=$(jq -c --arg id "$technique" '.techniques[$id].bypass_for_blockers // {}' "$TTP_RULES_FILE")

    echo -e "${BOLD}=== Blockers for [$technique] $name ===${NC}"
    echo ""

    echo -e "${CYAN}Common Blockers:${NC}"
    echo "$blockers" | jq -r '.[]' | while read blocker; do
        echo -e "  ${RED}$blocker${NC}"

        # Get bypasses from technique-specific mapping
        local technique_bypasses=$(echo "$bypass_map" | jq -r --arg b "$blocker" '.[$b] // [] | .[]' 2>/dev/null)
        if [ -n "$technique_bypasses" ]; then
            echo "    Technique-specific bypasses:"
            echo "$technique_bypasses" | while read bypass; do
                echo -e "      ${GREEN}- $bypass${NC}"
            done
        fi

        # Get bypasses from global blocker mapping
        local global_bypasses=$(jq -r --arg b "$blocker" '.blocker_to_bypass[$b].bypass_techniques // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null)
        if [ -n "$global_bypasses" ]; then
            echo "    General bypasses:"
            echo "$global_bypasses" | jq -r '"      - \(.technique): \(.description) [\(.tools | join(", "))]"' 2>/dev/null || \
            echo "$global_bypasses" | while read bypass; do
                echo -e "      ${GREEN}- $bypass${NC}"
            done
        fi

        # Get alternative techniques
        local alternatives=$(jq -r --arg b "$blocker" '.blocker_to_bypass[$b].alternative_techniques // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null)
        if [ -n "$alternatives" ]; then
            echo "    Alternative techniques:"
            for alt in $alternatives; do
                local alt_name=$(jq -r --arg id "$alt" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
                echo -e "      ${YELLOW}[$alt] $alt_name${NC}"
            done
        fi
        echo ""
    done

    # JSON output
    echo -e "${CYAN}JSON Output:${NC}"
    jq -n \
        --arg tech "$technique" \
        --arg name "$name" \
        --argjson blockers "$blockers" \
        --argjson bypasses "$bypass_map" \
        '{
            "technique": $tech,
            "name": $name,
            "blockers": $blockers,
            "bypasses": $bypasses
        }' | jq '.'
}

# ============================================================================
# ALTERNATIVES COMMAND
# Get alternative techniques when blocked
# ============================================================================

cmd_alternatives() {
    local technique="$1"

    if [ -z "$technique" ]; then
        echo -e "${RED}Usage: ghost-ttp.sh alternatives <technique>${NC}" >&2
        exit 1
    fi

    local name=$(jq -r --arg id "$technique" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
    local category=$(jq -r --arg id "$technique" '.techniques[$id].category // "unknown"' "$TTP_RULES_FILE")
    local phase=$(jq -r --arg id "$technique" '.techniques[$id].phase // "unknown"' "$TTP_RULES_FILE")
    local blockers=$(jq -r --arg id "$technique" '.techniques[$id].common_blockers // [] | .[]' "$TTP_RULES_FILE")

    echo -e "${BOLD}=== Alternatives for [$technique] $name ===${NC}"
    echo ""
    echo "Category: $category"
    echo "Phase: $phase"
    echo ""

    # Collect all alternative techniques
    local all_alternatives="[]"

    # 1. From blocker mappings
    echo -e "${CYAN}Alternatives based on common blockers:${NC}"
    for blocker in $blockers; do
        local alts=$(jq -c --arg b "$blocker" '.blocker_to_bypass[$b].alternative_techniques // []' "$TTP_RULES_FILE")
        all_alternatives=$(echo "$all_alternatives $alts" | jq -s 'add | unique')

        echo "  When blocked by '$blocker':"
        for alt in $(echo "$alts" | jq -r '.[]'); do
            local alt_name=$(jq -r --arg id "$alt" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
            local alt_prereqs=$(jq -r --arg id "$alt" '.techniques[$id].prerequisites // [] | join(", ")' "$TTP_RULES_FILE")
            echo -e "    ${GREEN}[$alt] $alt_name${NC}"
            if [ -n "$alt_prereqs" ]; then
                echo "      Prerequisites: $alt_prereqs"
            fi
        done
    done
    echo ""

    # 2. Same phase alternatives
    echo -e "${CYAN}Other techniques in same phase ($phase):${NC}"
    local phase_techs=$(jq -r --arg p "$phase" '.phase_techniques[$p].techniques // [] | .[]' "$TTP_RULES_FILE" 2>/dev/null)
    for tech in $phase_techs; do
        if [ "$tech" != "$technique" ]; then
            local tech_name=$(jq -r --arg id "$tech" '.techniques[$id].name // "Unknown"' "$TTP_RULES_FILE")
            echo "    [$tech] $tech_name"
        fi
    done
    echo ""

    # 3. Same category alternatives
    echo -e "${CYAN}Other techniques in same category ($category):${NC}"
    jq -r --arg cat "$category" --arg exclude "$technique" '
        .techniques | to_entries[] |
        select(.value.category == $cat and .key != $exclude) |
        "    [\(.key)] \(.value.name)"
    ' "$TTP_RULES_FILE"
    echo ""

    # JSON output
    echo -e "${CYAN}JSON Output:${NC}"
    jq -n \
        --arg tech "$technique" \
        --arg name "$name" \
        --arg phase "$phase" \
        --arg category "$category" \
        --argjson alts "$all_alternatives" \
        '{
            "blocked_technique": $tech,
            "name": $name,
            "phase": $phase,
            "category": $category,
            "alternatives": $alts
        }' | jq '.'
}

# ============================================================================
# LOOKUP COMMAND
# Lookup detailed technique information
# ============================================================================

cmd_lookup() {
    local mitre_id="$1"

    if [ -z "$mitre_id" ]; then
        echo -e "${RED}Usage: ghost-ttp.sh lookup <mitre_id>${NC}" >&2
        exit 1
    fi

    # Get from TTP rules
    local rule_data=$(jq --arg id "$mitre_id" '.techniques[$id] // null' "$TTP_RULES_FILE")

    if [ "$rule_data" = "null" ]; then
        echo -e "${YELLOW}Technique $mitre_id not found in TTP rules${NC}"
        exit 1
    fi

    # Get learned data if available
    local learned_data="{}"
    if [ -f "$CORTEX_FILE" ]; then
        learned_data=$(jq --arg id "$mitre_id" '.techniques[$id] // {}' "$CORTEX_FILE")
    fi

    local name=$(echo "$rule_data" | jq -r '.name')

    echo -e "${BOLD}=== [$mitre_id] $name ===${NC}"
    echo ""

    echo -e "${CYAN}Rule-Based Information:${NC}"
    echo "$rule_data" | jq '{
        category: .category,
        phase: .phase,
        contexts: .contexts,
        base_priority: .base_priority,
        prerequisites: .prerequisites,
        enables: .enables,
        common_blockers: .common_blockers,
        tools: .tools,
        agents: .agents
    }'
    echo ""

    if [ "$learned_data" != "{}" ]; then
        echo -e "${CYAN}Learned Effectiveness (from Cortex):${NC}"
        echo "$learned_data" | jq '{
            stats: .stats,
            context_effectiveness: .context_effectiveness
        }'
    else
        echo -e "${YELLOW}No learned data available for this technique${NC}"
    fi
}

# ============================================================================
# CONTEXTS COMMAND
# List all supported contexts
# ============================================================================

cmd_contexts() {
    echo -e "${BOLD}=== Supported Target Contexts ===${NC}"
    echo ""

    jq -r '.context_profiles | to_entries[] |
        "\(.key):\n  Description: \(.value.description)\n  Indicators: \(.value.indicators | join(", "))\n  Phases: \(.value.default_phases | join(" -> "))\n"
    ' "$TTP_RULES_FILE"
}

# ============================================================================
# HELP
# ============================================================================

show_help() {
    echo -e "${BOLD}GHOST Adaptive TTP Engine v1.0${NC}"
    echo ""
    echo "Recommends techniques based on context, learned effectiveness, and rule-based knowledge"
    echo ""
    echo -e "${CYAN}Usage:${NC}"
    echo "  ghost-ttp.sh <command> [args]"
    echo ""
    echo -e "${CYAN}Commands:${NC}"
    echo "  analyze <profile.json>        Analyze target and recommend TTPs"
    echo "  prioritize <phase> [context]  Get prioritized technique list for phase"
    echo "  chain <mitre_id>              Suggest attack chain from initial access"
    echo "  blockers <mitre_id>           Get common blockers and bypasses"
    echo "  alternatives <mitre_id>       Get alternative techniques if blocked"
    echo "  lookup <mitre_id>             Lookup technique details"
    echo "  contexts                      List all supported contexts"
    echo ""
    echo -e "${CYAN}Target Profile Format:${NC}"
    echo '  {'
    echo '    "ports": [80, 443, 22],'
    echo '    "services": ["http", "https", "ssh"],'
    echo '    "technologies": ["php", "apache", "mysql"],'
    echo '    "platform": "linux"'
    echo '  }'
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  ghost-ttp.sh analyze target.json"
    echo '  ghost-ttp.sh analyze '\''{"ports": [80, 445], "platform": "windows"}'\'''
    echo "  ghost-ttp.sh prioritize exploitation web_apps"
    echo "  ghost-ttp.sh chain T1190"
    echo "  ghost-ttp.sh blockers T1110"
    echo "  ghost-ttp.sh alternatives T1078"
    echo ""
    echo -e "${CYAN}Phases:${NC}"
    echo "  recon, enumeration, exploitation, privilege_escalation,"
    echo "  credential_access, lateral_movement, persistence"
    echo ""
    echo -e "${CYAN}Contexts:${NC}"
    echo "  linux, windows, macos, web_apps, api, mobile,"
    echo "  active_directory, cloud_aws, cloud_azure, cloud_gcp, iot, embedded"
    echo ""
    echo -e "${CYAN}Environment:${NC}"
    echo "  GHOST_MEMORY_DIR  Memory storage directory (default: ../memory)"
}

# ============================================================================
# MAIN
# ============================================================================

check_files

case "${1:-help}" in
    analyze)
        cmd_analyze "$2"
        ;;
    prioritize)
        cmd_prioritize "$2" "$3"
        ;;
    chain)
        cmd_chain "$2"
        ;;
    blockers)
        cmd_blockers "$2"
        ;;
    alternatives)
        cmd_alternatives "$2"
        ;;
    lookup)
        cmd_lookup "$2"
        ;;
    contexts)
        cmd_contexts
        ;;
    help|--help|-h|*)
        show_help
        ;;
esac
