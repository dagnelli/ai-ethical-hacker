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

# Initialize state.json with PTES phase tracking
init_state() {
    local ENGAGEMENT_DIR="$1"
    local STATE_FILE="$ENGAGEMENT_DIR/state.json"

    cat > "$STATE_FILE" << EOF
{
  "engagement_id": "$ENGAGEMENT_NAME",
  "target": "$TARGET",
  "created_at": "$(date -Iseconds)",
  "phase": "init",
  "phase_history": [
    {
      "phase": "init",
      "entered_at": "$(date -Iseconds)",
      "exited_at": null,
      "exit_reason": null
    }
  ],
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
  "phase_metrics": {
    "recon": {"tasks_completed": 0, "assets_discovered": 0, "ports_found": 0},
    "enumeration": {"services_enumerated": 0, "endpoints_found": 0},
    "vulnerability": {"vulns_found": 0, "confirmed": 0},
    "exploitation": {"attempts": 0, "successes": 0},
    "post_exploitation": {"privesc_achieved": false, "creds_harvested": 0}
  },
  "regression_triggers": [],
  "flags": {
    "user": null,
    "root": null
  }
}
EOF
    status "Created state.json (PTES-enhanced)"
}

# Initialize plan.json with PTES phases, completion criteria, and regression triggers
init_plan() {
    local ENGAGEMENT_DIR="$1"
    local PLAN_FILE="$ENGAGEMENT_DIR/plan.json"

    cat > "$PLAN_FILE" << 'EOF'
{
  "version": "2.0",
  "methodology": "PTES",
  "strategy": "auto_progress",
  "phases": [
    {
      "id": 1,
      "name": "recon",
      "ptes_phase": "intelligence_gathering",
      "parallel": true,
      "tasks": [
        {"id": "recon-ports", "agent": "shadow", "action": "port_scan", "priority": 1, "required": true},
        {"id": "recon-subs", "agent": "shadow", "action": "subdomain_enum", "priority": 1, "required": false},
        {"id": "recon-tech", "agent": "shadow", "action": "tech_detect", "priority": 2, "required": true}
      ],
      "completion_criteria": {
        "min_tasks_complete": 2,
        "required_tasks_complete": true,
        "min_ports_discovered": 1
      },
      "exit_triggers": ["tasks_done", "timeout_30m"]
    },
    {
      "id": 2,
      "name": "enumeration",
      "ptes_phase": "threat_modeling",
      "parallel": true,
      "depends_on": ["recon"],
      "triggers": {
        "port_80_443": {"agent": "spider", "action": "web_enum"},
        "port_445": {"agent": "phantom", "action": "smb_enum"},
        "port_22": {"agent": "phantom", "action": "ssh_enum"},
        "port_3389": {"agent": "phantom", "action": "rdp_enum"},
        "api_detected": {"agent": "interceptor", "action": "api_enum"},
        "llm_detected": {"agent": "mindbender", "action": "llm_probe"},
        "cloud_detected": {"agent": "skybreaker", "action": "cloud_enum"}
      },
      "completion_criteria": {
        "all_triggered_tasks_complete": true,
        "min_services_enumerated": 1
      },
      "regression_triggers": {
        "new_ports_discovered": {"action": "regress_to_recon", "reason": "New attack surface found"},
        "new_subdomains_found": {"action": "regress_to_recon", "reason": "Expanded scope discovered"}
      },
      "exit_triggers": ["tasks_done", "no_more_triggers"]
    },
    {
      "id": 3,
      "name": "vulnerability",
      "ptes_phase": "vulnerability_analysis",
      "parallel": true,
      "depends_on": ["enumeration"],
      "triggers": {
        "web_app": {"agent": "spider", "action": "vuln_scan"},
        "api_endpoint": {"agent": "interceptor", "action": "api_test"},
        "smb_share": {"agent": "phantom", "action": "smb_attack"},
        "ad_detected": {"agent": "phantom", "action": "ad_enum"},
        "llm_endpoint": {"agent": "mindbender", "action": "llm_attack"},
        "cloud_misconfig": {"agent": "skybreaker", "action": "cloud_exploit"}
      },
      "completion_criteria": {
        "all_triggered_tasks_complete": true,
        "min_findings": 0
      },
      "regression_triggers": {
        "new_endpoints_discovered": {"action": "regress_to_enumeration", "reason": "New endpoints need enumeration"},
        "auth_bypass_found": {"action": "expand_enumeration", "reason": "New access enables deeper enum"}
      },
      "exit_triggers": ["tasks_done", "high_confidence_vuln_found"]
    },
    {
      "id": 4,
      "name": "exploitation",
      "ptes_phase": "exploitation",
      "parallel": false,
      "depends_on": ["vulnerability"],
      "requires_approval": false,
      "entry_criteria": {
        "min_vulns_found": 1,
        "vuln_severity_threshold": "medium"
      },
      "completion_criteria": {
        "shell_obtained": true
      },
      "regression_triggers": {
        "exploit_failed": {"action": "regress_to_vulnerability", "reason": "Need more vulns to try"},
        "new_vuln_during_exploit": {"action": "log_and_continue", "reason": "Document for later"}
      },
      "exit_triggers": ["shell_obtained", "all_exploits_exhausted"]
    },
    {
      "id": 5,
      "name": "post_exploitation",
      "ptes_phase": "post_exploitation",
      "parallel": true,
      "depends_on": ["exploitation"],
      "tasks": [
        {"id": "privesc", "agent": "persistence", "action": "privilege_escalation", "priority": 1},
        {"id": "creds", "agent": "persistence", "action": "credential_harvest", "priority": 2},
        {"id": "lateral", "agent": "persistence", "action": "lateral_movement", "priority": 3}
      ],
      "completion_criteria": {
        "root_or_system": true
      },
      "regression_triggers": {
        "new_network_segment": {"action": "regress_to_recon", "reason": "New network to scan"},
        "new_credentials": {"action": "expand_lateral", "reason": "Try creds on other systems"}
      },
      "exit_triggers": ["root_obtained", "lateral_exhausted"]
    },
    {
      "id": 6,
      "name": "reporting",
      "ptes_phase": "reporting",
      "parallel": false,
      "depends_on": ["post_exploitation"],
      "tasks": [
        {"id": "report-gen", "agent": "scribe", "action": "generate_report", "priority": 1}
      ],
      "completion_criteria": {
        "report_generated": true,
        "all_findings_documented": true
      },
      "exit_triggers": ["report_complete"]
    }
  ],
  "global_regression_rules": {
    "critical_finding_any_phase": "log_immediately",
    "scope_expansion_detected": "pause_and_verify",
    "new_high_value_target": "evaluate_regression"
  }
}
EOF
    status "Created plan.json (PTES v2.0 with completion criteria)"
}

# Initialize findings.json with enhanced schema (ATT&CK, CVSS 4.0, CWE/CVE)
init_findings() {
    local ENGAGEMENT_DIR="$1"
    local FINDINGS_FILE="$ENGAGEMENT_DIR/findings.json"

    cat > "$FINDINGS_FILE" << EOF
{
  "engagement_id": "$ENGAGEMENT_NAME",
  "schema_version": "2.0",
  "findings": [],
  "assets": [],
  "credentials": [],
  "last_updated": "$(date -Iseconds)",
  "_schema": {
    "finding_template": {
      "id": "finding_<timestamp>",
      "severity": "critical|high|medium|low|info",
      "title": "string",
      "description": "string",
      "agent": "string",
      "discovered_at": "ISO8601",
      "phase": "recon|enumeration|vulnerability|exploitation|post_exploitation",
      "status": "new|confirmed|exploited|documented|remediated",
      "evidence": ["paths"],
      "attack": {
        "mitre_technique": "T<number>",
        "mitre_tactic": "string",
        "mitre_url": "https://attack.mitre.org/techniques/T<number>"
      },
      "classification": {
        "cwe_id": "CWE-<number>",
        "cwe_name": "string",
        "cve_id": "CVE-<year>-<number>",
        "owasp_category": "string"
      },
      "cvss": {
        "version": "4.0",
        "score": 0.0,
        "severity": "None|Low|Medium|High|Critical",
        "vector": "CVSS:4.0/AV:X/AC:X/AT:X/PR:X/UI:X/VC:X/VI:X/VA:X/SC:X/SI:X/SA:X",
        "exploitability": {
          "attack_vector": "Network|Adjacent|Local|Physical",
          "attack_complexity": "Low|High",
          "attack_requirements": "None|Present",
          "privileges_required": "None|Low|High",
          "user_interaction": "None|Passive|Active"
        },
        "impact": {
          "vuln_conf": "None|Low|High",
          "vuln_integ": "None|Low|High",
          "vuln_avail": "None|Low|High",
          "subseq_conf": "None|Low|High",
          "subseq_integ": "None|Low|High",
          "subseq_avail": "None|Low|High"
        }
      }
    },
    "asset_template": {
      "type": "host|port|subdomain|url|endpoint|service|email|user",
      "value": "string",
      "info": "string",
      "discovered_by": "agent",
      "discovered_at": "ISO8601",
      "phase": "string",
      "tags": ["web", "api", "smb", "ssh", "ad", "cloud", "llm"]
    }
  }
}
EOF
    status "Created findings.json (schema v2.0 with ATT&CK/CVSS4.0/CWE)"
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
