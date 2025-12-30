#!/bin/bash
#
# GHOST Report Generator
# Generate professional penetration test reports from findings
#
# Usage:
#   ghost-report.sh generate <type> [engagement_id]  - Generate report (executive/technical/full)
#   ghost-report.sh template list                     - List available templates
#   ghost-report.sh compliance <framework>            - Map findings to compliance framework
#   ghost-report.sh cvss <finding_id>                 - Calculate/display CVSS score breakdown
#   ghost-report.sh export <format>                   - Export report (md/html/pdf/json)
#
# Version: 1.0
# Part of GHOST (Guided Hacking Operations & Security Testing)
#

set -e

# ============================================================================
# Configuration
# ============================================================================

GHOST_ROOT="/tmp/ghost"
ENGAGEMENT="${GHOST_ENGAGEMENT:-$GHOST_ROOT/active}"
[ -L "$ENGAGEMENT" ] && ENGAGEMENT=$(readlink -f "$ENGAGEMENT")

FINDINGS_FILE="$ENGAGEMENT/findings.json"
STATE_FILE="$ENGAGEMENT/state.json"
REPORTS_DIR="$ENGAGEMENT/reports"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="$(dirname "$SCRIPT_DIR")/templates"
COMPLIANCE_FILE="$TEMPLATES_DIR/compliance-mappings.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Utility Functions
# ============================================================================

status() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[!]${NC} $1" >&2; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

# Check prerequisites
check_prereqs() {
    if [ ! -f "$FINDINGS_FILE" ]; then
        error "No findings file found at $FINDINGS_FILE"
        error "Initialize an engagement first: ghost-parallel-init.sh <name> <target>"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed"
        exit 1
    fi

    mkdir -p "$REPORTS_DIR"
}

# Get current timestamp
get_timestamp() {
    date -Iseconds
}

# Get engagement metadata
get_engagement_meta() {
    local key="$1"
    jq -r ".$key // \"N/A\"" "$STATE_FILE" 2>/dev/null || echo "N/A"
}

# ============================================================================
# CVSS Functions
# ============================================================================

# Calculate CVSS severity from score
get_cvss_severity() {
    local score="$1"
    if (( $(echo "$score >= 9.0" | bc -l) )); then echo "Critical"
    elif (( $(echo "$score >= 7.0" | bc -l) )); then echo "High"
    elif (( $(echo "$score >= 4.0" | bc -l) )); then echo "Medium"
    elif (( $(echo "$score >= 0.1" | bc -l) )); then echo "Low"
    else echo "None"
    fi
}

# Display CVSS breakdown for a finding
display_cvss() {
    local finding_id="$1"

    if [ -z "$finding_id" ]; then
        error "Usage: ghost-report.sh cvss <finding_id>"
        exit 1
    fi

    local finding=$(jq -r --arg id "$finding_id" '.findings[] | select(.id == $id)' "$FINDINGS_FILE")

    if [ -z "$finding" ] || [ "$finding" = "null" ]; then
        error "Finding not found: $finding_id"
        exit 1
    fi

    local title=$(echo "$finding" | jq -r '.title')
    local cvss_score=$(echo "$finding" | jq -r '.cvss.score // "N/A"')
    local cvss_severity=$(echo "$finding" | jq -r '.cvss.severity // "N/A"')
    local cwe=$(echo "$finding" | jq -r '.classification.cwe_id // "N/A"')
    local cve=$(echo "$finding" | jq -r '.classification.cve_id // "N/A"')
    local mitre=$(echo "$finding" | jq -r '.attack.mitre_technique // "N/A"')

    echo ""
    echo -e "${BOLD}CVSS Breakdown: $title${NC}"
    echo "=================================================="
    echo ""
    echo -e "  ${CYAN}CVSS 4.0 Score:${NC}    $cvss_score"
    echo -e "  ${CYAN}Severity:${NC}          $cvss_severity"
    echo ""
    echo -e "  ${CYAN}Classification:${NC}"
    echo "    CWE:             $cwe"
    echo "    CVE:             $cve"
    echo "    MITRE ATT&CK:    $mitre"
    echo ""

    # CVSS 4.0 metric breakdown (example structure)
    echo -e "  ${CYAN}CVSS 4.0 Metrics:${NC}"
    echo "    Attack Vector (AV):       Network (N)"
    echo "    Attack Complexity (AC):   Low (L)"
    echo "    Attack Requirements (AT): None (N)"
    echo "    Privileges Required (PR): None (N)"
    echo "    User Interaction (UI):    None (N)"
    echo ""
    echo "    Vulnerable System Impact:"
    echo "      Confidentiality (VC):   High (H)"
    echo "      Integrity (VI):         High (H)"
    echo "      Availability (VA):      None (N)"
    echo ""
    echo "    Subsequent System Impact:"
    echo "      Confidentiality (SC):   None (N)"
    echo "      Integrity (SI):         None (N)"
    echo "      Availability (SA):      None (N)"
    echo ""
    echo -e "  ${CYAN}Vector String:${NC}"
    echo "    CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
    echo ""
    echo -e "  ${CYAN}Calculator:${NC} https://www.first.org/cvss/calculator/4.0"
    echo ""
}

# ============================================================================
# Template Functions
# ============================================================================

# List available templates
list_templates() {
    echo ""
    echo -e "${BOLD}Available Report Templates${NC}"
    echo "=================================================="
    echo ""

    if [ -d "$TEMPLATES_DIR" ]; then
        for template in "$TEMPLATES_DIR"/*.md; do
            if [ -f "$template" ]; then
                local name=$(basename "$template" .md)
                local desc=$(head -5 "$template" | grep -oP '(?<=^> ).*' | head -1 || echo "No description")
                echo -e "  ${CYAN}$name${NC}"
                echo "    $desc"
                echo ""
            fi
        done
    else
        warning "Templates directory not found: $TEMPLATES_DIR"
    fi

    echo "Template Location: $TEMPLATES_DIR"
    echo ""
}

# ============================================================================
# Compliance Mapping Functions
# ============================================================================

# Map findings to compliance framework
map_compliance() {
    local framework="$1"

    if [ -z "$framework" ]; then
        echo ""
        echo -e "${BOLD}Available Compliance Frameworks${NC}"
        echo "=================================================="
        echo ""
        echo "  nist     - NIST 800-53 Security Controls"
        echo "  iso27001 - ISO 27001:2022 Controls"
        echo "  pci      - PCI DSS v4.0 Requirements"
        echo "  owasp    - OWASP Top 10 (2021)"
        echo "  all      - Map to all frameworks"
        echo ""
        echo "Usage: ghost-report.sh compliance <framework>"
        echo ""
        return
    fi

    check_prereqs

    if [ ! -f "$COMPLIANCE_FILE" ]; then
        error "Compliance mappings not found: $COMPLIANCE_FILE"
        exit 1
    fi

    echo ""
    echo -e "${BOLD}Compliance Mapping: $(echo "$framework" | tr '[:lower:]' '[:upper:]')${NC}"
    echo "=================================================="
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # Get all findings with CWE IDs
    local findings=$(jq -r '.findings[] | select(.classification.cwe_id != null)' "$FINDINGS_FILE")

    if [ -z "$findings" ]; then
        warning "No findings with CWE classifications found"
        return
    fi

    # Process each finding
    jq -r '.findings[] | select(.classification.cwe_id != null) |
        "\(.id)|\(.severity)|\(.title)|\(.classification.cwe_id)"' "$FINDINGS_FILE" | \
    while IFS='|' read -r id severity title cwe; do
        echo -e "${CYAN}Finding:${NC} $title"
        echo "  ID:       $id"
        echo "  Severity: $severity"
        echo "  CWE:      $cwe"
        echo ""

        # Look up compliance mappings for this CWE
        case "$framework" in
            nist|NIST)
                local controls=$(jq -r --arg cwe "$cwe" '.nist_800_53[$cwe] // []' "$COMPLIANCE_FILE" 2>/dev/null)
                if [ -n "$controls" ] && [ "$controls" != "[]" ]; then
                    echo "  NIST 800-53 Controls:"
                    echo "$controls" | jq -r '.[]' 2>/dev/null | sed 's/^/    - /'
                fi
                ;;
            iso27001|iso|ISO)
                local controls=$(jq -r --arg cwe "$cwe" '.iso_27001[$cwe] // []' "$COMPLIANCE_FILE" 2>/dev/null)
                if [ -n "$controls" ] && [ "$controls" != "[]" ]; then
                    echo "  ISO 27001:2022 Controls:"
                    echo "$controls" | jq -r '.[]' 2>/dev/null | sed 's/^/    - /'
                fi
                ;;
            pci|PCI)
                local reqs=$(jq -r --arg cwe "$cwe" '.pci_dss[$cwe] // []' "$COMPLIANCE_FILE" 2>/dev/null)
                if [ -n "$reqs" ] && [ "$reqs" != "[]" ]; then
                    echo "  PCI DSS v4.0 Requirements:"
                    echo "$reqs" | jq -r '.[]' 2>/dev/null | sed 's/^/    - /'
                fi
                ;;
            owasp|OWASP)
                local cats=$(jq -r --arg cwe "$cwe" '.owasp_top10[$cwe] // "N/A"' "$COMPLIANCE_FILE" 2>/dev/null)
                echo "  OWASP Top 10: $cats"
                ;;
            all)
                echo "  Compliance Mappings:"
                local nist=$(jq -r --arg cwe "$cwe" '.nist_800_53[$cwe] // []' "$COMPLIANCE_FILE" 2>/dev/null)
                local iso=$(jq -r --arg cwe "$cwe" '.iso_27001[$cwe] // []' "$COMPLIANCE_FILE" 2>/dev/null)
                local pci=$(jq -r --arg cwe "$cwe" '.pci_dss[$cwe] // []' "$COMPLIANCE_FILE" 2>/dev/null)
                local owasp=$(jq -r --arg cwe "$cwe" '.owasp_top10[$cwe] // "N/A"' "$COMPLIANCE_FILE" 2>/dev/null)

                echo "    OWASP Top 10: $owasp"
                [ "$nist" != "[]" ] && echo "$nist" | jq -r '.[]' 2>/dev/null | sed 's/^/    NIST: /'
                [ "$iso" != "[]" ] && echo "$iso" | jq -r '.[]' 2>/dev/null | sed 's/^/    ISO: /'
                [ "$pci" != "[]" ] && echo "$pci" | jq -r '.[]' 2>/dev/null | sed 's/^/    PCI: /'
                ;;
        esac
        echo ""
    done
}

# ============================================================================
# Report Generation Functions
# ============================================================================

# Calculate aggregate risk score
calculate_risk_score() {
    local critical=$(jq '[.findings[] | select(.severity == "critical")] | length' "$FINDINGS_FILE")
    local high=$(jq '[.findings[] | select(.severity == "high")] | length' "$FINDINGS_FILE")
    local medium=$(jq '[.findings[] | select(.severity == "medium")] | length' "$FINDINGS_FILE")
    local low=$(jq '[.findings[] | select(.severity == "low")] | length' "$FINDINGS_FILE")

    # Weighted score: Critical=40, High=10, Medium=3, Low=1
    local score=$((critical * 40 + high * 10 + medium * 3 + low * 1))

    # Determine risk level
    if [ "$score" -ge 100 ]; then echo "CRITICAL"
    elif [ "$score" -ge 50 ]; then echo "HIGH"
    elif [ "$score" -ge 20 ]; then echo "MEDIUM"
    elif [ "$score" -ge 1 ]; then echo "LOW"
    else echo "MINIMAL"
    fi
}

# Generate table of contents
generate_toc() {
    local report_type="$1"

    echo "## Table of Contents"
    echo ""
    echo "1. [Executive Summary](#executive-summary)"
    echo "2. [Engagement Overview](#engagement-overview)"
    echo "3. [Scope](#scope)"
    echo "4. [Risk Summary](#risk-summary)"

    if [ "$report_type" = "technical" ] || [ "$report_type" = "full" ]; then
        echo "5. [Detailed Findings](#detailed-findings)"
        echo "   - [Critical Findings](#critical-findings)"
        echo "   - [High Findings](#high-findings)"
        echo "   - [Medium Findings](#medium-findings)"
        echo "   - [Low Findings](#low-findings)"
        echo "6. [Remediation Summary](#remediation-summary)"
        echo "7. [Compliance Mapping](#compliance-mapping)"
        echo "8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)"
    fi

    echo "9. [Appendices](#appendices)"
    echo ""
}

# Generate executive summary section
generate_executive_summary() {
    local risk_level=$(calculate_risk_score)
    local critical=$(jq '[.findings[] | select(.severity == "critical")] | length' "$FINDINGS_FILE")
    local high=$(jq '[.findings[] | select(.severity == "high")] | length' "$FINDINGS_FILE")
    local medium=$(jq '[.findings[] | select(.severity == "medium")] | length' "$FINDINGS_FILE")
    local low=$(jq '[.findings[] | select(.severity == "low")] | length' "$FINDINGS_FILE")
    local total=$((critical + high + medium + low))

    local engagement_name=$(get_engagement_meta "engagement_name")
    local target=$(get_engagement_meta "target")
    local phase=$(get_engagement_meta "current_phase")

    cat << EOF
## Executive Summary

This penetration test was conducted to evaluate the security posture of the target systems and identify vulnerabilities that could be exploited by malicious actors.

### Key Findings

| Metric | Value |
|--------|-------|
| **Overall Risk Level** | $risk_level |
| **Total Vulnerabilities** | $total |
| **Critical** | $critical |
| **High** | $high |
| **Medium** | $medium |
| **Low** | $low |

### Risk Distribution

\`\`\`
Critical: $critical $(printf '%.0s#' $(seq 1 $critical))
High:     $high $(printf '%.0s#' $(seq 1 $high))
Medium:   $medium $(printf '%.0s#' $(seq 1 $medium))
Low:      $low $(printf '%.0s#' $(seq 1 $low))
\`\`\`

### Critical Issues Requiring Immediate Attention

EOF

    # List critical findings
    jq -r '.findings[] | select(.severity == "critical") |
        "- **\(.title)** - \(.description // "See detailed findings")"' "$FINDINGS_FILE" 2>/dev/null || echo "- No critical findings"

    echo ""
    echo "### Strategic Recommendations"
    echo ""
    echo "1. **Immediate**: Address all critical and high severity findings within 7 days"
    echo "2. **Short-term**: Implement security controls to prevent exploitation"
    echo "3. **Long-term**: Establish continuous security testing program"
    echo ""
}

# Generate engagement overview section
generate_engagement_overview() {
    local engagement_name=$(get_engagement_meta "engagement_name")
    local target=$(get_engagement_meta "target")
    local start_time=$(get_engagement_meta "started_at")
    local phase=$(get_engagement_meta "current_phase")

    cat << EOF
## Engagement Overview

| Field | Value |
|-------|-------|
| **Engagement Name** | $engagement_name |
| **Target** | $target |
| **Start Date** | $start_time |
| **Report Generated** | $(date '+%Y-%m-%d %H:%M:%S') |
| **Current Phase** | $phase |
| **Report Version** | 1.0 |

### Testing Methodology

This assessment followed the PTES (Penetration Testing Execution Standard) methodology:

1. **Pre-engagement Interactions** - Scope definition and authorization
2. **Intelligence Gathering** - Passive and active reconnaissance
3. **Threat Modeling** - Identifying attack vectors
4. **Vulnerability Analysis** - Discovery and validation
5. **Exploitation** - Controlled exploitation of vulnerabilities
6. **Post-Exploitation** - Impact assessment
7. **Reporting** - Documentation and recommendations

EOF
}

# Generate findings section
generate_findings_section() {
    local severity="$1"
    local severity_upper=$(echo "$severity" | tr '[:lower:]' '[:upper:]')

    echo "### ${severity_upper} Findings"
    echo ""

    local findings=$(jq -r --arg sev "$severity" '.findings[] | select(.severity == $sev)' "$FINDINGS_FILE")

    if [ -z "$findings" ] || [ "$findings" = "" ]; then
        echo "_No ${severity} severity findings._"
        echo ""
        return
    fi

    # Process each finding
    jq -r --arg sev "$severity" '.findings[] | select(.severity == $sev) | @base64' "$FINDINGS_FILE" | \
    while read -r finding_b64; do
        local finding=$(echo "$finding_b64" | base64 -d)

        local id=$(echo "$finding" | jq -r '.id')
        local title=$(echo "$finding" | jq -r '.title')
        local desc=$(echo "$finding" | jq -r '.description // "No description provided"')
        local cvss_score=$(echo "$finding" | jq -r '.cvss.score // "N/A"')
        local cvss_sev=$(echo "$finding" | jq -r '.cvss.severity // "N/A"')
        local cwe=$(echo "$finding" | jq -r '.classification.cwe_id // "N/A"')
        local cve=$(echo "$finding" | jq -r '.classification.cve_id // "N/A"')
        local mitre=$(echo "$finding" | jq -r '.attack.mitre_technique // "N/A"')
        local agent=$(echo "$finding" | jq -r '.agent // "N/A"')
        local phase=$(echo "$finding" | jq -r '.phase // "N/A"')
        local discovered=$(echo "$finding" | jq -r '.discovered_at // "N/A"')

        cat << EOF
#### $title

| Attribute | Value |
|-----------|-------|
| **Finding ID** | \`$id\` |
| **CVSS 4.0 Score** | $cvss_score ($cvss_sev) |
| **CWE** | $cwe |
| **CVE** | $cve |
| **MITRE ATT&CK** | $mitre |
| **Discovered By** | $agent |
| **Phase** | $phase |
| **Discovered At** | $discovered |

**Description:**
$desc

**Remediation:**
- Implement input validation and sanitization
- Apply principle of least privilege
- Follow secure coding guidelines
- See remediation guide for specific fixes

---

EOF
    done
}

# Generate MITRE ATT&CK mapping section
generate_mitre_section() {
    echo "## MITRE ATT&CK Mapping"
    echo ""
    echo "| Technique ID | Technique Name | Finding |"
    echo "|--------------|----------------|---------|"

    jq -r '.findings[] | select(.attack.mitre_technique != null) |
        "| \(.attack.mitre_technique) | [View](https://attack.mitre.org/techniques/\(.attack.mitre_technique)/) | \(.title) |"' "$FINDINGS_FILE" 2>/dev/null || echo "| N/A | N/A | No MITRE mappings |"

    echo ""
}

# Generate remediation summary
generate_remediation_summary() {
    echo "## Remediation Summary"
    echo ""
    echo "### Priority Matrix"
    echo ""
    echo "| Priority | Severity | Timeline | Actions Required |"
    echo "|----------|----------|----------|------------------|"
    echo "| P1 | Critical | Immediate (24-48 hrs) | Emergency patching, network isolation |"
    echo "| P2 | High | Short-term (1-2 weeks) | Patching, configuration changes |"
    echo "| P3 | Medium | Medium-term (1-3 months) | Security hardening, process updates |"
    echo "| P4 | Low | Long-term (3-6 months) | Best practice implementation |"
    echo ""
    echo "### Remediation by Finding"
    echo ""

    jq -r '.findings[] | "- **\(.title)** (\(.severity)): Address \(.classification.cwe_id // "security issue")"' "$FINDINGS_FILE" 2>/dev/null

    echo ""
}

# Generate full report
generate_report() {
    local report_type="${1:-full}"
    local engagement_id="${2:-}"
    local output_file="$REPORTS_DIR/ghost-report-$(date +%Y%m%d-%H%M%S).md"

    check_prereqs

    info "Generating $report_type report..."

    {
        # Header
        echo "# GHOST Penetration Test Report"
        echo ""
        echo "> Generated by GHOST (Guided Hacking Operations & Security Testing)"
        echo "> Report Type: $(echo "$report_type" | tr '[:lower:]' '[:upper:]')"
        echo "> Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "---"
        echo ""

        # Table of Contents
        generate_toc "$report_type"

        # Executive Summary
        generate_executive_summary

        # Engagement Overview
        generate_engagement_overview

        # Scope section
        echo "## Scope"
        echo ""
        echo "### In-Scope Assets"
        echo ""
        jq -r '.assets[] | "- **\(.type)**: \(.value) (\(.info // ""))"' "$FINDINGS_FILE" 2>/dev/null | head -20 || echo "- See engagement scope document"
        echo ""

        # Technical sections for technical/full reports
        if [ "$report_type" = "technical" ] || [ "$report_type" = "full" ]; then
            echo "## Detailed Findings"
            echo ""

            generate_findings_section "critical"
            generate_findings_section "high"
            generate_findings_section "medium"
            generate_findings_section "low"

            generate_remediation_summary

            echo "## Compliance Mapping"
            echo ""
            echo "See compliance report: \`ghost-report.sh compliance all\`"
            echo ""

            generate_mitre_section
        fi

        # Appendices
        echo "## Appendices"
        echo ""
        echo "### A. Testing Tools"
        echo ""
        echo "- Nmap - Network discovery and security auditing"
        echo "- Burp Suite - Web application security testing"
        echo "- SQLMap - SQL injection detection and exploitation"
        echo "- Nuclei - Vulnerability scanning"
        echo "- Custom scripts - GHOST agent toolkit"
        echo ""
        echo "### B. References"
        echo ""
        echo "- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)"
        echo "- [PTES Standard](http://www.pentest-standard.org/)"
        echo "- [MITRE ATT&CK](https://attack.mitre.org/)"
        echo "- [CVSS 4.0 Calculator](https://www.first.org/cvss/calculator/4.0)"
        echo ""
        echo "---"
        echo ""
        echo "_Report generated by GHOST v2.3_"
        echo "_\"Hack ethically. Document thoroughly. Improve security.\"_"

    } > "$output_file"

    status "Report generated: $output_file"
    echo ""
    info "Report Statistics:"
    echo "  Lines: $(wc -l < "$output_file")"
    echo "  Size:  $(du -h "$output_file" | cut -f1)"
    echo ""
}

# ============================================================================
# Export Functions
# ============================================================================

# Export report in various formats
export_report() {
    local format="${1:-md}"
    local latest_report=$(ls -t "$REPORTS_DIR"/*.md 2>/dev/null | head -1)

    if [ -z "$latest_report" ]; then
        warning "No reports found. Generate one first: ghost-report.sh generate"
        return 1
    fi

    case "$format" in
        md|markdown)
            cat "$latest_report"
            ;;
        html)
            info "Converting to HTML..."
            local html_file="${latest_report%.md}.html"

            # Simple markdown to HTML conversion
            {
                echo "<!DOCTYPE html>"
                echo "<html><head>"
                echo "<title>GHOST Security Report</title>"
                echo "<style>"
                echo "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }"
                echo "table { border-collapse: collapse; width: 100%; margin: 20px 0; }"
                echo "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
                echo "th { background-color: #2c3e50; color: white; }"
                echo "h1 { color: #2c3e50; }"
                echo "h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }"
                echo "h3 { color: #7f8c8d; }"
                echo "code { background-color: #f8f9fa; padding: 2px 6px; border-radius: 3px; }"
                echo "pre { background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }"
                echo ".critical { color: #c0392b; font-weight: bold; }"
                echo ".high { color: #e74c3c; }"
                echo ".medium { color: #f39c12; }"
                echo ".low { color: #27ae60; }"
                echo "</style>"
                echo "</head><body>"

                # Basic markdown conversion
                sed -e 's/^# \(.*\)/<h1>\1<\/h1>/' \
                    -e 's/^## \(.*\)/<h2>\1<\/h2>/' \
                    -e 's/^### \(.*\)/<h3>\1<\/h3>/' \
                    -e 's/^#### \(.*\)/<h4>\1<\/h4>/' \
                    -e 's/\*\*\([^*]*\)\*\*/<strong>\1<\/strong>/g' \
                    -e 's/`\([^`]*\)`/<code>\1<\/code>/g' \
                    -e 's/^- \(.*\)/<li>\1<\/li>/' \
                    -e 's/^---$/<hr>/' \
                    -e 's/^|.*|$/<tr><td>&<\/td><\/tr>/' \
                    "$latest_report"

                echo "</body></html>"
            } > "$html_file"

            status "HTML export: $html_file"
            ;;
        json)
            info "Exporting as JSON..."
            local json_file="${latest_report%.md}.json"

            jq -n \
                --arg title "GHOST Security Report" \
                --arg generated "$(date -Iseconds)" \
                --slurpfile findings "$FINDINGS_FILE" \
                '{
                    title: $title,
                    generated: $generated,
                    findings: $findings[0].findings,
                    assets: $findings[0].assets,
                    credentials: $findings[0].credentials
                }' > "$json_file"

            status "JSON export: $json_file"
            ;;
        pdf)
            info "PDF export requires pandoc and LaTeX"

            if command -v pandoc &> /dev/null; then
                local pdf_file="${latest_report%.md}.pdf"
                pandoc "$latest_report" -o "$pdf_file" --pdf-engine=xelatex 2>/dev/null && \
                    status "PDF export: $pdf_file" || \
                    warning "PDF generation failed. Install: pandoc, texlive-xetex"
            else
                warning "pandoc not installed. Install with: apt install pandoc texlive-xetex"
            fi
            ;;
        *)
            error "Unknown format: $format"
            echo "Supported formats: md, html, json, pdf"
            exit 1
            ;;
    esac
}

# ============================================================================
# Main Command Handler
# ============================================================================

show_help() {
    echo ""
    echo -e "${BOLD}GHOST Report Generator v1.0${NC}"
    echo ""
    echo "Generate professional penetration test reports from GHOST findings."
    echo ""
    echo -e "${CYAN}Usage:${NC}"
    echo "  ghost-report.sh <command> [args]"
    echo ""
    echo -e "${CYAN}Commands:${NC}"
    echo "  generate <type> [id]    Generate report (executive/technical/full)"
    echo "  template list           List available templates"
    echo "  compliance <framework>  Map findings to compliance framework"
    echo "  cvss <finding_id>       Display CVSS score breakdown"
    echo "  export <format>         Export report (md/html/pdf/json)"
    echo ""
    echo -e "${CYAN}Report Types:${NC}"
    echo "  executive    1-2 page summary for leadership"
    echo "  technical    Detailed findings with PoC and remediation"
    echo "  full         Complete report with all sections"
    echo ""
    echo -e "${CYAN}Compliance Frameworks:${NC}"
    echo "  nist         NIST 800-53 Security Controls"
    echo "  iso27001     ISO 27001:2022 Controls"
    echo "  pci          PCI DSS v4.0 Requirements"
    echo "  owasp        OWASP Top 10 (2021)"
    echo "  all          Map to all frameworks"
    echo ""
    echo -e "${CYAN}Export Formats:${NC}"
    echo "  md           Markdown (default)"
    echo "  html         HTML with styling"
    echo "  json         JSON structured data"
    echo "  pdf          PDF (requires pandoc)"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  ghost-report.sh generate executive"
    echo "  ghost-report.sh generate technical"
    echo "  ghost-report.sh compliance pci"
    echo "  ghost-report.sh cvss finding_1234567890"
    echo "  ghost-report.sh export html"
    echo ""
    echo -e "${CYAN}Environment:${NC}"
    echo "  GHOST_ENGAGEMENT    Path to engagement directory"
    echo "                      Default: /tmp/ghost/active"
    echo ""
    echo -e "${CYAN}Files:${NC}"
    echo "  Findings:   $FINDINGS_FILE"
    echo "  Templates:  $TEMPLATES_DIR"
    echo "  Reports:    $REPORTS_DIR"
    echo ""
}

# Main entry point
case "${1:-help}" in
    generate)
        generate_report "${2:-full}" "${3:-}"
        ;;
    template)
        case "${2:-list}" in
            list) list_templates ;;
            *) list_templates ;;
        esac
        ;;
    compliance)
        map_compliance "${2:-}"
        ;;
    cvss)
        check_prereqs
        display_cvss "$2"
        ;;
    export)
        check_prereqs
        export_report "${2:-md}"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        ;;
esac
