#!/bin/bash
#
# GHOST Research Engine
# Real-time CVE lookup, exploit-db search, and web research capabilities
#
# Usage:
#   ghost-research.sh cve <product> [version]      - Search NVD/CVE database
#   ghost-research.sh exploit <query>               - Search exploit-db
#   ghost-research.sh technique <name>              - Get technique info from web
#   ghost-research.sh correlate <service> <version> - Auto-correlate with known CVEs
#   ghost-research.sh github <owner/repo>           - Search GitHub Security Advisories
#   ghost-research.sh cache list|clear|stats        - Manage research cache
#   ghost-research.sh help                          - Show this help
#
# Environment:
#   GHOST_RESEARCH_CACHE - Cache directory (default: /tmp/ghost/research-cache)
#   GHOST_RESEARCH_TTL   - Cache TTL in seconds (default: 3600)
#   NVD_API_KEY          - Optional NVD API key for higher rate limits
#
# Examples:
#   ghost-research.sh cve apache 2.4.49
#   ghost-research.sh exploit "apache struts"
#   ghost-research.sh correlate openssh 7.9p1
#   ghost-research.sh technique kerberoasting
#

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Cache configuration
CACHE_DIR="${GHOST_RESEARCH_CACHE:-/tmp/ghost/research-cache}"
CACHE_TTL="${GHOST_RESEARCH_TTL:-3600}"  # 1 hour default

# API endpoints
NVD_API_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API_BASE="https://api.github.com"
EXPLOITDB_SEARCH_URL="https://www.exploit-db.com/search"

# Rate limiting
RATE_LIMIT_FILE="$CACHE_DIR/.rate_limits"
NVD_RATE_LIMIT=6  # requests per minute without API key
NVD_RATE_LIMIT_WITH_KEY=50  # requests per minute with API key

# Colors (optional, for terminal output)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Print colored output
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Ensure cache directory exists
init_cache() {
    mkdir -p "$CACHE_DIR"/{cve,exploit,technique,correlate,github}
    touch "$RATE_LIMIT_FILE"
}

# Generate cache key from arguments
cache_key() {
    echo "$*" | md5sum | cut -d' ' -f1
}

# Get cached result if valid
get_cache() {
    local category="$1"
    local key="$2"
    local cache_file="$CACHE_DIR/$category/$key.json"

    if [ -f "$cache_file" ]; then
        local file_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [ "$file_age" -lt "$CACHE_TTL" ]; then
            cat "$cache_file"
            return 0
        fi
    fi
    return 1
}

# Save result to cache
set_cache() {
    local category="$1"
    local key="$2"
    local data="$3"
    local cache_file="$CACHE_DIR/$category/$key.json"

    echo "$data" > "$cache_file"
}

# Check rate limit
check_rate_limit() {
    local api="$1"
    local limit="$2"
    local now=$(date +%s)
    local minute_ago=$((now - 60))

    # Clean old entries
    if [ -f "$RATE_LIMIT_FILE" ]; then
        grep -v "^$api:" "$RATE_LIMIT_FILE" > "$RATE_LIMIT_FILE.tmp" 2>/dev/null || true
        grep "^$api:" "$RATE_LIMIT_FILE" | while read line; do
            local ts=$(echo "$line" | cut -d':' -f2)
            if [ "$ts" -gt "$minute_ago" ]; then
                echo "$line"
            fi
        done >> "$RATE_LIMIT_FILE.tmp"
        mv "$RATE_LIMIT_FILE.tmp" "$RATE_LIMIT_FILE"
    fi

    # Count requests in last minute
    local count=0
    if [ -f "$RATE_LIMIT_FILE" ]; then
        count=$(grep -c "^$api:" "$RATE_LIMIT_FILE" 2>/dev/null || echo 0)
    fi

    if [ "$count" -ge "$limit" ]; then
        log_warn "Rate limit reached for $api ($count/$limit per minute). Waiting..."
        sleep $((60 - (now - minute_ago)))
        return 0
    fi

    # Record this request
    echo "$api:$now" >> "$RATE_LIMIT_FILE"
    return 0
}

# URL encode string
urlencode() {
    local string="$1"
    python3 -c "import urllib.parse; print(urllib.parse.quote('$string'))" 2>/dev/null || \
    echo "$string" | sed 's/ /%20/g; s/!/%21/g; s/"/%22/g; s/#/%23/g; s/\$/%24/g; s/&/%26/g; s/'\''/%27/g; s/(/%28/g; s/)/%29/g; s/*/%2A/g; s/+/%2B/g; s/,/%2C/g; s/:/%3A/g; s/;/%3B/g; s/=/%3D/g; s/?/%3F/g; s/@/%40/g'
}

# Check if jq is available
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed. Install with: apt-get install jq"
        exit 1
    fi
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed. Install with: apt-get install curl"
        exit 1
    fi
}

# ============================================================================
# CVE SEARCH (NVD API)
# ============================================================================

search_cve() {
    local product="$1"
    local version="${2:-}"

    log_info "Searching NVD for: $product ${version:+version $version}"

    # Check cache first
    local cache_key_val=$(cache_key "cve" "$product" "$version")
    if cached=$(get_cache "cve" "$cache_key_val"); then
        log_info "Using cached result (TTL: ${CACHE_TTL}s)"
        echo "$cached"
        return 0
    fi

    # Build search query
    local keyword_search=$(urlencode "$product${version:+ $version}")
    local url="${NVD_API_BASE}?keywordSearch=${keyword_search}&resultsPerPage=20"

    # Determine rate limit
    local rate_limit=$NVD_RATE_LIMIT
    local headers=()
    if [ -n "${NVD_API_KEY:-}" ]; then
        rate_limit=$NVD_RATE_LIMIT_WITH_KEY
        headers=(-H "apiKey: $NVD_API_KEY")
    fi

    # Check rate limit
    check_rate_limit "nvd" "$rate_limit"

    # Make request
    log_info "Querying NVD API..."
    local response
    response=$(curl -s -f --connect-timeout 10 --max-time 30 \
        "${headers[@]}" \
        "$url" 2>/dev/null) || {
        log_error "Failed to query NVD API"
        return 1
    }

    # Check for valid response
    if ! echo "$response" | jq -e '.vulnerabilities' > /dev/null 2>&1; then
        log_error "Invalid response from NVD API"
        echo "$response" | head -c 500
        return 1
    fi

    # Extract and format results
    local result
    result=$(echo "$response" | jq '{
        query: {
            product: "'"$product"'",
            version: "'"$version"'"
        },
        total_results: .totalResults,
        results_returned: (.vulnerabilities | length),
        timestamp: (now | todate),
        vulnerabilities: [
            .vulnerabilities[]? | {
                cve_id: .cve.id,
                description: (.cve.descriptions[]? | select(.lang == "en") | .value) // "No description",
                published: .cve.published,
                modified: .cve.lastModified,
                severity: (
                    .cve.metrics.cvssMetricV31[0]?.cvssData.baseSeverity //
                    .cve.metrics.cvssMetricV30[0]?.cvssData.baseSeverity //
                    .cve.metrics.cvssMetricV2[0]?.baseSeverity //
                    "UNKNOWN"
                ),
                cvss_score: (
                    .cve.metrics.cvssMetricV31[0]?.cvssData.baseScore //
                    .cve.metrics.cvssMetricV30[0]?.cvssData.baseScore //
                    .cve.metrics.cvssMetricV2[0]?.cvssData.baseScore //
                    0
                ),
                cvss_vector: (
                    .cve.metrics.cvssMetricV31[0]?.cvssData.vectorString //
                    .cve.metrics.cvssMetricV30[0]?.cvssData.vectorString //
                    .cve.metrics.cvssMetricV2[0]?.cvssData.vectorString //
                    "N/A"
                ),
                references: [.cve.references[]?.url][0:5],
                weaknesses: [.cve.weaknesses[]?.description[]?.value] | unique
            }
        ] | sort_by(-.cvss_score)
    }')

    # Cache result
    set_cache "cve" "$cache_key_val" "$result"

    echo "$result"

    # Summary
    local total=$(echo "$result" | jq -r '.total_results')
    local critical=$(echo "$result" | jq '[.vulnerabilities[] | select(.severity == "CRITICAL")] | length')
    local high=$(echo "$result" | jq '[.vulnerabilities[] | select(.severity == "HIGH")] | length')

    log_success "Found $total CVEs. Critical: $critical, High: $high"
}

# ============================================================================
# EXPLOIT-DB SEARCH
# ============================================================================

search_exploit() {
    local query="$1"

    log_info "Searching Exploit-DB for: $query"

    # Check cache first
    local cache_key_val=$(cache_key "exploit" "$query")
    if cached=$(get_cache "exploit" "$cache_key_val"); then
        log_info "Using cached result (TTL: ${CACHE_TTL}s)"
        echo "$cached"
        return 0
    fi

    # Try searchsploit first if available
    if command -v searchsploit &> /dev/null; then
        log_info "Using local searchsploit..."
        local ss_result
        ss_result=$(searchsploit -j "$query" 2>/dev/null) || ss_result="{}"

        if echo "$ss_result" | jq -e '.RESULTS_EXPLOIT | length > 0' > /dev/null 2>&1; then
            local result
            result=$(echo "$ss_result" | jq '{
                query: "'"$query"'",
                source: "searchsploit",
                timestamp: (now | todate),
                exploits: [
                    .RESULTS_EXPLOIT[]? | {
                        id: .EDB_ID,
                        title: .Title,
                        date: .Date,
                        platform: .Platform,
                        type: .Type,
                        path: .Path,
                        author: .Author,
                        verified: (.Verified == "1"),
                        codes: [.Codes | split(";")[]]
                    }
                ]
            }')

            set_cache "exploit" "$cache_key_val" "$result"
            echo "$result"

            local count=$(echo "$result" | jq '.exploits | length')
            log_success "Found $count exploits via searchsploit"
            return 0
        fi
    fi

    # Fallback: Parse Exploit-DB website
    log_info "Searching Exploit-DB website..."

    local encoded_query=$(urlencode "$query")
    local response
    response=$(curl -s -f --connect-timeout 10 --max-time 30 \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0" \
        "https://www.exploit-db.com/search?q=${encoded_query}" 2>/dev/null) || {
        log_warn "Failed to query Exploit-DB website, trying API..."

        # Try exploit-db.com json endpoint
        response=$(curl -s -f --connect-timeout 10 --max-time 30 \
            -H "User-Agent: Mozilla/5.0" \
            -H "X-Requested-With: XMLHttpRequest" \
            "https://www.exploit-db.com/search?q=${encoded_query}&draw=1" 2>/dev/null) || {
            log_error "Failed to query Exploit-DB"
            return 1
        }
    }

    # Check if we got JSON data (API response) or HTML
    if echo "$response" | jq -e '.data' > /dev/null 2>&1; then
        local result
        result=$(echo "$response" | jq '{
            query: "'"$query"'",
            source: "exploit-db-api",
            timestamp: (now | todate),
            total: .recordsTotal,
            exploits: [
                .data[]? | {
                    id: .id,
                    title: (.description | gsub("<[^>]*>"; "")),
                    date: .date_published,
                    platform: .platform.platform,
                    type: .type.type,
                    verified: .verified,
                    codes: [.codes[]?.code_title]
                }
            ]
        }')

        set_cache "exploit" "$cache_key_val" "$result"
        echo "$result"

        local count=$(echo "$result" | jq '.exploits | length')
        log_success "Found $count exploits"
        return 0
    fi

    # Parse HTML response (fallback)
    log_warn "Parsing HTML response (limited data)..."

    # Extract basic exploit info from HTML using grep/sed
    local result
    result=$(cat << EOF
{
    "query": "$query",
    "source": "exploit-db-html",
    "timestamp": "$(date -Iseconds)",
    "note": "HTML parsing - install searchsploit for better results",
    "exploits": []
}
EOF
)

    set_cache "exploit" "$cache_key_val" "$result"
    echo "$result"
    log_warn "Consider installing searchsploit: apt-get install exploitdb"
}

# ============================================================================
# GITHUB SECURITY ADVISORIES
# ============================================================================

search_github() {
    local repo="$1"

    log_info "Searching GitHub Security Advisories for: $repo"

    # Check cache first
    local cache_key_val=$(cache_key "github" "$repo")
    if cached=$(get_cache "github" "$cache_key_val"); then
        log_info "Using cached result (TTL: ${CACHE_TTL}s)"
        echo "$cached"
        return 0
    fi

    # Check if repo format is valid
    if ! echo "$repo" | grep -q '/'; then
        log_error "Invalid repo format. Use: owner/repository"
        return 1
    fi

    local owner=$(echo "$repo" | cut -d'/' -f1)
    local repository=$(echo "$repo" | cut -d'/' -f2)

    # Build headers
    local headers=(-H "Accept: application/vnd.github+json")
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        headers+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    fi

    # Query GitHub API
    log_info "Querying GitHub API..."
    local response
    response=$(curl -s -f --connect-timeout 10 --max-time 30 \
        "${headers[@]}" \
        "${GITHUB_API_BASE}/repos/${owner}/${repository}/security-advisories" 2>/dev/null) || {

        # Try dependabot alerts as fallback
        log_warn "Security advisories not accessible, trying dependabot alerts..."
        response=$(curl -s -f --connect-timeout 10 --max-time 30 \
            "${headers[@]}" \
            "${GITHUB_API_BASE}/repos/${owner}/${repository}/dependabot/alerts" 2>/dev/null) || {
            log_error "Failed to query GitHub API (may require authentication)"
            return 1
        }
    }

    # Format result
    local result
    result=$(echo "$response" | jq '{
        repository: "'"$repo"'",
        timestamp: (now | todate),
        advisories: [
            .[]? | {
                ghsa_id: .ghsa_id,
                cve_id: .cve_id,
                summary: .summary,
                description: .description,
                severity: .severity,
                published_at: .published_at,
                updated_at: .updated_at,
                vulnerabilities: [.vulnerabilities[]? | {
                    package: .package.name,
                    ecosystem: .package.ecosystem,
                    vulnerable_versions: .vulnerable_version_range,
                    patched_versions: .patched_versions
                }]
            }
        ]
    }' 2>/dev/null || echo "$response" | jq '{
        repository: "'"$repo"'",
        timestamp: (now | todate),
        alerts: [
            .[]? | {
                number: .number,
                state: .state,
                severity: .security_advisory.severity,
                cve_id: .security_advisory.cve_id,
                ghsa_id: .security_advisory.ghsa_id,
                summary: .security_advisory.summary,
                package: .security_vulnerability.package.name,
                vulnerable_range: .security_vulnerability.vulnerable_version_range
            }
        ]
    }')

    set_cache "github" "$cache_key_val" "$result"
    echo "$result"

    log_success "Retrieved security advisories for $repo"
}

# ============================================================================
# TECHNIQUE LOOKUP
# ============================================================================

search_technique() {
    local technique="$1"

    log_info "Searching for technique: $technique"

    # Check cache first
    local cache_key_val=$(cache_key "technique" "$technique")
    if cached=$(get_cache "technique" "$cache_key_val"); then
        log_info "Using cached result (TTL: ${CACHE_TTL}s)"
        echo "$cached"
        return 0
    fi

    # Query multiple sources
    local mitre_result=""
    local hacktricks_result=""

    # Try MITRE ATT&CK
    log_info "Searching MITRE ATT&CK..."
    local encoded_tech=$(urlencode "$technique")

    # Build result from known techniques database (embedded)
    local result
    result=$(cat << 'TECHNIQUES_DB'
{
    "techniques": {
        "kerberoasting": {
            "mitre_id": "T1558.003",
            "name": "Kerberoasting",
            "description": "Request service tickets for service accounts, then crack offline",
            "category": "credential_access",
            "tools": ["Rubeus", "GetUserSPNs.py", "Invoke-Kerberoast"],
            "detection": ["Event ID 4769", "TGS requests for unusual services"],
            "references": [
                "https://attack.mitre.org/techniques/T1558/003/",
                "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast"
            ]
        },
        "asreproasting": {
            "mitre_id": "T1558.004",
            "name": "AS-REP Roasting",
            "description": "Request AS-REP for accounts without pre-auth, crack offline",
            "category": "credential_access",
            "tools": ["Rubeus", "GetNPUsers.py", "kerbrute"],
            "detection": ["Event ID 4768 without pre-auth"],
            "references": [
                "https://attack.mitre.org/techniques/T1558/004/",
                "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast"
            ]
        },
        "pass-the-hash": {
            "mitre_id": "T1550.002",
            "name": "Pass the Hash",
            "description": "Use NTLM hash to authenticate without knowing plaintext password",
            "category": "lateral_movement",
            "tools": ["mimikatz", "impacket", "crackmapexec", "evil-winrm"],
            "detection": ["Event ID 4624 Type 3", "Unusual NTLM auth patterns"],
            "references": [
                "https://attack.mitre.org/techniques/T1550/002/",
                "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/over-pass-the-hash"
            ]
        },
        "sqli": {
            "mitre_id": "T1190",
            "name": "SQL Injection",
            "description": "Insert malicious SQL queries via user input",
            "category": "initial_access",
            "tools": ["sqlmap", "Burp Suite", "manual testing"],
            "detection": ["WAF logs", "Unusual query patterns", "Error messages"],
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://book.hacktricks.xyz/pentesting-web/sql-injection"
            ]
        },
        "xss": {
            "mitre_id": "T1059.007",
            "name": "Cross-Site Scripting",
            "description": "Inject client-side scripts into web pages",
            "category": "execution",
            "tools": ["XSSer", "Burp Suite", "XSS Hunter"],
            "detection": ["CSP violations", "Unusual script execution"],
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting"
            ]
        },
        "ssrf": {
            "mitre_id": "T1090",
            "name": "Server-Side Request Forgery",
            "description": "Force server to make requests to internal resources",
            "category": "discovery",
            "tools": ["Burp Collaborator", "SSRFmap", "gopherus"],
            "detection": ["Unusual outbound requests", "Internal IP access"],
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery"
            ]
        },
        "ssti": {
            "mitre_id": "T1059",
            "name": "Server-Side Template Injection",
            "description": "Inject template syntax to execute code on server",
            "category": "execution",
            "tools": ["tplmap", "Burp Suite", "manual testing"],
            "detection": ["Template error messages", "Unusual render patterns"],
            "references": [
                "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection",
                "https://portswigger.net/research/server-side-template-injection"
            ]
        },
        "jwt": {
            "mitre_id": "T1552",
            "name": "JWT Attacks",
            "description": "Exploit JWT implementation flaws (none algorithm, key confusion)",
            "category": "credential_access",
            "tools": ["jwt_tool", "Burp JWT extension", "jwt.io"],
            "detection": ["Invalid signature acceptance", "Algorithm switching"],
            "references": [
                "https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens",
                "https://portswigger.net/web-security/jwt"
            ]
        }
    }
}
TECHNIQUES_DB
)

    # Search for the technique in our database
    local technique_lower=$(echo "$technique" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
    local found
    found=$(echo "$result" | jq --arg tech "$technique_lower" '
        .techniques[$tech] //
        (.techniques | to_entries | map(select(.key | contains($tech))) | .[0].value) //
        (.techniques | to_entries | map(select(.value.name | ascii_downcase | contains($tech))) | .[0].value)
    ')

    if [ "$found" != "null" ] && [ -n "$found" ]; then
        local output
        output=$(jq -n --argjson tech "$found" --arg query "$technique" '{
            query: $query,
            source: "ghost-research-db",
            timestamp: (now | todate),
            technique: $tech
        }')

        set_cache "technique" "$cache_key_val" "$output"
        echo "$output"
        log_success "Found technique: $technique"
        return 0
    fi

    # Not found in local DB, provide web search suggestion
    local output
    output=$(jq -n --arg query "$technique" '{
        query: $query,
        source: "not-found",
        timestamp: (now | todate),
        suggestion: "Try searching these resources:",
        resources: [
            "https://attack.mitre.org/techniques/",
            "https://book.hacktricks.xyz/",
            "https://www.thehacker.recipes/",
            "https://pentestbook.six2dez.com/"
        ]
    }')

    set_cache "technique" "$cache_key_val" "$output"
    echo "$output"
    log_warn "Technique not found in local database. Check suggested resources."
}

# ============================================================================
# CORRELATE SERVICE/VERSION WITH CVEs
# ============================================================================

correlate_cve() {
    local service="$1"
    local version="$2"

    log_info "Correlating CVEs for: $service $version"

    # Check cache first
    local cache_key_val=$(cache_key "correlate" "$service" "$version")
    if cached=$(get_cache "correlate" "$cache_key_val"); then
        log_info "Using cached result (TTL: ${CACHE_TTL}s)"
        echo "$cached"
        return 0
    fi

    # Normalize service name for known products
    local product="$service"
    case "${service,,}" in
        openssh|ssh)
            product="openssh"
            ;;
        apache|httpd|apache2)
            product="apache http server"
            ;;
        nginx)
            product="nginx"
            ;;
        mysql|mariadb)
            product="mysql"
            ;;
        postgresql|postgres)
            product="postgresql"
            ;;
        vsftpd|proftpd|ftp)
            product="$service"
            ;;
        smb|samba)
            product="samba"
            ;;
        tomcat)
            product="apache tomcat"
            ;;
        iis)
            product="microsoft iis"
            ;;
        exchange)
            product="microsoft exchange"
            ;;
    esac

    # Search NVD
    local cve_result
    cve_result=$(search_cve "$product" "$version" 2>/dev/null) || cve_result="{}"

    # Search exploits
    local exploit_result
    exploit_result=$(search_exploit "$product $version" 2>/dev/null) || exploit_result="{}"

    # Combine results
    local result
    result=$(jq -n \
        --arg service "$service" \
        --arg version "$version" \
        --arg product "$product" \
        --argjson cves "$cve_result" \
        --argjson exploits "$exploit_result" \
        '{
            service: $service,
            version: $version,
            normalized_product: $product,
            timestamp: (now | todate),
            cve_results: {
                total: ($cves.total_results // 0),
                critical: ([$cves.vulnerabilities[]? | select(.severity == "CRITICAL")] | length),
                high: ([$cves.vulnerabilities[]? | select(.severity == "HIGH")] | length),
                top_cves: [($cves.vulnerabilities // [])[] | {
                    id: .cve_id,
                    severity: .severity,
                    score: .cvss_score,
                    description: (.description | .[0:200])
                }][0:5]
            },
            exploit_results: {
                total: (($exploits.exploits // []) | length),
                exploits: [($exploits.exploits // [])[0:5][] | {
                    id: .id,
                    title: .title,
                    type: .type
                }]
            },
            risk_assessment: (
                if ([$cves.vulnerabilities[]? | select(.severity == "CRITICAL")] | length) > 0 then "CRITICAL"
                elif ([$cves.vulnerabilities[]? | select(.severity == "HIGH")] | length) > 0 then "HIGH"
                elif ($cves.total_results // 0) > 0 then "MEDIUM"
                else "LOW"
                end
            )
        }')

    set_cache "correlate" "$cache_key_val" "$result"
    echo "$result"

    local risk=$(echo "$result" | jq -r '.risk_assessment')
    log_success "Correlation complete. Risk: $risk"
}

# ============================================================================
# CACHE MANAGEMENT
# ============================================================================

cache_list() {
    echo "=== GHOST Research Cache ==="
    echo "Location: $CACHE_DIR"
    echo ""

    for category in cve exploit technique correlate github; do
        local dir="$CACHE_DIR/$category"
        if [ -d "$dir" ]; then
            local count=$(find "$dir" -name "*.json" 2>/dev/null | wc -l)
            local size=$(du -sh "$dir" 2>/dev/null | cut -f1)
            echo "$category: $count entries ($size)"

            # Show recent entries
            find "$dir" -name "*.json" -printf "%T@ %f\n" 2>/dev/null | \
                sort -rn | head -3 | while read ts file; do
                    local age=$(($(date +%s) - ${ts%.*}))
                    echo "  - ${file%.json} (${age}s ago)"
                done
        fi
    done
}

cache_clear() {
    local category="${1:-all}"

    if [ "$category" = "all" ]; then
        rm -rf "$CACHE_DIR"/*
        log_success "Cleared all cache"
    else
        rm -rf "${CACHE_DIR:?}/$category"/*
        log_success "Cleared $category cache"
    fi
}

cache_stats() {
    echo "=== GHOST Research Cache Statistics ==="
    echo ""
    echo "Location: $CACHE_DIR"
    echo "TTL: ${CACHE_TTL}s"
    echo ""

    local total_files=0
    local total_size=0
    local expired=0
    local now=$(date +%s)

    for category in cve exploit technique correlate github; do
        local dir="$CACHE_DIR/$category"
        if [ -d "$dir" ]; then
            local count=$(find "$dir" -name "*.json" 2>/dev/null | wc -l)
            total_files=$((total_files + count))

            # Count expired
            find "$dir" -name "*.json" 2>/dev/null | while read f; do
                local file_age=$((now - $(stat -c %Y "$f" 2>/dev/null || echo 0)))
                if [ "$file_age" -gt "$CACHE_TTL" ]; then
                    expired=$((expired + 1))
                fi
            done
        fi
    done

    local total_size_human=$(du -sh "$CACHE_DIR" 2>/dev/null | cut -f1 || echo "0")

    echo "Total entries: $total_files"
    echo "Total size: $total_size_human"
    echo "Expired entries: $expired"
    echo ""

    # Rate limit status
    if [ -f "$RATE_LIMIT_FILE" ]; then
        local minute_ago=$((now - 60))
        local nvd_count=$(grep "^nvd:" "$RATE_LIMIT_FILE" 2>/dev/null | \
            awk -F: -v limit=$minute_ago '$2 > limit' | wc -l)
        echo "Rate Limits (last minute):"
        echo "  NVD: $nvd_count/${NVD_RATE_LIMIT}"
    fi
}

# ============================================================================
# HELP
# ============================================================================

show_help() {
    cat << 'EOF'
GHOST Research Engine v1.0
Real-time CVE lookup, exploit-db search, and web research

Usage: ghost-research.sh <command> [arguments]

Commands:
  cve <product> [version]       Search NVD/CVE database for vulnerabilities
                                Example: ghost-research.sh cve apache 2.4.49
                                Example: ghost-research.sh cve "log4j"

  exploit <query>               Search Exploit-DB for exploits
                                Example: ghost-research.sh exploit "apache struts"
                                Uses searchsploit if available, falls back to web

  technique <name>              Get technique info from built-in database
                                Example: ghost-research.sh technique kerberoasting
                                Example: ghost-research.sh technique "sql injection"

  correlate <service> <version> Auto-correlate service/version with CVEs & exploits
                                Example: ghost-research.sh correlate openssh 7.9p1
                                Example: ghost-research.sh correlate apache 2.4.49

  github <owner/repo>           Search GitHub Security Advisories
                                Example: ghost-research.sh github apache/struts

  cache list                    List cached research results
  cache clear [category]        Clear cache (all or specific: cve, exploit, etc.)
  cache stats                   Show cache statistics

Environment Variables:
  GHOST_RESEARCH_CACHE   Cache directory (default: /tmp/ghost/research-cache)
  GHOST_RESEARCH_TTL     Cache TTL in seconds (default: 3600)
  NVD_API_KEY            NVD API key for higher rate limits (recommended)
  GITHUB_TOKEN           GitHub token for security advisories access

API Rate Limits:
  NVD without key:  6 requests/minute
  NVD with key:     50 requests/minute
  GitHub:           60 requests/hour (5000 with token)

Output Format:
  All commands output JSON for easy parsing with jq

Integration with GHOST Memory:
  Results can be piped to ghost-memory.sh for tracking:
    ghost-research.sh correlate openssh 7.9p1 | \
      jq -r '.cve_results.top_cves[].id' | \
      xargs -I {} ghost-memory.sh insight cve "Found {} on target"

Examples:
  # Full reconnaissance correlation
  ghost-research.sh correlate nginx 1.18.0 | jq '.risk_assessment'

  # Find exploits for specific CVE
  ghost-research.sh exploit CVE-2021-44228

  # Check technique details before attack
  ghost-research.sh technique kerberoasting | jq '.technique.tools'

  # Audit cache usage
  ghost-research.sh cache stats

EOF
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    check_dependencies
    init_cache

    local command="${1:-help}"
    shift || true

    case "$command" in
        cve)
            [ -z "${1:-}" ] && { log_error "Usage: $SCRIPT_NAME cve <product> [version]"; exit 1; }
            search_cve "$1" "${2:-}"
            ;;
        exploit)
            [ -z "${1:-}" ] && { log_error "Usage: $SCRIPT_NAME exploit <query>"; exit 1; }
            search_exploit "$*"
            ;;
        technique)
            [ -z "${1:-}" ] && { log_error "Usage: $SCRIPT_NAME technique <name>"; exit 1; }
            search_technique "$*"
            ;;
        correlate)
            [ -z "${1:-}" ] || [ -z "${2:-}" ] && {
                log_error "Usage: $SCRIPT_NAME correlate <service> <version>"; exit 1;
            }
            correlate_cve "$1" "$2"
            ;;
        github)
            [ -z "${1:-}" ] && { log_error "Usage: $SCRIPT_NAME github <owner/repo>"; exit 1; }
            search_github "$1"
            ;;
        cache)
            case "${1:-list}" in
                list)
                    cache_list
                    ;;
                clear)
                    cache_clear "${2:-all}"
                    ;;
                stats)
                    cache_stats
                    ;;
                *)
                    log_error "Unknown cache command: $1"
                    echo "Usage: $SCRIPT_NAME cache {list|clear|stats}"
                    exit 1
                    ;;
            esac
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
