# ORCHESTRATOR Tools Reference

## Agent Invocation Commands

### Core Agent Commands

```bash
# Reconnaissance
/recon <target> [options]
  --platform kali|windows
  --passive-only          # No active scanning
  --output <dir>

# Web Application Testing
/web <url> [options]
  --platform kali|windows
  --owasp-full           # Run all OWASP Top 10 tests
  --depth <n>            # Spider depth

# API Testing
/api <endpoint> [options]
  --auth <token>         # Authentication token
  --spec <file>          # OpenAPI/Swagger spec

# LLM/AI Testing
/llm <url> [options]
  --model <name>         # Target model name
  --all-attacks          # Run full attack suite

# Network/AD Testing
/network <target> [options]
  --platform kali|windows
  --ad                   # Active Directory mode

# Cloud Testing
/cloud <target> [options]
  --provider aws|azure|gcp
  --profile <name>       # AWS/Azure/GCP profile

# Exploitation
/exploit <target> [options]
  --cve <CVE-ID>         # Specific CVE
  --payload <type>       # Payload type

# Post-Exploitation
/post-exploit <target> [options]
  --platform linux|windows
  --privesc              # Focus on privilege escalation

# Reporting
/report [options]
  --format md|html|pdf
  --template <name>
  --output <file>
```

## Orchestration Utilities

### Target Management

```bash
# Set target environment variable
export TARGET=<ip_or_domain>

# Add to hosts file
echo "$TARGET target.htb" | sudo tee -a /etc/hosts

# Verify target reachability
ping -c 3 $TARGET

# Quick port check
nc -zv $TARGET 80 443 22
```

### Workspace Setup

```bash
# Create engagement directory structure
mkdir -p ~/engagements/$TARGET/{recon,web,api,network,exploit,loot,report}
cd ~/engagements/$TARGET

# Initialize logging
script -a ./engagement.log
```

### Progress Tracking

```bash
# Create progress file
cat << 'EOF' > progress.md
# Engagement: $TARGET
# Started: $(date)

## Phases
- [ ] Pre-Engagement
- [ ] Intelligence Gathering
- [ ] Threat Modeling
- [ ] Vulnerability Analysis
- [ ] Exploitation
- [ ] Post-Exploitation
- [ ] Reporting
EOF
```

## Scope Validation Tools

```bash
# Validate IP is in scope
validate_scope() {
    local target=$1
    local scope_file=$2

    if grep -q "$target" "$scope_file"; then
        echo "[SCOPE] $target is IN SCOPE"
        return 0
    else
        echo "[SCOPE] WARNING: $target may be OUT OF SCOPE"
        return 1
    fi
}

# Usage
validate_scope "10.10.10.100" ./scope.md
```

## Platform Detection

```bash
# Detect OS via nmap
detect_os() {
    local target=$1
    nmap -O --osscan-guess $target 2>/dev/null | grep "OS details" | head -1
}

# Detect OS via TTL
detect_os_ttl() {
    local target=$1
    ttl=$(ping -c 1 $target | grep ttl | awk -F'ttl=' '{print $2}' | cut -d' ' -f1)

    if [ "$ttl" -le 64 ]; then
        echo "Linux/Unix (TTL: $ttl)"
    elif [ "$ttl" -le 128 ]; then
        echo "Windows (TTL: $ttl)"
    else
        echo "Unknown (TTL: $ttl)"
    fi
}
```

## Evidence Collection

```bash
# Screenshot web page
cutycapt --url=http://$TARGET --out=./evidence/homepage.png

# Record terminal session
asciinema rec ./evidence/session.cast

# Hash evidence files
find ./evidence -type f -exec sha256sum {} \; > ./evidence/hashes.txt
```

## Reporting Integration

```bash
# Compile findings from all agents
compile_report() {
    local engagement_dir=$1
    local output=$2

    echo "# GHOST Penetration Test Report" > $output
    echo "## Target: $TARGET" >> $output
    echo "## Date: $(date)" >> $output
    echo "" >> $output

    # Aggregate findings
    for agent_dir in recon web api network exploit; do
        if [ -f "$engagement_dir/$agent_dir/findings.md" ]; then
            echo "## $agent_dir Findings" >> $output
            cat "$engagement_dir/$agent_dir/findings.md" >> $output
            echo "" >> $output
        fi
    done
}
```

## HackTheBox Integration

```bash
# HTB-specific commands
htb_connect() {
    sudo openvpn ~/.config/htb/lab.ovpn &
    sleep 10
    ip addr show tun0
}

htb_spawn() {
    local box_name=$1
    echo "[HTB] Spawn $box_name from HTB interface"
    echo "[HTB] Set TARGET variable after spawn"
}

htb_submit_flag() {
    local flag=$1
    echo "[HTB] Submit flag: $flag"
    echo "[HTB] Use HTB web interface to submit"
}
```
