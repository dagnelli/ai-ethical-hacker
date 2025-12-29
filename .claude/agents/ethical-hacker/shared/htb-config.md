# HackTheBox Configuration

> *"The box doesn't beat me. I beat the box."*

## VPN Connection

### Initial Setup

```bash
# Download your VPN configuration from HTB
# Save to: ~/.config/htb/lab.ovpn

# Create config directory
mkdir -p ~/.config/htb

# Connect to HTB VPN
sudo openvpn ~/.config/htb/lab.ovpn

# Run in background
sudo openvpn --config ~/.config/htb/lab.ovpn --daemon

# Verify connection
ip addr show tun0
ping -c 3 10.10.10.1
```

### Connection Troubleshooting

```bash
# Check if already connected
ip addr | grep tun0

# Kill existing connections
sudo killall openvpn

# Check VPN logs
sudo journalctl -u openvpn --since "5 minutes ago"

# Test connectivity
ping -c 3 10.10.10.2  # HTB DNS

# Verify routes
ip route | grep tun0
```

### VPN Config Options

```bash
# lab.ovpn additions for stability
ping 10
ping-restart 60
resolv-retry infinite
```

## Target Handling

### Environment Setup

```bash
# Set target IP (REQUIRED for every engagement)
export TARGET=<box_ip>

# Add to /etc/hosts for easier access
echo "$TARGET box.htb" | sudo tee -a /etc/hosts

# Verify
ping -c 1 box.htb
```

### Workspace Creation

```bash
# Create engagement directory
mkdir -p ~/htb/$BOX_NAME/{recon,web,exploit,loot,notes}
cd ~/htb/$BOX_NAME

# Create notes file
cat << 'EOF' > notes.md
# HTB: $BOX_NAME
## Target: $TARGET
## Started: $(date)
## Difficulty: [Easy/Medium/Hard/Insane]

## Enumeration

## Initial Access

## Privilege Escalation

## Flags
- User:
- Root:

## Lessons Learned

EOF

# Start logging
script -a ./session.log
```

### Target Variables Template

```bash
# ~/.bashrc additions for HTB
export HTB_VPN="$HOME/.config/htb/lab.ovpn"

# Quick target setup function
htb() {
    export TARGET=$1
    export BOX_NAME=$2
    echo "[HTB] Target: $TARGET"
    echo "[HTB] Box: $BOX_NAME"
    echo "$TARGET $BOX_NAME.htb" | sudo tee -a /etc/hosts
    mkdir -p ~/htb/$BOX_NAME/{recon,web,exploit,loot,notes}
    cd ~/htb/$BOX_NAME
}

# Usage: htb 10.10.10.100 mybox
```

## Flag Handling

### Flag Locations

| Flag | Location | Format |
|------|----------|--------|
| User | /home/*/user.txt | 32-char hex |
| Root | /root/root.txt | 32-char hex |

### Flag Retrieval Commands

```bash
# User flag (after initial access)
cat /home/*/user.txt 2>/dev/null || find /home -name user.txt -exec cat {} \; 2>/dev/null

# Root flag (after privesc)
cat /root/root.txt

# Windows user flag
type C:\Users\*\Desktop\user.txt

# Windows root flag
type C:\Users\Administrator\Desktop\root.txt
```

### Flag Submission

```bash
# Manual submission via HTB web interface
echo "[HTB] User Flag: <flag_here>"
echo "[HTB] Submit at: https://app.hackthebox.com/machines/<box_name>"

# Verify flag format (32 hex characters)
echo "<flag>" | grep -E '^[a-f0-9]{32}$' && echo "Valid format" || echo "Invalid format"
```

## Box Difficulty Mapping

### Easy Boxes

**Focus Areas:**
- Thorough enumeration
- Common CVEs
- Default credentials
- Simple misconfigurations

**Typical Attack Chain:**
```
Recon → Public Exploit → User → SUID/Sudo → Root
```

**Common Techniques:**
- Web app vulnerabilities (SQLi, LFI, RFI)
- Outdated services with public exploits
- Weak/default credentials
- Basic privilege escalation

### Medium Boxes

**Focus Areas:**
- Chained exploits
- Custom scripting
- Less obvious attack paths

**Typical Attack Chain:**
```
Deep Recon → Custom Exploit → Initial Shell → Enum → Privesc Chain → Root
```

**Common Techniques:**
- Chained vulnerabilities
- Custom exploit modification
- Token manipulation
- Service exploitation

### Hard Boxes

**Focus Areas:**
- Multiple pivot points
- Advanced techniques
- Source code review
- Custom tool development

**Typical Attack Chain:**
```
Extensive Recon → Multiple Footholds → Lateral Movement → Complex Privesc → Root
```

**Common Techniques:**
- Binary exploitation
- Advanced web attacks
- Active Directory attacks
- Container escapes

### Insane Boxes

**Focus Areas:**
- Near 0-day techniques
- Extreme persistence
- Custom exploit development
- Multi-stage attacks

**Approach:**
- Expect to spend significant time
- Research extensively
- Combine multiple techniques
- Document everything

## Standard Workflow

### Phase 1: Setup

```bash
# 1. Spawn box from HTB interface
# 2. Note the IP address
# 3. Run setup

htb 10.10.10.100 boxname

# 4. Verify connectivity
ping -c 3 $TARGET
```

### Phase 2: Reconnaissance

```bash
# Quick port scan
nmap -sC -sV -oA recon/nmap-initial $TARGET

# Full port scan (background)
nmap -p- -T4 -oA recon/nmap-full $TARGET &

# Web enumeration (if ports 80/443)
whatweb http://$TARGET
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o recon/gobuster.txt
```

### Phase 3: Vulnerability Analysis

```bash
# Service-specific enumeration
# Check each open port for known vulnerabilities
searchsploit <service> <version>
```

### Phase 4: Exploitation

```bash
# Document the exploit used
echo "[EXPLOIT] Using: <exploit_name>" >> notes.md
echo "[EXPLOIT] Source: <source_url>" >> notes.md

# Capture user flag
cat /home/*/user.txt | tee loot/user.txt
```

### Phase 5: Privilege Escalation

```bash
# Linux enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee recon/linpeas.txt

# Windows enumeration
# Upload and run winPEAS
```

### Phase 6: Post-Exploitation

```bash
# Capture root flag
cat /root/root.txt | tee loot/root.txt

# Document the full attack chain
```

### Phase 7: Documentation

```bash
# Complete notes.md
# Generate writeup (if permitted)
# Submit flags
```

## Quick Reference Commands

```bash
# Directory busting
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -o recon/gobuster.txt

# Subdomain enumeration
gobuster vhost -u http://$TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# SMB enumeration
smbclient -L //$TARGET -N
enum4linux-ng $TARGET

# SNMP enumeration
snmpwalk -v2c -c public $TARGET

# Web vulnerability scan
nikto -h http://$TARGET -o recon/nikto.txt
```

## Tips & Tricks

### When Stuck

1. **Re-enumerate** - Different tools, different wordlists
2. **Check all services** - Even "uninteresting" ports
3. **Read the source** - HTML comments, JS files
4. **Try credentials** - Reuse found creds everywhere
5. **Check HTB forums** - Hints without spoilers

### Common Mistakes to Avoid

- Not scanning all ports
- Ignoring UDP
- Not adding to /etc/hosts
- Forgetting to check robots.txt
- Not trying found credentials everywhere
- Giving up too early

### Useful Resources

- HTB Forums: https://forum.hackthebox.com/
- IppSec Videos: https://www.youtube.com/c/ippsec
- 0xdf Writeups: https://0xdf.gitlab.io/
- HackTricks: https://book.hacktricks.xyz/
