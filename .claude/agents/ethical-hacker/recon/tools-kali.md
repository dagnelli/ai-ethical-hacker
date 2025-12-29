# SHADOW Tools Reference — Kali Linux

> *"Every tool is a lens. Together, they reveal everything."*

## Port Scanning

### nmap (Network Mapper)
**Source**: https://nmap.org/docs.html

```bash
# Quick initial scan
nmap -sC -sV -oA recon/nmap-initial $TARGET

# Full TCP port scan
nmap -p- -T4 -oA recon/nmap-full-tcp $TARGET

# Full TCP with service detection
nmap -p- -sC -sV -T4 -oA recon/nmap-full $TARGET

# UDP top 100 ports
sudo nmap -sU --top-ports 100 -oA recon/nmap-udp $TARGET

# UDP top 20 (faster)
sudo nmap -sU --top-ports 20 -T4 -oA recon/nmap-udp-quick $TARGET

# Vulnerability scan
nmap --script vuln -oA recon/nmap-vuln $TARGET

# All default scripts
nmap -sC -sV --script=default -oA recon/nmap-default $TARGET

# Aggressive scan (noisy but thorough)
nmap -A -T4 -oA recon/nmap-aggressive $TARGET

# Stealth SYN scan
sudo nmap -sS -T2 -oA recon/nmap-stealth $TARGET

# Specific port range
nmap -p 1-10000 -sV -oA recon/nmap-range $TARGET

# Parse results
grep 'open' recon/nmap-initial.nmap
cat recon/nmap-initial.gnmap | grep -oP '\d+/open' | cut -d'/' -f1 | tr '\n' ','
```

### masscan
**Source**: https://github.com/robertdavidgraham/masscan

```bash
# Full port scan (very fast)
sudo masscan -p1-65535 $TARGET --rate=1000 -oG recon/masscan.gnmap

# Top ports with rate limit
sudo masscan -p1-1000 $TARGET --rate=500 -oG recon/masscan-top.gnmap

# Specific ports
sudo masscan -p21,22,23,25,80,110,143,443,445,3389 $TARGET -oG recon/masscan-common.gnmap
```

### rustscan
**Source**: https://github.com/RustScan/RustScan

```bash
# Quick scan, pipe to nmap
rustscan -a $TARGET -- -sC -sV -oA recon/rustscan

# Batch size and timeout
rustscan -a $TARGET -b 500 -t 1500 -- -sC -sV

# Multiple targets
rustscan -a $TARGET1,$TARGET2 --ulimit 5000
```

### autorecon
**Source**: https://github.com/Tib3rius/AutoRecon

```bash
# Full automated reconnaissance
autorecon $TARGET -o recon/autorecon

# Single target with verbosity
autorecon $TARGET -v -o recon/autorecon

# Multiple targets
autorecon targets.txt -o recon/autorecon
```

## DNS Enumeration

### dnsrecon
**Source**: https://github.com/darkoperator/dnsrecon

```bash
# Standard enumeration
dnsrecon -d $DOMAIN -t std -o recon/dnsrecon-std.xml

# Zone transfer attempt
dnsrecon -d $DOMAIN -t axfr

# Brute force subdomains
dnsrecon -d $DOMAIN -t brt -D /usr/share/wordlists/dnsmap.txt

# All enumeration types
dnsrecon -d $DOMAIN -t std,brt,axfr,zonewalk
```

### dig
```bash
# All records
dig $DOMAIN ANY +noall +answer

# Specific record types
dig $DOMAIN A +short
dig $DOMAIN MX +short
dig $DOMAIN TXT +short
dig $DOMAIN NS +short
dig $DOMAIN CNAME +short

# Zone transfer
dig axfr @ns1.$DOMAIN $DOMAIN

# Reverse lookup
dig -x $IP +short
```

### fierce
**Source**: https://github.com/mschwager/fierce

```bash
# DNS reconnaissance
fierce --domain $DOMAIN

# With wordlist
fierce --domain $DOMAIN --wordlist /usr/share/wordlists/dirb/common.txt
```

## Subdomain Enumeration

### amass
**Source**: https://github.com/owasp-amass/amass

```bash
# Passive enumeration
amass enum -passive -d $DOMAIN -o recon/amass-passive.txt

# Active enumeration
amass enum -active -d $DOMAIN -o recon/amass-active.txt

# Brute force
amass enum -brute -d $DOMAIN -w /usr/share/wordlists/amass/subdomains-top1million-5000.txt -o recon/amass-brute.txt

# With timeout
amass enum -passive -d $DOMAIN -timeout 30 -o recon/amass.txt

# Intel gathering
amass intel -whois -d $DOMAIN
```

### subfinder
**Source**: https://github.com/projectdiscovery/subfinder

```bash
# Basic enumeration
subfinder -d $DOMAIN -o recon/subfinder.txt

# All sources
subfinder -d $DOMAIN -all -o recon/subfinder-all.txt

# With rate limiting
subfinder -d $DOMAIN -rate-limit 10 -o recon/subfinder.txt

# Silent mode (just domains)
subfinder -d $DOMAIN -silent
```

### assetfinder
**Source**: https://github.com/tomnomnom/assetfinder

```bash
# Find subdomains
assetfinder --subs-only $DOMAIN | tee recon/assetfinder.txt
```

### Combined workflow
```bash
# Combine all subdomain tools
subfinder -d $DOMAIN -silent > recon/subs.txt
amass enum -passive -d $DOMAIN >> recon/subs.txt
assetfinder --subs-only $DOMAIN >> recon/subs.txt

# Deduplicate
sort -u recon/subs.txt > recon/subdomains.txt

# Verify live hosts
cat recon/subdomains.txt | httpx -silent -o recon/live-subdomains.txt
```

## Web Reconnaissance

### whatweb
**Source**: https://github.com/urbanadventurer/WhatWeb

```bash
# Basic scan
whatweb $URL -v

# Aggressive scan
whatweb $URL -a 3 -v

# Output to file
whatweb $URL -a 3 --log-json=recon/whatweb.json
```

### wafw00f
**Source**: https://github.com/EnableSecurity/wafw00f

```bash
# WAF detection
wafw00f $URL

# All WAF checks
wafw00f $URL -a

# List all WAFs
wafw00f -l
```

### httpx
**Source**: https://github.com/projectdiscovery/httpx

```bash
# Probe live hosts
cat recon/subdomains.txt | httpx -silent -o recon/live.txt

# With tech detection
cat recon/subdomains.txt | httpx -tech-detect -o recon/tech.txt

# With status codes
cat recon/subdomains.txt | httpx -status-code -title -o recon/http-info.txt

# Full output
cat recon/subdomains.txt | httpx -status-code -title -tech-detect -content-length -o recon/httpx-full.txt
```

### nuclei (Recon templates)
**Source**: https://github.com/projectdiscovery/nuclei

```bash
# Technology detection
nuclei -u $URL -t technologies/ -o recon/nuclei-tech.txt

# Exposure checks
nuclei -u $URL -t exposures/ -o recon/nuclei-exposure.txt

# Misconfiguration
nuclei -u $URL -t misconfiguration/ -o recon/nuclei-misconfig.txt
```

## Directory & File Discovery

### ffuf
**Source**: https://github.com/ffuf/ffuf

```bash
# Directory brute force
ffuf -u $URL/FUZZ -w /usr/share/wordlists/dirb/common.txt -o recon/ffuf-dirs.json

# File extensions
ffuf -u $URL/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt,.bak -o recon/ffuf-files.json

# Recursive
ffuf -u $URL/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion -recursion-depth 2

# Filter by status
ffuf -u $URL/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404

# Filter by size
ffuf -u $URL/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 0
```

### gobuster
**Source**: https://github.com/OJ/gobuster

```bash
# Directory mode
gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -o recon/gobuster-dir.txt

# With extensions
gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -o recon/gobuster-ext.txt

# DNS mode (subdomains)
gobuster dns -d $DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Vhost mode
gobuster vhost -u http://$TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### feroxbuster
**Source**: https://github.com/epi052/feroxbuster

```bash
# Recursive directory discovery
feroxbuster -u $URL -w /usr/share/wordlists/dirb/common.txt -o recon/feroxbuster.txt

# With extensions
feroxbuster -u $URL -x php,html,txt -o recon/feroxbuster-ext.txt
```

## OSINT Tools

### theHarvester
**Source**: https://github.com/laramies/theHarvester

```bash
# All sources
theHarvester -d $DOMAIN -b all -f recon/theharvester

# Specific sources
theHarvester -d $DOMAIN -b google,bing,linkedin -f recon/theharvester
```

### recon-ng
**Source**: https://github.com/lanmaster53/recon-ng

```bash
# Start recon-ng
recon-ng

# Inside recon-ng:
workspaces create $DOMAIN
db insert domains domain=$DOMAIN
modules load recon/domains-hosts/hackertarget
run
modules load recon/hosts-hosts/resolve
run
show hosts
```

### Shodan CLI
```bash
# Search by IP
shodan host $IP

# Search query
shodan search "hostname:$DOMAIN"

# Count results
shodan count "hostname:$DOMAIN"
```

## Virtual Host Discovery

```bash
# ffuf vhost discovery
ffuf -u http://$TARGET -H "Host: FUZZ.$DOMAIN" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <filter_size>

# gobuster vhost
gobuster vhost -u http://$TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

## Quick Reference Commands

```bash
# One-liner recon
nmap -sC -sV $TARGET && whatweb http://$TARGET && gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt

# Export open ports for further scanning
nmap -p- $TARGET -oG - | grep '/open' | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//'

# Quick subdomain + live check
subfinder -d $DOMAIN -silent | httpx -silent | tee live-domains.txt
```

## Output Consolidation

```bash
# Combine all recon data
cat recon/nmap-*.nmap > recon/all-nmap.txt
cat recon/*-subdomains.txt | sort -u > recon/all-subdomains.txt

# Generate summary
echo "=== RECON SUMMARY ===" > recon/summary.txt
echo "Open Ports:" >> recon/summary.txt
grep 'open' recon/nmap-initial.nmap >> recon/summary.txt
echo "" >> recon/summary.txt
echo "Subdomains:" >> recon/summary.txt
wc -l recon/all-subdomains.txt >> recon/summary.txt
```
