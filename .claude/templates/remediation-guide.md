> Remediation guide template with fix recommendations organized by severity and vulnerability type

# Security Remediation Guide

---

## Document Information

| Field | Value |
|-------|-------|
| **Engagement** | {{ENGAGEMENT_NAME}} |
| **Generated** | {{REPORT_DATE}} |
| **Version** | {{VERSION}} |
| **Target** | {{TARGET}} |

---

## Remediation Priority Matrix

### Timeline Guidelines

| Priority | Severity | Timeline | Resource Level |
|----------|----------|----------|----------------|
| **P1** | Critical | 0-48 hours | Emergency/All hands |
| **P2** | High | 1-2 weeks | Dedicated team |
| **P3** | Medium | 1-3 months | Scheduled sprint |
| **P4** | Low | 3-6 months | Backlog |

### Effort Estimation

| Effort Level | Hours | Description |
|--------------|-------|-------------|
| **Minimal** | < 2 | Configuration change, quick fix |
| **Low** | 2-8 | Single component fix |
| **Medium** | 8-40 | Multiple components, testing required |
| **High** | 40-80 | Architectural change |
| **Major** | 80+ | System redesign |

---

## Critical Severity Remediations (P1)

### Immediate Actions Required

{{#CRITICAL_REMEDIATIONS}}

---

#### {{FINDING_ID}}: {{FINDING_TITLE}}

**CVSS Score:** {{CVSS_SCORE}} | **CWE:** {{CWE_ID}}

##### Emergency Mitigation (Do Now)

{{IMMEDIATE_ACTION}}

```bash
{{IMMEDIATE_COMMAND}}
```

##### Root Cause

{{ROOT_CAUSE}}

##### Permanent Fix

{{PERMANENT_FIX}}

###### Implementation Steps

{{#FIX_STEPS}}
1. {{STEP}}
{{/FIX_STEPS}}

###### Code Fix

**Before (Vulnerable):**
```{{LANGUAGE}}
{{VULNERABLE_CODE}}
```

**After (Secure):**
```{{LANGUAGE}}
{{SECURE_CODE}}
```

##### Verification

```bash
{{VERIFICATION_COMMAND}}
```

Expected result: {{EXPECTED_RESULT}}

---

{{/CRITICAL_REMEDIATIONS}}

---

## High Severity Remediations (P2)

{{#HIGH_REMEDIATIONS}}

---

#### {{FINDING_ID}}: {{FINDING_TITLE}}

**CVSS Score:** {{CVSS_SCORE}} | **CWE:** {{CWE_ID}}

##### Issue Summary

{{ISSUE_SUMMARY}}

##### Fix Implementation

{{FIX_IMPLEMENTATION}}

##### Code/Configuration Changes

```{{LANGUAGE}}
{{FIX_CODE}}
```

##### Testing Requirements

{{TESTING_REQUIREMENTS}}

---

{{/HIGH_REMEDIATIONS}}

---

## Medium Severity Remediations (P3)

{{#MEDIUM_REMEDIATIONS}}

---

#### {{FINDING_ID}}: {{FINDING_TITLE}}

**CVSS Score:** {{CVSS_SCORE}} | **CWE:** {{CWE_ID}}

##### Recommended Fix

{{RECOMMENDED_FIX}}

##### Implementation Notes

{{IMPLEMENTATION_NOTES}}

---

{{/MEDIUM_REMEDIATIONS}}

---

## Low Severity Remediations (P4)

{{#LOW_REMEDIATIONS}}

- **{{FINDING_TITLE}}** ({{CWE_ID}}): {{QUICK_FIX}}

{{/LOW_REMEDIATIONS}}

---

## Remediation by Vulnerability Category

### Injection Vulnerabilities (CWE-74)

#### SQL Injection (CWE-89)

**Root Cause:** User input concatenated directly into SQL queries

**Fix Pattern:**
```python
# WRONG - Vulnerable to SQLi
query = f"SELECT * FROM users WHERE id = {user_input}"

# CORRECT - Parameterized query
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))
```

**Framework-Specific Fixes:**

| Framework | Solution |
|-----------|----------|
| Java/JDBC | PreparedStatement with bound parameters |
| PHP/PDO | PDO::prepare() with bindParam() |
| Python/SQLAlchemy | ORM queries or text() with bindparams |
| Node/Sequelize | Model methods or parameterized raw queries |
| .NET/EF | LINQ queries or FromSqlInterpolated |

**Additional Controls:**
- Input validation (whitelist approach)
- Least privilege database accounts
- WAF rules for SQLi patterns
- Error message suppression

---

#### Cross-Site Scripting (CWE-79)

**Root Cause:** Unsanitized user input rendered in HTML context

**Fix Pattern:**
```javascript
// WRONG - Direct insertion
element.innerHTML = userInput;

// CORRECT - Text content (no HTML parsing)
element.textContent = userInput;

// CORRECT - Proper encoding for HTML context
element.innerHTML = DOMPurify.sanitize(userInput);
```

**Context-Specific Encoding:**

| Context | Encoding Function |
|---------|-------------------|
| HTML Body | HTML entity encode |
| HTML Attribute | Attribute encode + quote |
| JavaScript | JavaScript escape |
| URL Parameter | URL encode |
| CSS | CSS escape |

**Framework Solutions:**

| Framework | Built-in Protection |
|-----------|---------------------|
| React | JSX auto-escapes by default |
| Angular | Automatic sanitization |
| Vue.js | v-text directive (safe) |
| Django | Template auto-escaping |
| Rails | ERB auto-escaping |

---

#### Command Injection (CWE-78)

**Root Cause:** User input passed to system shell

**Fix Pattern:**
```python
# WRONG - Shell injection vulnerable
os.system(f"ping {user_input}")

# CORRECT - Avoid shell, use array arguments
subprocess.run(["ping", "-c", "4", user_input], shell=False)

# CORRECT - Strict input validation
import re
if re.match(r'^[\d\.]+$', user_input):
    subprocess.run(["ping", "-c", "4", user_input])
```

**Best Practices:**
- Avoid shell=True in subprocess calls
- Use language APIs instead of shell commands
- Strict whitelist input validation
- Sandbox execution environments

---

#### Server-Side Template Injection (CWE-1336)

**Root Cause:** User input used in template expressions

**Fix Pattern:**
```python
# WRONG - User input in template
template = Template(user_input)

# CORRECT - User input as data, not template
template = Template("Hello {{ name }}")
template.render(name=user_input)
```

**Framework Hardening:**
- Enable sandbox mode (Jinja2: sandbox=True)
- Disable dangerous builtins
- Use logic-less templates when possible

---

### Authentication Vulnerabilities

#### Broken Authentication (CWE-287)

**Common Issues and Fixes:**

| Issue | Fix |
|-------|-----|
| Weak passwords | Enforce complexity, check breached passwords |
| Missing MFA | Implement TOTP or WebAuthn |
| Session fixation | Regenerate session ID after login |
| Credential stuffing | Rate limiting, CAPTCHA, breach monitoring |

**Session Management:**
```python
# Secure session configuration
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
```

---

#### JWT Vulnerabilities (CWE-347)

**Algorithm Confusion Fix:**
```python
# WRONG - Accepts any algorithm
jwt.decode(token, key, algorithms=None)

# CORRECT - Explicit algorithm whitelist
jwt.decode(token, key, algorithms=['RS256'])
```

**JWT Security Checklist:**
- [ ] Explicit algorithm specification
- [ ] Strong signing keys (256+ bits)
- [ ] Short expiration times
- [ ] Proper signature verification
- [ ] No sensitive data in payload

---

### Access Control Vulnerabilities

#### Broken Access Control (CWE-284)

**IDOR/BOLA Fix Pattern:**
```python
# WRONG - Direct object reference
@app.get("/documents/{doc_id}")
def get_document(doc_id):
    return Document.query.get(doc_id)

# CORRECT - Authorization check
@app.get("/documents/{doc_id}")
def get_document(doc_id, current_user):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        raise Forbidden()
    return doc
```

**Authorization Patterns:**
- Role-Based Access Control (RBAC)
- Attribute-Based Access Control (ABAC)
- Resource-level permissions
- Ownership validation

---

### Security Misconfiguration

#### Common Misconfigurations

| Issue | Fix |
|-------|-----|
| Debug mode in production | Disable debug, use proper logging |
| Default credentials | Change all defaults, use secrets management |
| Unnecessary services | Disable unused features/ports |
| Missing security headers | Implement CSP, HSTS, X-Frame-Options |
| Verbose errors | Custom error pages, log errors server-side |

**Security Headers Configuration:**
```nginx
# Nginx security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

---

### Cryptographic Failures

#### Weak Cryptography (CWE-327)

**Secure Algorithms:**

| Purpose | Recommended | Avoid |
|---------|-------------|-------|
| Hashing (passwords) | bcrypt, Argon2, scrypt | MD5, SHA1, SHA256 (for passwords) |
| Hashing (integrity) | SHA-256, SHA-3 | MD5, SHA1 |
| Symmetric encryption | AES-256-GCM | DES, 3DES, RC4 |
| Asymmetric encryption | RSA-2048+, ECDSA | RSA-1024 |
| Key derivation | PBKDF2, Argon2 | Simple hashing |

**Password Hashing Example:**
```python
# WRONG
import hashlib
password_hash = hashlib.md5(password).hexdigest()

# CORRECT
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

---

## Verification Checklist

### After Remediation

{{#VERIFICATION_ITEMS}}
- [ ] {{ITEM}}
{{/VERIFICATION_ITEMS}}

### Standard Verification Steps

- [ ] Retest original attack vector
- [ ] Verify fix doesn't introduce new issues
- [ ] Check for similar patterns elsewhere
- [ ] Update security documentation
- [ ] Monitor for exploitation attempts

---

## Resources

### Security References

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Security Guidelines](https://csrc.nist.gov/)
- [SANS Secure Coding](https://www.sans.org/secure-coding/)

### Framework Security Guides

- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [Spring Security](https://spring.io/projects/spring-security)
- [Express.js Security](https://expressjs.com/en/advanced/best-practice-security.html)
- [Rails Security Guide](https://guides.rubyonrails.org/security.html)

---

*Generated by GHOST v2.3*
*"Fix once, secure forever."*
