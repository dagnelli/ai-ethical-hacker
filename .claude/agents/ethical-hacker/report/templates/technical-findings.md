# Technical Findings Template

---

# [CLIENT NAME]
## Penetration Test Technical Report
### [DATE]

---

## Document Information

| Field | Value |
|-------|-------|
| Document Version | 1.0 |
| Classification | Confidential |
| Prepared By | [Tester Name] |
| Reviewed By | [Reviewer Name] |
| Report Date | [DATE] |

---

## Table of Contents

1. [Engagement Overview](#1-engagement-overview)
2. [Scope Details](#2-scope-details)
3. [Testing Methodology](#3-testing-methodology)
4. [Findings Summary](#4-findings-summary)
5. [Detailed Findings](#5-detailed-findings)
6. [Appendices](#appendices)

---

## 1. Engagement Overview

### 1.1 Purpose
[Detailed description of assessment objectives]

### 1.2 Testing Timeline

| Phase | Start | End | Duration |
|-------|-------|-----|----------|
| Reconnaissance | [Date] | [Date] | X days |
| Vulnerability Discovery | [Date] | [Date] | X days |
| Exploitation | [Date] | [Date] | X days |
| Reporting | [Date] | [Date] | X days |

### 1.3 Testing Team

| Name | Role | Contact |
|------|------|---------|
| [Name] | Lead Tester | [Email] |
| [Name] | Security Analyst | [Email] |

---

## 2. Scope Details

### 2.1 In-Scope Assets

#### Web Applications
| Application | URL | Environment |
|-------------|-----|-------------|
| [App Name] | https://app.example.com | Production |
| [App Name] | https://staging.example.com | Staging |

#### Network Assets
| Asset | IP/Range | Description |
|-------|----------|-------------|
| [Server] | 10.0.0.1 | Web Server |
| [Server] | 10.0.0.2 | Database Server |

#### API Endpoints
| API | Base URL | Version |
|-----|----------|---------|
| [API Name] | https://api.example.com/v1 | 1.0 |

### 2.2 Out-of-Scope
- [List items explicitly excluded]
- [Third-party services]
- [Specific IP ranges]

### 2.3 Testing Restrictions
- [Time windows]
- [Prohibited techniques]
- [Rate limiting requirements]

---

## 3. Testing Methodology

### 3.1 Approach
[OWASP Testing Guide / PTES / Custom methodology description]

### 3.2 Testing Phases

#### Phase 1: Reconnaissance
- Passive information gathering
- Active enumeration
- Service identification

#### Phase 2: Vulnerability Discovery
- Automated scanning
- Manual testing
- Business logic analysis

#### Phase 3: Exploitation
- Proof of concept development
- Impact demonstration
- Access verification

#### Phase 4: Post-Exploitation (if applicable)
- Privilege escalation attempts
- Lateral movement assessment
- Data access verification

### 3.3 Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Burp Suite | 2024.x | Web application testing |
| Nmap | 7.x | Network scanning |
| SQLMap | 1.x | SQL injection testing |
| [Tool] | [Version] | [Purpose] |

---

## 4. Findings Summary

### 4.1 Statistics

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Informational | X |
| **Total** | **X** |

### 4.2 Findings Overview

| ID | Title | Severity | CVSS | Status |
|----|-------|----------|------|--------|
| FIND-001 | [Title] | Critical | 9.8 | Open |
| FIND-002 | [Title] | High | 8.1 | Open |
| FIND-003 | [Title] | Medium | 5.3 | Open |
| FIND-004 | [Title] | Low | 3.1 | Open |

---

## 5. Detailed Findings

---

### FIND-001: [Critical Finding Title]

#### Overview

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CWE** | CWE-89: SQL Injection |
| **OWASP** | A03:2021 - Injection |
| **Status** | Open |

#### Affected Resources

| Resource | Type | Details |
|----------|------|---------|
| https://app.example.com/search | URL | search parameter |
| https://app.example.com/login | URL | username parameter |

#### Description

[Detailed technical description of the vulnerability]

The application is vulnerable to SQL injection in the search functionality. User-supplied input is directly concatenated into SQL queries without proper sanitization or parameterization, allowing attackers to manipulate database queries.

#### Technical Details

**Vulnerable Parameter**: `search`
**Injection Point**: GET parameter
**Database Type**: MySQL 8.0

#### Impact

**Confidentiality**: HIGH - Attackers can extract all data from the database including user credentials, personal information, and business data.

**Integrity**: HIGH - Attackers can modify or delete database records.

**Availability**: HIGH - Attackers could potentially drop tables or perform denial of service.

**Business Impact**: Complete compromise of application data, regulatory violations (GDPR, PCI-DSS), reputational damage.

#### Proof of Concept

**Step 1**: Navigate to search page
```
GET /search?q=test HTTP/1.1
Host: app.example.com
```

**Step 2**: Inject SQL payload
```
GET /search?q=test' OR '1'='1 HTTP/1.1
Host: app.example.com
```

**Step 3**: Extract data using UNION injection
```
GET /search?q=' UNION SELECT username,password,null FROM users-- HTTP/1.1
Host: app.example.com
```

#### Evidence

**Screenshot 1**: SQL error message disclosure
[INSERT SCREENSHOT]

**Screenshot 2**: Successful data extraction
[INSERT SCREENSHOT]

**Request/Response**:
```http
GET /search?q=' UNION SELECT 1,2,3-- HTTP/1.1
Host: app.example.com
Cookie: session=abc123

Response:
HTTP/1.1 200 OK
Content-Type: text/html

<div class="result">1</div>
<div class="result">2</div>
<div class="result">3</div>
```

#### Remediation

**Immediate Actions**:
1. Implement parameterized queries/prepared statements
2. Apply input validation on all user inputs
3. Enable Web Application Firewall rules

**Code Fix Example (PHP)**:
```php
// Vulnerable code
$query = "SELECT * FROM products WHERE name = '" . $_GET['search'] . "'";

// Fixed code using prepared statements
$stmt = $pdo->prepare("SELECT * FROM products WHERE name = ?");
$stmt->execute([$_GET['search']]);
```

**Code Fix Example (Python/SQLAlchemy)**:
```python
# Vulnerable
query = f"SELECT * FROM products WHERE name = '{search}'"

# Fixed
result = db.session.execute(
    text("SELECT * FROM products WHERE name = :search"),
    {"search": search}
)
```

#### Verification Steps
1. Repeat the proof of concept steps
2. Confirm SQL injection payloads no longer succeed
3. Verify error messages are properly handled

#### References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

---

### FIND-002: [High Finding Title]

[Repeat the same structure as FIND-001]

---

### FIND-003: [Medium Finding Title]

[Repeat the same structure as FIND-001]

---

## Appendices

### Appendix A: CVSS Scoring Details

| Finding | Base Score | Vector String |
|---------|------------|---------------|
| FIND-001 | 9.8 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| FIND-002 | 8.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N |

### Appendix B: Tool Outputs

#### Nmap Scan Results
```
[INSERT RELEVANT NMAP OUTPUT]
```

#### Vulnerability Scanner Results
```
[INSERT RELEVANT SCANNER OUTPUT]
```

### Appendix C: Testing Credentials Used

| Account | Access Level | Purpose |
|---------|--------------|---------|
| testuser | Standard User | Application testing |
| testadmin | Administrator | Admin function testing |

### Appendix D: Remediation Priority Matrix

| Priority | Finding | Effort | Risk Reduction |
|----------|---------|--------|----------------|
| P1 | FIND-001 | Medium | Critical |
| P2 | FIND-002 | Low | High |
| P3 | FIND-003 | High | Medium |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [DATE] | [Author] | Initial release |
| 1.1 | [DATE] | [Author] | [Changes made] |

---

*CONFIDENTIAL - For [CLIENT NAME] use only*
