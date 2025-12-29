# CVSS 3.1 Calculator Reference

> *"Risk quantified is risk understood."*

---

## CVSS 3.1 Overview

The Common Vulnerability Scoring System (CVSS) provides a standardized method for rating the severity of security vulnerabilities.

### Score Ranges

| Score | Severity | Color |
|-------|----------|-------|
| 0.0 | None | - |
| 0.1 - 3.9 | Low | Green |
| 4.0 - 6.9 | Medium | Yellow |
| 7.0 - 8.9 | High | Orange |
| 9.0 - 10.0 | Critical | Red |

---

## Base Metrics

### Attack Vector (AV)

| Value | Description | Score |
|-------|-------------|-------|
| **Network (N)** | Attack can be launched remotely over the network | 0.85 |
| **Adjacent (A)** | Attack requires adjacent network access (same LAN/WiFi) | 0.62 |
| **Local (L)** | Attack requires local access to the system | 0.55 |
| **Physical (P)** | Attack requires physical access to the device | 0.20 |

**Decision Guide**:
- Is the vulnerability exploitable over the internet? → Network
- Does it require same network segment? → Adjacent
- Does it require login/shell access? → Local
- Does it require hands-on device access? → Physical

---

### Attack Complexity (AC)

| Value | Description | Score |
|-------|-------------|-------|
| **Low (L)** | No special conditions or circumstances required | 0.77 |
| **High (H)** | Successful attack requires specific conditions to be met | 0.44 |

**Decision Guide**:
- Can anyone exploit this reliably? → Low
- Does it require race conditions, specific configuration, or MITM position? → High

**High Complexity Examples**:
- Race conditions
- Specific non-default configuration
- Memory layout bypasses (ASLR)
- Victim must be in specific state

---

### Privileges Required (PR)

| Value | Scope Unchanged | Scope Changed |
|-------|-----------------|---------------|
| **None (N)** | 0.85 | 0.85 |
| **Low (L)** | 0.62 | 0.68 |
| **High (H)** | 0.27 | 0.50 |

**Decision Guide**:
- No authentication needed? → None
- Regular user account required? → Low
- Admin/root account required? → High

---

### User Interaction (UI)

| Value | Description | Score |
|-------|-------------|-------|
| **None (N)** | No user interaction required | 0.85 |
| **Required (R)** | User must take some action (click link, open file) | 0.62 |

**Decision Guide**:
- Can attacker exploit without victim doing anything? → None
- Does victim need to click, download, or interact? → Required

---

### Scope (S)

| Value | Description |
|-------|-------------|
| **Unchanged (U)** | Exploited component and impacted component are the same |
| **Changed (C)** | Exploited component can affect resources beyond its authorization |

**Decision Guide**:
- Does exploit impact only the vulnerable component? → Unchanged
- Can exploit affect other components (other applications, OS, network)? → Changed

**Changed Scope Examples**:
- Web app XSS affecting user's browser
- Container escape affecting host
- VM escape affecting hypervisor
- Sandbox escape

---

### Impact Metrics

#### Confidentiality Impact (C)

| Value | Description | Score |
|-------|-------------|-------|
| **High (H)** | Total information disclosure, complete loss of confidentiality | 0.56 |
| **Low (L)** | Some information disclosed, limited scope | 0.22 |
| **None (N)** | No impact to confidentiality | 0.00 |

#### Integrity Impact (I)

| Value | Description | Score |
|-------|-------------|-------|
| **High (H)** | Complete loss of integrity, attacker can modify any data | 0.56 |
| **Low (L)** | Some data modification possible, limited scope | 0.22 |
| **None (N)** | No impact to integrity | 0.00 |

#### Availability Impact (A)

| Value | Description | Score |
|-------|-------------|-------|
| **High (H)** | Total denial of service, complete shutdown | 0.56 |
| **Low (L)** | Reduced performance or interruption | 0.22 |
| **None (N)** | No impact to availability | 0.00 |

---

## Common Vulnerability Scores

### Critical (9.0 - 10.0)

| Vulnerability | Vector | Score |
|--------------|--------|-------|
| Remote Code Execution (unauth) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| SQL Injection (full access) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| Auth Bypass (admin access) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| Deserialization RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| Command Injection | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |

### High (7.0 - 8.9)

| Vulnerability | Vector | Score |
|--------------|--------|-------|
| XSS (Stored) | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | 9.3 |
| SSRF (internal access) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N | 8.6 |
| IDOR (sensitive data) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Auth bypass (user level) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Local Privilege Escalation | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 |
| XXE (file read) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |

### Medium (4.0 - 6.9)

| Vulnerability | Vector | Score |
|--------------|--------|-------|
| XSS (Reflected) | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| CSRF | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 |
| Information Disclosure | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Clickjacking | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | 4.3 |
| Session Fixation | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 5.4 |
| Open Redirect | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |

### Low (0.1 - 3.9)

| Vulnerability | Vector | Score |
|--------------|--------|-------|
| Minor Info Disclosure | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Missing Security Headers | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.1 |
| Verbose Errors | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Cookie without flags | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.1 |

---

## Vector String Format

```
CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[N|L|H]/I:[N|L|H]/A:[N|L|H]
```

### Examples

```
# Remote Code Execution (unauth, network)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical

# Stored XSS
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 Medium

# Local Privilege Escalation
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 High

# CSRF
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N = 6.5 Medium
```

---

## Quick Decision Tree

```
START
  │
  ├─ Can attacker exploit over network?
  │   ├─ YES → AV:N
  │   └─ NO → Requires local access?
  │           ├─ YES → AV:L
  │           └─ NO → AV:A or AV:P
  │
  ├─ Does exploitation require special conditions?
  │   ├─ NO → AC:L
  │   └─ YES (race condition, specific config) → AC:H
  │
  ├─ Authentication required?
  │   ├─ NO → PR:N
  │   ├─ Regular user → PR:L
  │   └─ Admin → PR:H
  │
  ├─ User interaction needed?
  │   ├─ NO → UI:N
  │   └─ YES (click, open) → UI:R
  │
  ├─ Does it affect other components?
  │   ├─ NO → S:U
  │   └─ YES (browser, other apps, host) → S:C
  │
  └─ Impact on CIA?
      ├─ Full access/control → C:H/I:H/A:H
      ├─ Partial/Limited → C:L/I:L/A:L
      └─ No impact → C:N/I:N/A:N
```

---

## Online Calculators

- **NVD Calculator**: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
- **FIRST Calculator**: https://www.first.org/cvss/calculator/3.1

---

## Temporal and Environmental Metrics

### Temporal Metrics (Optional)

| Metric | Values | Description |
|--------|--------|-------------|
| Exploit Code Maturity (E) | X, U, P, F, H | How mature is the exploit |
| Remediation Level (RL) | X, O, T, W, U | Is there a fix available |
| Report Confidence (RC) | X, U, R, C | How confident is the report |

### Environmental Metrics (Optional)

Used to customize score based on the organization's specific environment:
- Modified Base Metrics
- Impact Subscore Modifiers (CR, IR, AR)

---

## Notes for Accurate Scoring

1. **Be conservative**: When uncertain, choose the lower-impact option
2. **Consider realistic exploitation**: Not theoretical maximum
3. **Document assumptions**: Explain your scoring rationale
4. **Review peer scores**: Validate against similar vulnerabilities
5. **Adjust for context**: Use environmental metrics when applicable
