> Full technical report template with detailed vulnerability documentation

# Penetration Test Technical Report

---

## Document Control

| Field | Value |
|-------|-------|
| **Client** | {{CLIENT_NAME}} |
| **Engagement ID** | {{ENGAGEMENT_ID}} |
| **Document Version** | {{VERSION}} |
| **Classification** | CONFIDENTIAL |
| **Author** | {{AUTHOR}} |
| **Review Date** | {{REVIEW_DATE}} |

### Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {{REPORT_DATE}} | {{AUTHOR}} | Initial release |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Engagement Overview](#2-engagement-overview)
3. [Scope and Methodology](#3-scope-and-methodology)
4. [Risk Assessment](#4-risk-assessment)
5. [Detailed Findings](#5-detailed-findings)
   - [5.1 Critical Findings](#51-critical-findings)
   - [5.2 High Findings](#52-high-findings)
   - [5.3 Medium Findings](#53-medium-findings)
   - [5.4 Low Findings](#54-low-findings)
   - [5.5 Informational](#55-informational)
6. [Remediation Roadmap](#6-remediation-roadmap)
7. [Compliance Mapping](#7-compliance-mapping)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Appendices](#9-appendices)

---

## 1. Executive Summary

{{EXECUTIVE_SUMMARY}}

### Key Statistics

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | {{TOTAL_FINDINGS}} |
| Critical | {{CRITICAL_COUNT}} |
| High | {{HIGH_COUNT}} |
| Medium | {{MEDIUM_COUNT}} |
| Low | {{LOW_COUNT}} |
| Overall Risk Rating | {{RISK_RATING}} |

---

## 2. Engagement Overview

### 2.1 Engagement Details

| Field | Value |
|-------|-------|
| **Target** | {{TARGET}} |
| **Target Type** | {{TARGET_TYPE}} |
| **Testing Period** | {{START_DATE}} to {{END_DATE}} |
| **Testing Hours** | {{TESTING_HOURS}} |
| **Tester(s)** | {{TESTERS}} |

### 2.2 Points of Contact

| Role | Name | Email | Phone |
|------|------|-------|-------|
| Client Technical | {{CLIENT_TECH_NAME}} | {{CLIENT_TECH_EMAIL}} | {{CLIENT_TECH_PHONE}} |
| Client Business | {{CLIENT_BIZ_NAME}} | {{CLIENT_BIZ_EMAIL}} | {{CLIENT_BIZ_PHONE}} |
| Lead Tester | {{TESTER_NAME}} | {{TESTER_EMAIL}} | {{TESTER_PHONE}} |

### 2.3 Testing Environment

| Attribute | Details |
|-----------|---------|
| Source IP(s) | {{SOURCE_IPS}} |
| VPN Required | {{VPN_REQUIRED}} |
| Credentials Provided | {{CREDS_PROVIDED}} |
| Test Accounts | {{TEST_ACCOUNTS}} |

---

## 3. Scope and Methodology

### 3.1 In-Scope Assets

{{#SCOPE_ASSETS}}
| Asset Type | Asset | Notes |
|------------|-------|-------|
| {{ASSET_TYPE}} | {{ASSET_VALUE}} | {{ASSET_NOTES}} |
{{/SCOPE_ASSETS}}

### 3.2 Out-of-Scope

{{#OUT_OF_SCOPE}}
- {{EXCLUSION}}
{{/OUT_OF_SCOPE}}

### 3.3 Testing Methodology

This assessment followed the **PTES (Penetration Testing Execution Standard)** methodology:

#### Phase 1: Pre-engagement Interactions
- Scope definition and authorization
- Rules of engagement agreement
- Emergency contact procedures

#### Phase 2: Intelligence Gathering
- Passive reconnaissance (OSINT)
- Active reconnaissance (scanning)
- Technology fingerprinting

#### Phase 3: Threat Modeling
- Attack surface analysis
- Threat identification
- Attack vector prioritization

#### Phase 4: Vulnerability Analysis
- Automated scanning
- Manual testing
- Vulnerability validation

#### Phase 5: Exploitation
- Controlled exploitation
- Proof of concept development
- Impact demonstration

#### Phase 6: Post-Exploitation
- Privilege escalation attempts
- Lateral movement assessment
- Data access evaluation

#### Phase 7: Reporting
- Finding documentation
- Risk assessment
- Remediation recommendations

### 3.4 Testing Standards Applied

| Standard | Coverage |
|----------|----------|
| OWASP Testing Guide v4.2 | Web Application Testing |
| OWASP API Security Top 10 | API Testing |
| PTES | Overall Methodology |
| NIST SP 800-115 | Technical Security Testing |
| CVSS 4.0 | Vulnerability Scoring |

---

## 4. Risk Assessment

### 4.1 Risk Rating Methodology

Findings are rated using CVSS 4.0 (Common Vulnerability Scoring System):

| CVSS Score | Severity | Priority |
|------------|----------|----------|
| 9.0 - 10.0 | Critical | P1 - Immediate |
| 7.0 - 8.9 | High | P2 - Short-term |
| 4.0 - 6.9 | Medium | P3 - Medium-term |
| 0.1 - 3.9 | Low | P4 - Long-term |
| 0.0 | None/Info | P5 - As resources allow |

### 4.2 Risk Summary

```
Severity Distribution:

Critical [{{CRITICAL_BAR}}] {{CRITICAL_COUNT}} ({{CRITICAL_PCT}}%)
High     [{{HIGH_BAR}}] {{HIGH_COUNT}} ({{HIGH_PCT}}%)
Medium   [{{MEDIUM_BAR}}] {{MEDIUM_COUNT}} ({{MEDIUM_PCT}}%)
Low      [{{LOW_BAR}}] {{LOW_COUNT}} ({{LOW_PCT}}%)
```

### 4.3 Attack Surface Analysis

{{ATTACK_SURFACE_SUMMARY}}

---

## 5. Detailed Findings

### 5.1 Critical Findings

{{#CRITICAL_FINDINGS}}
---

#### {{FINDING_ID}}: {{FINDING_TITLE}}

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL |
| **CVSS 4.0 Score** | {{CVSS_SCORE}} |
| **CVSS Vector** | {{CVSS_VECTOR}} |
| **CWE** | {{CWE_ID}} - {{CWE_NAME}} |
| **CVE** | {{CVE_ID}} |
| **MITRE ATT&CK** | {{MITRE_TECHNIQUE}} |
| **OWASP Category** | {{OWASP_CATEGORY}} |
| **Affected Asset** | {{AFFECTED_ASSET}} |
| **Discovered By** | {{AGENT}} |
| **Discovered At** | {{DISCOVERED_AT}} |

##### Description

{{DESCRIPTION}}

##### Technical Details

{{TECHNICAL_DETAILS}}

##### Proof of Concept

**Request:**
```http
{{POC_REQUEST}}
```

**Response:**
```http
{{POC_RESPONSE}}
```

##### Steps to Reproduce

{{#STEPS}}
{{STEP_NUMBER}}. {{STEP_DESCRIPTION}}
{{/STEPS}}

##### Impact

**Technical Impact:**
{{TECHNICAL_IMPACT}}

**Business Impact:**
{{BUSINESS_IMPACT}}

##### Evidence

| Evidence Type | Location |
|--------------|----------|
{{#EVIDENCE}}
| {{EVIDENCE_TYPE}} | `{{EVIDENCE_PATH}}` |
{{/EVIDENCE}}

##### Remediation

**Immediate Mitigation:**
{{IMMEDIATE_MITIGATION}}

**Permanent Fix:**
{{PERMANENT_FIX}}

**Code Example (Before):**
```{{LANGUAGE}}
{{VULNERABLE_CODE}}
```

**Code Example (After):**
```{{LANGUAGE}}
{{FIXED_CODE}}
```

##### References

{{#REFERENCES}}
- [{{REF_TITLE}}]({{REF_URL}})
{{/REFERENCES}}

{{/CRITICAL_FINDINGS}}

### 5.2 High Findings

{{#HIGH_FINDINGS}}
---

#### {{FINDING_ID}}: {{FINDING_TITLE}}

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **CVSS 4.0 Score** | {{CVSS_SCORE}} |
| **CWE** | {{CWE_ID}} |
| **Affected Asset** | {{AFFECTED_ASSET}} |

##### Description
{{DESCRIPTION}}

##### Proof of Concept
```
{{POC}}
```

##### Impact
{{IMPACT}}

##### Remediation
{{REMEDIATION}}

{{/HIGH_FINDINGS}}

### 5.3 Medium Findings

{{#MEDIUM_FINDINGS}}
---

#### {{FINDING_ID}}: {{FINDING_TITLE}}

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **CVSS 4.0 Score** | {{CVSS_SCORE}} |
| **CWE** | {{CWE_ID}} |
| **Affected Asset** | {{AFFECTED_ASSET}} |

##### Description
{{DESCRIPTION}}

##### Remediation
{{REMEDIATION}}

{{/MEDIUM_FINDINGS}}

### 5.4 Low Findings

{{#LOW_FINDINGS}}
---

#### {{FINDING_ID}}: {{FINDING_TITLE}}

| Attribute | Value |
|-----------|-------|
| **Severity** | LOW |
| **CVSS 4.0 Score** | {{CVSS_SCORE}} |
| **CWE** | {{CWE_ID}} |

##### Description
{{DESCRIPTION}}

##### Remediation
{{REMEDIATION}}

{{/LOW_FINDINGS}}

### 5.5 Informational

{{#INFORMATIONAL_FINDINGS}}
- **{{FINDING_TITLE}}**: {{DESCRIPTION}}
{{/INFORMATIONAL_FINDINGS}}

---

## 6. Remediation Roadmap

### 6.1 Priority Matrix

| Priority | Timeframe | Findings | Resources Required |
|----------|-----------|----------|-------------------|
| P1 (Critical) | 0-48 hours | {{P1_COUNT}} | Emergency response team |
| P2 (High) | 1-2 weeks | {{P2_COUNT}} | Development team |
| P3 (Medium) | 1-3 months | {{P3_COUNT}} | Scheduled maintenance |
| P4 (Low) | 3-6 months | {{P4_COUNT}} | Best practice implementation |

### 6.2 Remediation by Finding

{{#REMEDIATION_ITEMS}}
| Finding | Priority | Effort | Owner | Due Date |
|---------|----------|--------|-------|----------|
| {{FINDING_TITLE}} | {{PRIORITY}} | {{EFFORT}} | {{OWNER}} | {{DUE_DATE}} |
{{/REMEDIATION_ITEMS}}

### 6.3 Verification Testing

After remediation, the following should be verified:

{{#VERIFICATION_ITEMS}}
- [ ] {{VERIFICATION_ITEM}}
{{/VERIFICATION_ITEMS}}

---

## 7. Compliance Mapping

### 7.1 OWASP Top 10 (2021)

| Category | Findings |
|----------|----------|
| A01:2021 - Broken Access Control | {{A01_COUNT}} |
| A02:2021 - Cryptographic Failures | {{A02_COUNT}} |
| A03:2021 - Injection | {{A03_COUNT}} |
| A04:2021 - Insecure Design | {{A04_COUNT}} |
| A05:2021 - Security Misconfiguration | {{A05_COUNT}} |
| A06:2021 - Vulnerable Components | {{A06_COUNT}} |
| A07:2021 - Auth Failures | {{A07_COUNT}} |
| A08:2021 - Software Integrity Failures | {{A08_COUNT}} |
| A09:2021 - Logging Failures | {{A09_COUNT}} |
| A10:2021 - SSRF | {{A10_COUNT}} |

### 7.2 NIST 800-53 Mapping

{{#NIST_MAPPINGS}}
| Finding | NIST Control | Control Family |
|---------|--------------|----------------|
| {{FINDING}} | {{CONTROL}} | {{FAMILY}} |
{{/NIST_MAPPINGS}}

### 7.3 PCI DSS v4.0 Mapping

{{#PCI_MAPPINGS}}
| Finding | PCI Requirement | Status |
|---------|-----------------|--------|
| {{FINDING}} | {{REQUIREMENT}} | {{STATUS}} |
{{/PCI_MAPPINGS}}

### 7.4 ISO 27001:2022 Mapping

{{#ISO_MAPPINGS}}
| Finding | ISO Control | Control Objective |
|---------|-------------|-------------------|
| {{FINDING}} | {{CONTROL}} | {{OBJECTIVE}} |
{{/ISO_MAPPINGS}}

---

## 8. MITRE ATT&CK Mapping

### 8.1 Techniques Observed

| Tactic | Technique ID | Technique Name | Finding |
|--------|--------------|----------------|---------|
{{#MITRE_TECHNIQUES}}
| {{TACTIC}} | {{TECHNIQUE_ID}} | {{TECHNIQUE_NAME}} | {{FINDING}} |
{{/MITRE_TECHNIQUES}}

### 8.2 Attack Path Visualization

```
{{ATTACK_PATH_ASCII}}
```

---

## 9. Appendices

### Appendix A: Testing Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Nmap | 7.94 | Network discovery and scanning |
| Burp Suite | 2024.x | Web application testing |
| SQLMap | 1.8 | SQL injection testing |
| Nuclei | 3.x | Vulnerability scanning |
| Nikto | 2.5 | Web server scanning |
| Gobuster | 3.6 | Directory enumeration |
| ffuf | 2.1 | Web fuzzing |
| GHOST Toolkit | 2.3 | Agent-based testing |

### Appendix B: Discovered Assets

{{#ASSETS}}
| Type | Value | Info | Tags |
|------|-------|------|------|
| {{TYPE}} | {{VALUE}} | {{INFO}} | {{TAGS}} |
{{/ASSETS}}

### Appendix C: Discovered Credentials

**WARNING: Handle with care - sensitive data**

| Username | Type | Source | Status |
|----------|------|--------|--------|
{{#CREDENTIALS}}
| {{USERNAME}} | {{TYPE}} | {{SOURCE}} | {{STATUS}} |
{{/CREDENTIALS}}

### Appendix D: Testing Timeline

{{#TIMELINE}}
| Date | Time | Activity | Notes |
|------|------|----------|-------|
| {{DATE}} | {{TIME}} | {{ACTIVITY}} | {{NOTES}} |
{{/TIMELINE}}

### Appendix E: References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES Standard](http://www.pentest-standard.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CVSS 4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- [CWE Database](https://cwe.mitre.org/)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

## Document Classification

This document is classified as **CONFIDENTIAL** and is intended solely for {{CLIENT_NAME}}.

Unauthorized disclosure, copying, or distribution of this document is strictly prohibited.

---

*Report generated by GHOST v2.3*
*"Hack ethically. Document thoroughly. Improve security."*
