> Individual finding template with complete documentation structure

# Security Finding Report

---

## Finding: {{FINDING_TITLE}}

### Classification

| Attribute | Value |
|-----------|-------|
| **Finding ID** | `{{FINDING_ID}}` |
| **Severity** | {{SEVERITY}} |
| **CVSS 4.0 Score** | {{CVSS_SCORE}} ({{CVSS_SEVERITY}}) |
| **CVSS Vector** | `{{CVSS_VECTOR}}` |
| **Status** | {{STATUS}} |

### Vulnerability Classification

| Standard | ID | Name |
|----------|----|----- |
| **CWE** | {{CWE_ID}} | {{CWE_NAME}} |
| **CVE** | {{CVE_ID}} | {{CVE_DESCRIPTION}} |
| **OWASP** | {{OWASP_CATEGORY}} | {{OWASP_NAME}} |
| **MITRE ATT&CK** | {{MITRE_TECHNIQUE}} | {{MITRE_NAME}} |

### Discovery Information

| Field | Value |
|-------|-------|
| **Discovered By** | {{AGENT}} |
| **Discovery Phase** | {{PHASE}} |
| **Discovery Date** | {{DISCOVERED_AT}} |
| **Engagement** | {{ENGAGEMENT_NAME}} |

---

## Description

{{DESCRIPTION}}

### Technical Summary

{{TECHNICAL_SUMMARY}}

---

## Affected Resources

| Resource Type | Identifier | Details |
|--------------|------------|---------|
{{#AFFECTED_RESOURCES}}
| {{RESOURCE_TYPE}} | {{RESOURCE_ID}} | {{RESOURCE_DETAILS}} |
{{/AFFECTED_RESOURCES}}

### Affected Endpoints

{{#ENDPOINTS}}
- `{{METHOD}} {{URL}}`
  - Parameter: `{{PARAMETER}}`
  - Component: {{COMPONENT}}
{{/ENDPOINTS}}

---

## Proof of Concept

### Prerequisites

{{#PREREQUISITES}}
- {{PREREQUISITE}}
{{/PREREQUISITES}}

### Steps to Reproduce

{{#STEPS}}
**Step {{STEP_NUMBER}}:** {{STEP_TITLE}}

{{STEP_DESCRIPTION}}

```{{STEP_CODE_LANGUAGE}}
{{STEP_CODE}}
```

{{/STEPS}}

### HTTP Request

```http
{{POC_REQUEST_METHOD}} {{POC_REQUEST_URL}} HTTP/1.1
Host: {{POC_HOST}}
{{POC_REQUEST_HEADERS}}

{{POC_REQUEST_BODY}}
```

### HTTP Response

```http
HTTP/1.1 {{POC_RESPONSE_CODE}} {{POC_RESPONSE_STATUS}}
{{POC_RESPONSE_HEADERS}}

{{POC_RESPONSE_BODY}}
```

### Exploitation Result

{{EXPLOITATION_RESULT}}

---

## Impact Assessment

### Technical Impact

| Impact Category | Level | Description |
|-----------------|-------|-------------|
| **Confidentiality** | {{CONFIDENTIALITY_IMPACT}} | {{CONFIDENTIALITY_DESCRIPTION}} |
| **Integrity** | {{INTEGRITY_IMPACT}} | {{INTEGRITY_DESCRIPTION}} |
| **Availability** | {{AVAILABILITY_IMPACT}} | {{AVAILABILITY_DESCRIPTION}} |

### Business Impact

{{BUSINESS_IMPACT}}

#### Risk Scenarios

{{#RISK_SCENARIOS}}
1. **{{SCENARIO_TITLE}}**: {{SCENARIO_DESCRIPTION}}
   - Likelihood: {{LIKELIHOOD}}
   - Impact: {{IMPACT}}
{{/RISK_SCENARIOS}}

### Compliance Impact

| Framework | Requirement | Status |
|-----------|-------------|--------|
{{#COMPLIANCE_IMPACT}}
| {{FRAMEWORK}} | {{REQUIREMENT}} | {{STATUS}} |
{{/COMPLIANCE_IMPACT}}

---

## Evidence

### Screenshots

{{#SCREENSHOTS}}
| Screenshot | Description |
|------------|-------------|
| `{{SCREENSHOT_PATH}}` | {{SCREENSHOT_DESCRIPTION}} |
{{/SCREENSHOTS}}

### Request/Response Captures

| Capture | Location |
|---------|----------|
{{#CAPTURES}}
| {{CAPTURE_NAME}} | `{{CAPTURE_PATH}}` |
{{/CAPTURES}}

### Tool Output

| Tool | Output Location |
|------|-----------------|
{{#TOOL_OUTPUTS}}
| {{TOOL_NAME}} | `{{OUTPUT_PATH}}` |
{{/TOOL_OUTPUTS}}

### Additional Evidence

{{ADDITIONAL_EVIDENCE}}

---

## Remediation

### Immediate Mitigation

**Priority:** {{MITIGATION_PRIORITY}}
**Effort:** {{MITIGATION_EFFORT}}
**Timeline:** {{MITIGATION_TIMELINE}}

{{IMMEDIATE_MITIGATION}}

### Permanent Fix

**Priority:** {{FIX_PRIORITY}}
**Effort:** {{FIX_EFFORT}}
**Timeline:** {{FIX_TIMELINE}}

{{PERMANENT_FIX}}

### Code Example

**Vulnerable Code:**
```{{CODE_LANGUAGE}}
{{VULNERABLE_CODE}}
```

**Secure Code:**
```{{CODE_LANGUAGE}}
{{SECURE_CODE}}
```

### Configuration Changes

{{#CONFIG_CHANGES}}
**{{CONFIG_FILE}}:**
```{{CONFIG_FORMAT}}
{{CONFIG_CONTENT}}
```
{{/CONFIG_CHANGES}}

### Testing After Remediation

To verify the fix:

{{#VERIFICATION_STEPS}}
1. {{VERIFICATION_STEP}}
{{/VERIFICATION_STEPS}}

---

## CVSS 4.0 Breakdown

### Base Score: {{CVSS_SCORE}}

#### Exploitability Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| Attack Vector (AV) | {{AV}} | {{AV_DESC}} |
| Attack Complexity (AC) | {{AC}} | {{AC_DESC}} |
| Attack Requirements (AT) | {{AT}} | {{AT_DESC}} |
| Privileges Required (PR) | {{PR}} | {{PR_DESC}} |
| User Interaction (UI) | {{UI}} | {{UI_DESC}} |

#### Vulnerable System Impact

| Metric | Value | Description |
|--------|-------|-------------|
| Confidentiality (VC) | {{VC}} | {{VC_DESC}} |
| Integrity (VI) | {{VI}} | {{VI_DESC}} |
| Availability (VA) | {{VA}} | {{VA_DESC}} |

#### Subsequent System Impact

| Metric | Value | Description |
|--------|-------|-------------|
| Confidentiality (SC) | {{SC}} | {{SC_DESC}} |
| Integrity (SI) | {{SI}} | {{SI_DESC}} |
| Availability (SA) | {{SA}} | {{SA_DESC}} |

### Vector String

```
CVSS:4.0/AV:{{AV}}/AC:{{AC}}/AT:{{AT}}/PR:{{PR}}/UI:{{UI}}/VC:{{VC}}/VI:{{VI}}/VA:{{VA}}/SC:{{SC}}/SI:{{SI}}/SA:{{SA}}
```

---

## MITRE ATT&CK Mapping

### Technique Details

| Field | Value |
|-------|-------|
| **Technique ID** | {{MITRE_TECHNIQUE}} |
| **Technique Name** | {{MITRE_NAME}} |
| **Tactic** | {{MITRE_TACTIC}} |
| **Sub-technique** | {{MITRE_SUB}} |
| **Platform** | {{MITRE_PLATFORM}} |

### ATT&CK Reference

[View on MITRE ATT&CK](https://attack.mitre.org/techniques/{{MITRE_TECHNIQUE}}/)

### Detection Guidance

{{DETECTION_GUIDANCE}}

---

## References

### Vendor Documentation
{{#VENDOR_REFS}}
- [{{VENDOR_REF_TITLE}}]({{VENDOR_REF_URL}})
{{/VENDOR_REFS}}

### Security Standards
- [CWE-{{CWE_ID}}: {{CWE_NAME}}](https://cwe.mitre.org/data/definitions/{{CWE_ID_NUM}}.html)
- [OWASP: {{OWASP_NAME}}]({{OWASP_URL}})
- [MITRE ATT&CK: {{MITRE_NAME}}](https://attack.mitre.org/techniques/{{MITRE_TECHNIQUE}}/)

### Additional Resources
{{#ADDITIONAL_REFS}}
- [{{REF_TITLE}}]({{REF_URL}})
{{/ADDITIONAL_REFS}}

---

## Metadata

```json
{
  "finding_id": "{{FINDING_ID}}",
  "severity": "{{SEVERITY}}",
  "cvss": {
    "version": "4.0",
    "score": {{CVSS_SCORE}},
    "vector": "{{CVSS_VECTOR}}"
  },
  "classification": {
    "cwe_id": "{{CWE_ID}}",
    "cve_id": "{{CVE_ID}}",
    "owasp": "{{OWASP_CATEGORY}}",
    "mitre": "{{MITRE_TECHNIQUE}}"
  },
  "discovery": {
    "agent": "{{AGENT}}",
    "phase": "{{PHASE}}",
    "timestamp": "{{DISCOVERED_AT}}"
  },
  "status": "{{STATUS}}"
}
```

---

*Generated by GHOST v2.3*
*Finding documented at {{DISCOVERED_AT}}*
