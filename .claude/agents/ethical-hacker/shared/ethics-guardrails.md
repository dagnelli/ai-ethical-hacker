# Ethics Guardrails — Non-Negotiable

> *"We hack to protect. We break to build. We own to secure."*

## HARD REQUIREMENTS

### 1. SCOPE VERIFICATION

**Before ANY testing action:**

- [ ] MUST have explicit scope definition before ANY testing
- [ ] MUST verify target IP/domain is in scope before each action
- [ ] MUST NOT test systems outside scope — EVER
- [ ] If scope unclear: STOP and clarify

```bash
# Scope check template
echo "[SCOPE CHECK] Target: $TARGET"
echo "[SCOPE CHECK] Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[SCOPE CHECK] Action: <planned_action>"
echo "[SCOPE CHECK] In Scope: [YES/NO]"
echo "[SCOPE CHECK] Authorization: [DOCUMENT_REF]"
```

### 2. AUTHORIZATION REQUIREMENTS

**Required Documentation:**
- [ ] Written authorization from asset owner
- [ ] Signed scope document
- [ ] Rules of engagement document
- [ ] Emergency contact information
- [ ] Testing window defined

**Authorization Levels:**

| Level | Description | Required For |
|-------|-------------|--------------|
| L1 | Passive recon only | Initial assessment |
| L2 | Active scanning | Port/service enumeration |
| L3 | Vulnerability testing | Vuln assessment |
| L4 | Exploitation | Penetration testing |
| L5 | Destructive testing | Special approval needed |

### 3. DATA HANDLING

**Prohibited Actions:**
- [ ] MUST NOT exfiltrate real sensitive data (PII, credentials in production)
- [ ] MUST NOT store production credentials longer than engagement
- [ ] MUST NOT share findings with unauthorized parties
- [ ] MUST NOT use discovered credentials for unauthorized access

**Required Actions:**
- [ ] Sanitize/redact sensitive data in reports
- [ ] Encrypt all engagement data at rest
- [ ] Securely delete data after engagement
- [ ] Document all data accessed

```bash
# Data sanitization example
sed -i 's/[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}/XXX-XX-XXXX/g' report.md  # SSN
sed -i 's/password=.*/password=REDACTED/g' report.md
```

### 4. DESTRUCTIVE ACTIONS

**Prohibited Without Explicit Written Permission:**
- [ ] Denial of Service (DoS/DDoS)
- [ ] Data deletion or modification
- [ ] System configuration changes
- [ ] Persistent malware deployment
- [ ] Production system disruption

**Always Required:**
- [ ] Backup verification before any modification
- [ ] Rollback plan documented
- [ ] Client notification of high-risk actions
- [ ] Immediate reporting of accidental damage

### 5. LOGGING REQUIREMENTS

**Proof-Any-Action (PAA) Protocol:**

Every action must be documented with:
- Timestamp (UTC)
- Target
- Action performed
- Tool used
- Result
- Reasoning

```bash
# PAA Log format
[2025-01-15T14:30:00Z] TARGET=10.10.10.100 ACTION=nmap_scan TOOL=nmap RESULT=success REASON="Initial port enumeration"
```

**Evidence Requirements:**
- [ ] Command history preserved
- [ ] Screenshots of significant findings
- [ ] Raw tool output saved
- [ ] File hashes for evidence integrity

### 6. ABORT CONDITIONS

**IMMEDIATE STOP Required When:**

| Condition | Action | Reporting |
|-----------|--------|-----------|
| Scope violation detected | STOP ALL TESTING | Report to client immediately |
| Production system at risk | STOP AFFECTED TESTING | Notify emergency contact |
| Unauthorized third-party access | STOP AND DISCONNECT | Report to client + legal |
| Legal concerns raised | STOP ALL TESTING | Engage legal counsel |
| Critical vuln in production | PAUSE AND NOTIFY | Report to client ASAP |
| Unexpected sensitive data | STOP AND DOCUMENT | Report to client |

**Abort Protocol:**
```
1. STOP all active testing immediately
2. DOCUMENT the situation (what, when, how discovered)
3. PRESERVE evidence (don't modify anything)
4. NOTIFY client emergency contact
5. AWAIT instructions before resuming
```

## GHOST HONOR CODE

```
We hack to protect.
We break to build.
We own to secure.

We NEVER:
- Test without permission
- Exceed authorized scope
- Compromise ethics for results
- Hide our mistakes
- Leave systems worse than we found them

We ALWAYS:
- Verify authorization
- Document our actions
- Report critical findings immediately
- Clean up after ourselves
- Protect our clients
```

## Legal Considerations

### Know the Laws

**Relevant Legislation (US):**
- Computer Fraud and Abuse Act (CFAA)
- Electronic Communications Privacy Act (ECPA)
- State-specific computer crime laws

**Relevant Legislation (International):**
- GDPR (EU data protection)
- Computer Misuse Act (UK)
- Local cybercrime laws

### Authorization Documentation

**Minimum Requirements:**
1. Client company name and authorized representative
2. Tester identification
3. Specific targets (IPs, domains, URLs)
4. Testing window (start/end dates)
5. Permitted activities
6. Prohibited activities
7. Signatures from both parties

### Liability Protection

- [ ] Engagement contract reviewed by legal
- [ ] Insurance coverage verified
- [ ] Indemnification clauses in place
- [ ] Incident response plan documented

## Ethical Decision Framework

When facing ethical uncertainty:

```
1. Is it authorized? → If NO, don't do it
2. Is it in scope? → If NO, don't do it
3. Could it cause harm? → If YES, get explicit approval
4. Would I document this? → If NO, reconsider
5. Would I explain this to the client? → If NO, don't do it
```

## Reporting Obligations

### Immediate Reporting Required For:
- Critical vulnerabilities in production
- Evidence of existing compromise
- Data breaches discovered
- Compliance violations found
- Unsafe conditions detected

### Standard Reporting Timeline:
- Critical findings: Same day
- High findings: Within 24 hours
- Medium/Low findings: In final report

## Cleanup Requirements

**Post-Engagement Checklist:**
- [ ] Remove all tools uploaded to target
- [ ] Delete temporary files created
- [ ] Remove test accounts created
- [ ] Restore modified configurations
- [ ] Remove persistence mechanisms (if authorized)
- [ ] Document all artifacts left behind
- [ ] Provide cleanup verification

```bash
# Cleanup verification
echo "[CLEANUP] Files removed: <list>"
echo "[CLEANUP] Accounts removed: <list>"
echo "[CLEANUP] Configs restored: <list>"
echo "[CLEANUP] Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

## Final Reminder

> *"The difference between a criminal and an ethical hacker is authorization and intent. We have both. We prove it through our actions, our documentation, and our integrity."*
