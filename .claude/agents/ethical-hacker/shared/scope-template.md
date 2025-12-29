# Penetration Test Scope Definition

> *"Scope is sacred. We test what we're authorized to test. Nothing more. Nothing less."*

---

## Engagement Details

| Field | Value |
|-------|-------|
| Client | [CLIENT_NAME] |
| Engagement ID | [ENGAGEMENT_ID] |
| Tester | GHOST |
| Start Date | [START_DATE] |
| End Date | [END_DATE] |
| Testing Hours | [e.g., 09:00-18:00 UTC, Business hours only] |
| Report Due | [REPORT_DATE] |

---

## In-Scope Targets

### Network Assets

| IP/Range | Hostname | Type | Notes |
|----------|----------|------|-------|
| [IP_ADDRESS] | [hostname.domain.com] | [Server/Workstation/Network Device] | [Notes] |
| [CIDR_RANGE] | - | [Network Range] | [Notes] |

### Web Applications

| URL | Type | Authentication | Notes |
|-----|------|----------------|-------|
| [https://app.domain.com] | [Production/Staging/Dev] | [Yes/No] | [Notes] |

### APIs

| Endpoint | Type | Authentication | Notes |
|----------|------|----------------|-------|
| [https://api.domain.com/v1] | [REST/GraphQL/SOAP] | [API Key/OAuth/None] | [Notes] |

### AI/LLM Systems

| URL | Model | Type | Notes |
|-----|-------|------|-------|
| [https://chat.domain.com] | [GPT-4/Claude/Custom] | [Chat/Agent/RAG] | [Notes] |

### Cloud Assets

| Provider | Account/Subscription | Resources | Notes |
|----------|---------------------|-----------|-------|
| [AWS/Azure/GCP] | [Account ID] | [EC2, S3, Lambda, etc.] | [Notes] |

### Mobile Applications

| App Name | Platform | Version | Notes |
|----------|----------|---------|-------|
| [App Name] | [iOS/Android/Both] | [Version] | [Notes] |

---

## Out-of-Scope

### Excluded Targets

| Target | Reason |
|--------|--------|
| [IP/Domain] | [Production database - risk too high] |
| [IP/Domain] | [Third-party service - no authorization] |
| [IP/Domain] | [Shared hosting - affects other customers] |

### Excluded Activities

| Activity | Reason |
|----------|--------|
| [Denial of Service] | [Not authorized] |
| [Social Engineering] | [Out of scope for this engagement] |
| [Physical Access] | [Remote testing only] |

---

## Allowed Attack Types

### Authorized

- [x] **Network Scanning** - Port scanning, service enumeration
- [x] **Web Application Testing** - OWASP Top 10, business logic
- [x] **API Testing** - OWASP API Top 10
- [x] **LLM/AI Testing** - OWASP LLM Top 10
- [ ] **Social Engineering** - [If checked, specify type]
- [ ] **Physical Access** - [If checked, specify locations]
- [ ] **Denial of Service** - [If checked, specify limits]
- [ ] **Data Exfiltration** - [If checked, must be sanitized]

### Testing Depth

| Category | Depth | Notes |
|----------|-------|-------|
| Vulnerability Scanning | Full | Automated + Manual |
| Exploitation | Controlled | No data modification |
| Post-Exploitation | Limited | Document only |
| Privilege Escalation | Yes | Stop at Domain Admin |
| Lateral Movement | Yes | Document paths only |
| Persistence | No | Do not install |

---

## Restrictions

### Technical Restrictions

- [ ] No testing during [specific hours]
- [ ] No automated scanning against [specific systems]
- [ ] No brute force attacks against [specific services]
- [ ] No modification of [specific data]
- [ ] Maximum concurrent connections: [number]
- [ ] Bandwidth limits: [if applicable]

### Data Handling Restrictions

- [ ] Do not access [specific data types]
- [ ] Do not exfiltrate any production data
- [ ] Redact all PII in reports
- [ ] Encrypt all evidence at rest

### Notification Requirements

- [ ] Notify before testing [specific systems]
- [ ] Daily status updates required
- [ ] Immediate notification for critical findings

---

## Emergency Contacts

| Role | Name | Email | Phone | Availability |
|------|------|-------|-------|--------------|
| Technical POC | [NAME] | [EMAIL] | [PHONE] | [24/7 / Business Hours] |
| Management POC | [NAME] | [EMAIL] | [PHONE] | [24/7 / Business Hours] |
| Security Team | [NAME] | [EMAIL] | [PHONE] | [24/7 / Business Hours] |
| Legal Contact | [NAME] | [EMAIL] | [PHONE] | [Business Hours] |

### Escalation Procedures

1. **Critical Finding**: Call Technical POC immediately
2. **System Compromise Suspected**: Call Security Team
3. **Legal Concerns**: Contact Legal and stop testing
4. **Unable to Reach POC**: Contact Management POC

---

## Rules of Engagement

### Permitted Actions

1. Port scanning and service enumeration
2. Vulnerability scanning with industry-standard tools
3. Manual testing and exploitation attempts
4. Credential testing against in-scope systems
5. Screenshot and evidence collection
6. Report generation

### Prohibited Actions

1. Testing outside defined scope
2. Destructive attacks without explicit approval
3. Accessing systems not listed in scope
4. Sharing findings with unauthorized parties
5. Installing persistent backdoors
6. Modifying production data

### Incident Handling

If an incident occurs during testing:
1. **STOP** all testing immediately
2. **DOCUMENT** what happened
3. **NOTIFY** emergency contact within [X] minutes
4. **PRESERVE** all evidence
5. **AWAIT** instructions before resuming

---

## Credentials & Access

### Provided Credentials

| System | Username | Access Level | Notes |
|--------|----------|--------------|-------|
| [System] | [username] | [User/Admin/Root] | [Notes] |

### VPN/Network Access

| Type | Details |
|------|---------|
| VPN | [VPN endpoint and credentials] |
| Jump Host | [If applicable] |
| Network Segment | [Which VLANs accessible] |

---

## Authorization Statement

This document authorizes the penetration testing team (GHOST) to perform security testing on the above-listed targets within the specified timeframe and according to the rules of engagement defined herein.

The undersigned confirms they have the authority to authorize this testing on behalf of [CLIENT_NAME].

### Client Authorization

```
Company: _________________________________

Authorized By: ___________________________

Title: __________________________________

Signature: ______________________________

Date: __________________________________
```

### Tester Acknowledgment

```
Tester: GHOST

I acknowledge and agree to abide by the scope, rules of engagement, and restrictions defined in this document.

Signature: ______________________________

Date: __________________________________
```

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [DATE] | [NAME] | Initial scope |

---

## Appendix A: Testing Tools

Authorized tools include but are not limited to:
- Nmap, Masscan, RustScan
- Burp Suite, OWASP ZAP
- SQLMap, ffuf, Gobuster
- Metasploit Framework
- Impacket, CrackMapExec
- Custom scripts as needed

## Appendix B: Compliance Requirements

If applicable, note compliance frameworks:
- [ ] PCI-DSS
- [ ] HIPAA
- [ ] SOC 2
- [ ] ISO 27001
- [ ] GDPR
- [ ] Other: _______________
