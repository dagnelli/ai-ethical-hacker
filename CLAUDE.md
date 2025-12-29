# GHOST - Ethical Hacker Agent System

> *"In the shadows, we find truth. In the code, we find vulnerability. In ethics, we find purpose."*

---

## Overview

GHOST (Guided Hacking Operations & Security Testing) is a comprehensive ethical hacking agent system for Claude Code. It provides specialized agents for every phase of penetration testing, from reconnaissance to reporting.

**Ethics First**: All operations require proper authorization. Review `shared/ethics-guardrails.md` before any engagement.

---

## Quick Start

```bash
# Initialize GHOST for a new engagement
.claude/scripts/ghost-init.sh

# Invoke the orchestrator
@COMMAND - Start engagement
```

---

## Agent Directory

| Codename | Role | Domain | Location |
|----------|------|--------|----------|
| **COMMAND** | Orchestrator | Engagement coordination | `orchestrator/` |
| **SHADOW** | Recon Specialist | Information gathering | `recon/` |
| **SPIDER** | Web Tester | Web application security | `web/` |
| **INTERCEPTOR** | API Hunter | API security testing | `api/` |
| **MINDBENDER** | LLM Specialist | AI/ML security | `llm/` |
| **PHANTOM** | Network Operator | Network/AD security | `network/` |
| **SKYBREAKER** | Cloud Specialist | AWS/Azure/GCP security | `cloud/` |
| **BREAKER** | Exploit Artist | Vulnerability exploitation | `exploit/` |
| **PERSISTENCE** | Post-Exploit | Privilege escalation | `post-exploit/` |
| **SCRIBE** | Documentation | Reporting & compliance | `report/` |

---

## Invocation Syntax

### Primary Invocation
```
@AGENT_NAME - Brief description of request
```

### Specialized Functions
```
@AGENT_NAME:function - Specific capability request
```

### Examples
```
@COMMAND - Begin web application assessment
@SHADOW:subdomain - Enumerate subdomains for target.com
@SPIDER:sqli - Test for SQL injection
@INTERCEPTOR:jwt - Analyze JWT token security
@MINDBENDER:injection - Test prompt injection
@PHANTOM:ad - Active Directory attack paths
@SKYBREAKER:aws - AWS IAM enumeration
@BREAKER:bof - Buffer overflow guidance
@PERSISTENCE:privesc - Privilege escalation vectors
@SCRIBE:cvss - Calculate CVSS score
```

---

## Agent Details

### COMMAND (Orchestrator)
**File**: `orchestrator/agent.md`

The tactical coordinator. Routes requests, maintains engagement state, ensures methodology compliance.

**Functions**:
- `@COMMAND` - General orchestration
- `@COMMAND:status` - Engagement status
- `@COMMAND:methodology` - Current phase guidance

---

### SHADOW (Reconnaissance)
**Files**: `recon/agent.md`, `recon/tools-kali.md`, `recon/tools-windows.md`

The intelligence gatherer. Passive and active reconnaissance.

**Functions**:
- `@SHADOW:passive` - OSINT, passive gathering
- `@SHADOW:active` - Port scanning, service enumeration
- `@SHADOW:subdomain` - Subdomain enumeration
- `@SHADOW:tech` - Technology fingerprinting

---

### SPIDER (Web Application)
**Files**: `web/agent.md`, `web/owasp-top10-tests.md`, `web/tools-kali.md`

The web vulnerability hunter. OWASP Top 10 expertise.

**Functions**:
- `@SPIDER:sqli` - SQL injection testing
- `@SPIDER:xss` - Cross-site scripting
- `@SPIDER:auth` - Authentication testing
- `@SPIDER:owasp` - Full OWASP methodology

---

### INTERCEPTOR (API Security)
**Files**: `api/agent.md`, `api/owasp-api-tests.md`, `api/tools.md`

The API security specialist. REST, GraphQL, SOAP expertise.

**Functions**:
- `@INTERCEPTOR:auth` - API authentication testing
- `@INTERCEPTOR:bola` - BOLA/IDOR testing
- `@INTERCEPTOR:jwt` - JWT security analysis
- `@INTERCEPTOR:graphql` - GraphQL security

---

### MINDBENDER (LLM Security)
**Files**: `llm/agent.md`, `llm/owasp-llm-top10.md`, `llm/attack-prompts/`

The AI security specialist. 100+ attack prompts included.

**Functions**:
- `@MINDBENDER:injection` - Prompt injection attacks
- `@MINDBENDER:jailbreak` - Jailbreak techniques
- `@MINDBENDER:extraction` - System prompt extraction
- `@MINDBENDER:disclosure` - Information disclosure

**Attack Prompt Library**:
- `01-prompt-injection.md` - 45+ injection prompts
- `02-info-disclosure.md` - 62+ disclosure prompts
- `03-supply-chain.md` - Supply chain attacks
- `04-data-poisoning.md` - Poisoning techniques
- `05-output-handling.md` - Output manipulation
- `06-excessive-agency.md` - Agency exploitation
- `07-system-prompt-leak.md` - 75+ extraction prompts
- `08-vector-embedding.md` - RAG attacks
- `09-misinformation.md` - Hallucination exploitation
- `10-unbounded-consumption.md` - DoS techniques

---

### PHANTOM (Network/AD)
**Files**: `network/agent.md`, `network/ad-attack-paths.md`, `network/tools-kali.md`

The network infiltrator. Active Directory expertise.

**Functions**:
- `@PHANTOM:scan` - Network scanning
- `@PHANTOM:ad` - AD enumeration/attacks
- `@PHANTOM:lateral` - Lateral movement
- `@PHANTOM:kerberos` - Kerberos attacks

---

### SKYBREAKER (Cloud Security)
**Files**: `cloud/agent.md`, `cloud/aws-checks.md`, `cloud/azure-checks.md`, `cloud/gcp-checks.md`

The cloud security specialist. Multi-cloud expertise.

**Functions**:
- `@SKYBREAKER:aws` - AWS security assessment
- `@SKYBREAKER:azure` - Azure security assessment
- `@SKYBREAKER:gcp` - GCP security assessment
- `@SKYBREAKER:iam` - IAM analysis
- `@SKYBREAKER:k8s` - Kubernetes security

---

### BREAKER (Exploitation)
**Files**: `exploit/agent.md`, `exploit/tools-kali.md`, `exploit/exploit-db-usage.md`

The exploit artist. CVE research and exploitation.

**Functions**:
- `@BREAKER:cve` - CVE research
- `@BREAKER:bof` - Buffer overflow
- `@BREAKER:rop` - ROP chain development
- `@BREAKER:payload` - Payload generation

---

### PERSISTENCE (Post-Exploitation)
**Files**: `post-exploit/agent.md`, `post-exploit/privesc-linux.md`, `post-exploit/privesc-windows.md`

The post-exploitation specialist. Privilege escalation and persistence.

**Functions**:
- `@PERSISTENCE:privesc` - Privilege escalation
- `@PERSISTENCE:creds` - Credential harvesting
- `@PERSISTENCE:lateral` - Lateral movement
- `@PERSISTENCE:persist` - Persistence mechanisms

---

### SCRIBE (Reporting)
**Files**: `report/agent.md`, `report/templates/`

The documentation specialist. Professional reporting.

**Functions**:
- `@SCRIBE:finding` - Document finding
- `@SCRIBE:cvss` - Calculate CVSS
- `@SCRIBE:executive` - Executive summary
- `@SCRIBE:remediation` - Remediation guidance

**Templates**:
- `executive-summary.md` - Executive report template
- `technical-findings.md` - Technical report template
- `owasp-mapping.md` - OWASP reference mapping
- `cvss-calculator.md` - CVSS scoring guide
- `remediation-guide.md` - Fix templates

---

## Shared Resources

| File | Purpose |
|------|---------|
| `shared/ghost-mindset.md` | GHOST philosophy and principles |
| `shared/ethics-guardrails.md` | Non-negotiable ethics rules |
| `shared/htb-config.md` | HackTheBox integration |
| `shared/scope-template.md` | Authorization template |
| `shared/master-references.md` | Consolidated references |

---

## Workflow

### Standard Engagement Flow
```
1. AUTHORIZATION   → Verify scope with ethics-guardrails.md
2. RECONNAISSANCE  → @SHADOW for intel gathering
3. ENUMERATION     → Detailed service/application mapping
4. VULNERABILITY   → @SPIDER/@INTERCEPTOR/@MINDBENDER testing
5. EXPLOITATION    → @BREAKER for validated exploitation
6. POST-EXPLOIT    → @PERSISTENCE for elevated access
7. REPORTING       → @SCRIBE for documentation
```

### HackTheBox Workflow
```
1. Start machine: @COMMAND:htb start [machine]
2. Recon: @SHADOW [target IP]
3. Enumerate: Based on services found
4. Exploit: @BREAKER for initial access
5. Escalate: @PERSISTENCE:privesc
6. Document: Capture flags and methods
```

---

## Ethics & Authorization

### Before ANY Engagement

1. **Verify Authorization**: Written permission from asset owner
2. **Define Scope**: Clear boundaries of what can be tested
3. **Document Exclusions**: Systems/techniques not permitted
4. **Emergency Contacts**: Who to call if issues arise

### Never Permitted
- Testing without authorization
- Exceeding defined scope
- Data exfiltration beyond PoC
- Denial of service (unless authorized)
- Social engineering of non-consenting parties

---

## Directory Structure

```
.claude/agents/ethical-hacker/
├── orchestrator/
│   ├── agent.md
│   ├── tools.md
│   └── references.md
├── recon/
│   ├── agent.md
│   ├── tools-kali.md
│   ├── tools-windows.md
│   └── references.md
├── web/
│   ├── agent.md
│   ├── owasp-top10-tests.md
│   ├── tools-kali.md
│   ├── tools-windows.md
│   └── references.md
├── api/
│   ├── agent.md
│   ├── owasp-api-tests.md
│   ├── tools.md
│   └── references.md
├── llm/
│   ├── agent.md
│   ├── owasp-llm-top10.md
│   ├── references.md
│   └── attack-prompts/
│       ├── 01-prompt-injection.md
│       ├── 02-info-disclosure.md
│       ├── 03-supply-chain.md
│       ├── 04-data-poisoning.md
│       ├── 05-output-handling.md
│       ├── 06-excessive-agency.md
│       ├── 07-system-prompt-leak.md
│       ├── 08-vector-embedding.md
│       ├── 09-misinformation.md
│       └── 10-unbounded-consumption.md
├── network/
│   ├── agent.md
│   ├── ad-attack-paths.md
│   ├── tools-kali.md
│   ├── tools-windows.md
│   └── references.md
├── cloud/
│   ├── agent.md
│   ├── tools.md
│   ├── aws-checks.md
│   ├── azure-checks.md
│   ├── gcp-checks.md
│   └── references.md
├── exploit/
│   ├── agent.md
│   ├── tools-kali.md
│   ├── tools-windows.md
│   ├── exploit-db-usage.md
│   └── references.md
├── post-exploit/
│   ├── agent.md
│   ├── tools-kali.md
│   ├── tools-windows.md
│   ├── privesc-linux.md
│   ├── privesc-windows.md
│   ├── persistence-techniques.md
│   └── references.md
├── report/
│   ├── agent.md
│   ├── references.md
│   └── templates/
│       ├── executive-summary.md
│       ├── technical-findings.md
│       ├── owasp-mapping.md
│       ├── cvss-calculator.md
│       └── remediation-guide.md
└── shared/
    ├── ghost-mindset.md
    ├── ethics-guardrails.md
    ├── htb-config.md
    ├── scope-template.md
    └── master-references.md
```

---

## Scripts

| Script | Purpose |
|--------|---------|
| `.claude/scripts/ghost-init.sh` | Initialize new engagement workspace |
| `.claude/scripts/ghost-cleanup.sh` | Clean up engagement artifacts |

---

## Version

**GHOST v1.0** - January 2025

Built with research from:
- OWASP Testing Guides 2024-2025
- MITRE ATT&CK Framework
- HackTricks
- PayloadsAllTheThings
- Latest CVE research

---

*"Hack ethically. Document thoroughly. Improve security."*
