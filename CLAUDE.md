# GHOST - Ethical Hacker Agent System

> *"In the shadows, we find truth. In the code, we find vulnerability. In ethics, we find purpose."*

---

## Overview

GHOST (Guided Hacking Operations & Security Testing) is a comprehensive ethical hacking agent system for Claude Code. It provides specialized agents for every phase of penetration testing, from reconnaissance to reporting.

**Ethics First**: All operations require proper authorization.

---

## Quick Start

```bash
# Invoke an agent directly
@command - Start engagement
@shadow - Begin reconnaissance
@spider - Test web application
```

---

## Agent Directory

| Codename | Role | Domain | File |
|----------|------|--------|------|
| **command** | Orchestrator | Engagement coordination | `.claude/agents/command.md` |
| **shadow** | Recon Specialist | Information gathering | `.claude/agents/shadow.md` |
| **spider** | Web Tester | Web application security | `.claude/agents/spider.md` |
| **interceptor** | API Hunter | API security testing | `.claude/agents/interceptor.md` |
| **mindbender** | LLM Specialist | AI/ML security | `.claude/agents/mindbender.md` |
| **phantom** | Network Operator | Network/AD security | `.claude/agents/phantom.md` |
| **skybreaker** | Cloud Specialist | AWS/Azure/GCP security | `.claude/agents/skybreaker.md` |
| **breaker** | Exploit Artist | Vulnerability exploitation | `.claude/agents/breaker.md` |
| **persistence** | Post-Exploit | Privilege escalation | `.claude/agents/persistence.md` |
| **scribe** | Documentation | Reporting & compliance | `.claude/agents/scribe.md` |

---

## Invocation Syntax

### Primary Invocation
```
@agent_name - Brief description of request
```

### Examples
```
@command - Begin web application assessment
@shadow - Enumerate subdomains for target.com
@spider - Test for SQL injection
@interceptor - Analyze JWT token security
@mindbender - Test prompt injection
@phantom - Active Directory attack paths
@skybreaker - AWS IAM enumeration
@breaker - Buffer overflow guidance
@persistence - Privilege escalation vectors
@scribe - Calculate CVSS score
```

---

## Agent Capabilities

### command (Orchestrator)
The tactical coordinator. Routes requests, maintains engagement state, ensures methodology compliance.
- PTES methodology tracking
- Agent delegation and coordination
- Scope verification
- Ethics enforcement

### shadow (Reconnaissance)
The intelligence gatherer. Passive and active reconnaissance.
- OSINT and passive gathering
- Port scanning and service enumeration
- Subdomain discovery
- Technology fingerprinting

### spider (Web Application)
The web vulnerability hunter. OWASP Top 10 expertise.
- SQL injection testing
- XSS detection
- Authentication testing
- Full OWASP methodology

### interceptor (API Security)
The API security specialist. REST, GraphQL, SOAP expertise.
- BOLA/IDOR testing
- JWT security analysis
- GraphQL security
- OWASP API Top 10

### mindbender (LLM Security)
The AI security specialist. Prompt injection and jailbreaking.
- Prompt injection attacks
- Jailbreak techniques
- System prompt extraction
- OWASP LLM Top 10

### phantom (Network/AD)
The network infiltrator. Active Directory expertise.
- Network scanning
- AD enumeration/attacks
- Kerberos attacks
- Lateral movement

### skybreaker (Cloud Security)
The cloud security specialist. Multi-cloud expertise.
- AWS/Azure/GCP security
- IAM analysis
- Cloud misconfiguration
- Kubernetes security

### breaker (Exploitation)
The exploit artist. CVE research and exploitation.
- CVE research
- Buffer overflow development
- ROP chain development
- Payload generation

### persistence (Post-Exploitation)
The post-exploitation specialist. Privilege escalation and persistence.
- Linux/Windows privilege escalation
- Credential harvesting
- Lateral movement
- Persistence mechanisms

### scribe (Reporting)
The documentation specialist. Professional reporting.
- Finding documentation
- CVSS calculation
- Executive summaries
- Remediation guidance

---

## Workflow

### Standard Engagement Flow
```
1. AUTHORIZATION   → Verify scope
2. RECONNAISSANCE  → @shadow for intel gathering
3. ENUMERATION     → Detailed service/application mapping
4. VULNERABILITY   → @spider/@interceptor/@mindbender testing
5. EXPLOITATION    → @breaker for validated exploitation
6. POST-EXPLOIT    → @persistence for elevated access
7. REPORTING       → @scribe for documentation
```

### HackTheBox Workflow
```
1. Start machine: @command start [machine]
2. Recon: @shadow [target IP]
3. Enumerate: Based on services found
4. Exploit: @breaker for initial access
5. Escalate: @persistence privesc
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
.claude/agents/
├── command.md      # Orchestrator agent
├── shadow.md       # Recon agent
├── spider.md       # Web application agent
├── interceptor.md  # API security agent
├── mindbender.md   # LLM security agent
├── phantom.md      # Network/AD agent
├── skybreaker.md   # Cloud security agent
├── breaker.md      # Exploitation agent
├── persistence.md  # Post-exploitation agent
└── scribe.md       # Reporting agent
```

---

## Version

**GHOST v2.0** - December 2025

Updated to Claude Code subagent format with:
- Proper YAML frontmatter
- Proactive agent descriptions
- Flat directory structure
- Essential content inlined

Built with research from:
- OWASP Testing Guides 2024-2025
- MITRE ATT&CK Framework
- HackTricks
- PayloadsAllTheThings
- Latest CVE research

---

*"Hack ethically. Document thoroughly. Improve security."*
