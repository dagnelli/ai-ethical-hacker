# GHOST - Ethical Hacker Agent System

> *"In the shadows, we find truth. In the code, we find vulnerability. In ethics, we find purpose."*

---

## Overview

GHOST (Guided Hacking Operations & Security Testing) is a comprehensive ethical hacking agent system for Claude Code. It provides specialized agents for every phase of penetration testing, from reconnaissance to reporting.

**Ethics First**: All operations require proper authorization.

---

## Quick Start

```bash
# Standard mode - invoke agents directly
@command - Start engagement
@shadow - Begin reconnaissance
@spider - Test web application

# Parallel mode - hunter/gather with auto-dispatch
~/.claude/scripts/ghost-parallel-init.sh myengagement 10.10.10.100
export GHOST_ENGAGEMENT="/tmp/ghost/active"
@command - Begin parallel engagement
```

---

## Agent Directory

### Core Agents
| Codename | Role | Domain | File |
|----------|------|--------|------|
| **command** | Orchestrator | Engagement coordination | `.claude/agents/command.md` |
| **shadow** | Recon Specialist | Information gathering | `.claude/agents/shadow.md` |
| **spider** | Web Coordinator | Web app testing orchestration | `.claude/agents/spider.md` |
| **interceptor** | API Hunter | API security testing | `.claude/agents/interceptor.md` |
| **mindbender** | LLM Specialist | AI/ML security | `.claude/agents/mindbender.md` |
| **phantom** | Network Operator | Network/AD security | `.claude/agents/phantom.md` |
| **skybreaker** | Cloud Specialist | AWS/Azure/GCP security | `.claude/agents/skybreaker.md` |
| **breaker** | Exploit Artist | Vulnerability exploitation | `.claude/agents/breaker.md` |
| **persistence** | Post-Exploit | Privilege escalation | `.claude/agents/persistence.md` |
| **scribe** | Documentation | Reporting & compliance | `.claude/agents/scribe.md` |

### Web Sub-Agents (OWASP WSTG 4.2)
| Codename | Role | WSTG Coverage | File |
|----------|------|---------------|------|
| **venom** | Injection Specialist | WSTG-INPV (19 tests) | `.claude/agents/venom.md` |
| **gatekeeper** | Auth/Access Specialist | WSTG-IDNT/ATHN/AUTHZ/SESS (28 tests) | `.claude/agents/gatekeeper.md` |
| **trickster** | Logic Specialist | WSTG-BUSL (12 tests) | `.claude/agents/trickster.md` |
| **specter** | Client-Side Specialist | WSTG-CLNT (13 tests) | `.claude/agents/specter.md` |

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
@spider - Coordinate full web app test (auto-dispatches sub-agents)
@interceptor - Analyze JWT token security
@mindbender - Test prompt injection
@phantom - Active Directory attack paths
@skybreaker - AWS IAM enumeration
@breaker - Buffer overflow guidance
@persistence - Privilege escalation vectors
@scribe - Calculate CVSS score

# Web Sub-Agents (auto-dispatched by @spider or invoked directly)
@venom - Test SQL injection on login form
@gatekeeper - Test JWT algorithm confusion
@trickster - Test race condition on coupon apply
@specter - Test DOM XSS via URL hash
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

### spider (Web Coordinator)
The web application security coordinator. Orchestrates specialized sub-agents.
- OWASP WSTG 4.2 methodology
- Auto-dispatches @venom, @gatekeeper, @trickster, @specter
- Handles WSTG-INFO, WSTG-CONF, WSTG-CRYP, WSTG-ERR directly
- Aggregates and prioritizes web findings

### venom (Injection Specialist)
The injection specialist. SQL whispers secrets.
- SQL injection (all types and DB variants)
- XSS (reflected, stored, context-aware)
- Command injection, SSTI, XXE, SSRF
- WAF bypass techniques

### gatekeeper (Auth/Access Specialist)
The authentication and authorization breaker.
- JWT attacks (none, confusion, cracking)
- OAuth/OIDC exploitation
- Session management attacks
- IDOR and privilege escalation

### trickster (Business Logic Specialist)
The logic manipulator. Rules are suggestions.
- Race conditions (Turbo Intruder)
- Workflow bypass
- Price/quantity manipulation
- File upload attacks

### specter (Client-Side Specialist)
The browser haunter. DOM speaks to me.
- DOM XSS (sources, sinks, clobbering)
- CORS exploitation
- WebSocket/postMessage attacks
- Clickjacking

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

## Parallel Mode (Hunter-Gather)

GHOST supports parallel agent execution with automatic trigger-based dispatch.

### Architecture
```
/tmp/ghost/
├── engagements/{name}/
│   ├── state.json          # Current phase, active hunters
│   ├── plan.json           # Attack dependency graph
│   ├── findings.json       # Consolidated findings
│   ├── runlog.jsonl        # Audit trail
│   ├── tasks/
│   │   ├── pending/        # Queued tasks
│   │   ├── running/        # Active tasks
│   │   └── completed/      # Finished tasks
│   └── hunters/{agent}/    # Per-agent working dirs
└── active -> {current}     # Symlink to active engagement
```

### Scripts
| Script | Purpose |
|--------|---------|
| `ghost-parallel-init.sh` | Initialize engagement with parallel support |
| `ghost-dispatch.sh` | Queue and manage tasks |
| `ghost-findings.sh` | Add findings, assets, credentials |
| `ghost-watchdog.sh` | Auto-dispatch based on triggers |

### Usage

```bash
# 1. Initialize parallel engagement
~/.claude/scripts/ghost-parallel-init.sh htb-box 10.10.10.100

# 2. Set environment
export GHOST_ENGAGEMENT="/tmp/ghost/active"
export TARGET="10.10.10.100"

# 3. Start with COMMAND (auto-dispatches recon)
@command - Begin parallel engagement on $TARGET

# 4. Monitor progress
~/.claude/scripts/ghost-dispatch.sh status

# 5. View findings
~/.claude/scripts/ghost-findings.sh export summary

# 6. Start auto-dispatch watchdog (optional)
~/.claude/scripts/ghost-watchdog.sh start
```

### Smart Dispatch Logic (v2.0)
- **Parallel within phases**: All recon runs simultaneously
- **Sequential between phases**: Recon completes before enumeration
- **Trigger-based**: Findings auto-dispatch appropriate agents
  - Port 80/443 → @spider
  - Port 445 → @phantom
  - /api/ endpoint → @interceptor
  - LLM detected → @mindbender
- **Auto-progression**: Phases advance when completion criteria met
- **Auto-regression**: New discoveries trigger expanded recon

### Phase Completion Criteria
| Phase | Criteria | Auto-Progress To |
|-------|----------|------------------|
| recon | tasks done + ports ≥ 1 | enumeration |
| enumeration | triggered tasks done | vulnerability |
| vulnerability | vuln scans done | exploitation (if vulns) |
| exploitation | shell or exhausted | post_exploitation |
| post_exploitation | root or exhausted | reporting |

### Enhanced Findings (v2.0)
```bash
# Add finding with MITRE ATT&CK, CVSS 4.0, CWE, CVE
~/.claude/scripts/ghost-findings.sh add critical "SQL Injection" "Login form" T1190 CWE-89 9.8 CVE-2024-1234

# Add port (auto-tagged)
~/.claude/scripts/ghost-findings.sh port 443 https "nginx 1.24"

# Add asset with tags
~/.claude/scripts/ghost-findings.sh asset endpoint "/api/users" "REST API" "api,auth"

# Phase management
~/.claude/scripts/ghost-watchdog.sh phase              # Show phase & metrics
~/.claude/scripts/ghost-watchdog.sh regress recon      # Force regression
~/.claude/scripts/ghost-watchdog.sh flag user <hash>   # Capture user flag
~/.claude/scripts/ghost-watchdog.sh flag root <hash>   # Capture root flag
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
.claude/
├── agents/
│   ├── command.md      # Orchestrator agent
│   ├── shadow.md       # Recon agent
│   ├── spider.md       # Web coordinator agent
│   ├── venom.md        # Injection specialist (WSTG-INPV)
│   ├── gatekeeper.md   # Auth/access specialist (WSTG-IDNT/ATHN/AUTHZ/SESS)
│   ├── trickster.md    # Business logic specialist (WSTG-BUSL)
│   ├── specter.md      # Client-side specialist (WSTG-CLNT)
│   ├── interceptor.md  # API security agent
│   ├── mindbender.md   # LLM security agent
│   ├── phantom.md      # Network/AD agent
│   ├── skybreaker.md   # Cloud security agent
│   ├── breaker.md      # Exploitation agent
│   ├── persistence.md  # Post-exploitation agent
│   ├── scribe.md       # Reporting agent
│   └── references/     # Research documents
│       ├── client-side-vulnerabilities.md
│       └── business-logic-vulnerabilities.md
├── memory/                     # Memory Cortex & TTP Engine (v3.0)
│   ├── cortex.json             # Long-term memory store
│   ├── cortex-schema.json      # JSON schema for memory
│   └── ttp-rules.json          # Adaptive TTP rule-based knowledge
├── templates/                  # Report templates (v3.0)
│   ├── executive-summary.md    # Executive report template
│   ├── technical-report.md     # Full technical report template
│   ├── finding-template.md     # Individual finding template
│   ├── remediation-guide.md    # Fix recommendations template
│   └── compliance-mappings.json # CWE/NIST/ISO/PCI/OWASP mappings
├── resources/
│   └── business-logic-vulnerabilities.md
├── scripts/
│   ├── ghost-init.sh           # Standard engagement init
│   ├── ghost-parallel-init.sh  # Parallel mode init
│   ├── ghost-dispatch.sh       # Task queue management
│   ├── ghost-findings.sh       # Findings management
│   ├── ghost-watchdog.sh       # Auto-dispatch monitor
│   ├── ghost-memory.sh         # Memory Cortex management (v3.0)
│   ├── ghost-research.sh       # CVE/Exploit-DB research (v3.0)
│   ├── ghost-vault.sh          # Encrypted credential storage (v3.0)
│   ├── ghost-ttp.sh            # Adaptive TTP engine (v3.0)
│   ├── ghost-report.sh         # Professional report generator (v3.0)
│   └── ghost-cleanup.sh        # Engagement cleanup
└── settings.json               # GHOST configuration
```

---

## Version

**GHOST v3.0** - December 2025

### New in v3.0 (Full Intelligence Suite)

**Memory Cortex** (`ghost-memory.sh`)
- Long-term memory for engagements, techniques, and patterns
- Technique effectiveness tracking by context (linux, windows, web, AD, cloud)
- Pattern matching to recognize target fingerprints
- Engagement recall for similar past operations
- Learning loop from engagement outcomes

**Research Engine** (`ghost-research.sh`)
- Real-time CVE lookup via NVD API
- Exploit-DB search (searchsploit + web fallback)
- Built-in technique database (kerberoasting, SQLi, XSS, SSRF, etc.)
- Service/version to CVE correlation
- GitHub Security Advisories integration
- Intelligent caching with TTL and rate limiting

**Secure Vault** (`ghost-vault.sh`)
- AES256 GPG symmetric encryption for credentials
- Credential types: password, hash, key, token, api_key, ssh_key, certificate
- Secrets never logged to access.log (audit trail safe)
- Secure temp files with shred cleanup
- Export with hashed secrets for reporting

**Adaptive TTP Engine** (`ghost-ttp.sh`)
- Context-aware technique recommendations
- 18+ MITRE ATT&CK techniques with prerequisites and blockers
- 12 target contexts (linux, windows, AD, cloud, API, etc.)
- 6 predefined attack chains
- Blocker bypass suggestions
- Combines learned effectiveness with rule-based knowledge

**Enhanced Reports** (`ghost-report.sh`)
- Professional templates (executive, technical, finding, remediation)
- CVSS 4.0 scoring with full metric breakdown
- Compliance mapping (NIST 800-53, ISO 27001, PCI DSS, OWASP)
- Export formats: Markdown, HTML, JSON, PDF
- 80+ CWE to compliance framework mappings

### Previous (v2.3 - Web Sub-Agents)
- **OWASP WSTG 4.2 Coverage**: Full 72+ test coverage via specialized agents
- **@spider Coordinator**: Orchestrates web testing with auto-dispatch
- **@venom Agent**: Injection specialist (SQLi, XSS, CMDi, SSTI, XXE, SSRF)
- **@gatekeeper Agent**: Auth/access specialist (JWT, OAuth, IDOR, sessions)
- **@trickster Agent**: Business logic specialist (race, workflow, upload)
- **@specter Agent**: Client-side specialist (DOM XSS, CORS, WebSockets)
- **Research Documents**: Comprehensive technique references with 2024-2025 CVEs

### Previous (v2.2)
- PTES Phase Sequencing with completion criteria
- Auto-Progression/Regression
- MITRE ATT&CK, CVSS 4.0, CWE/CVE mapping
- Phase metrics and history

### Previous (v2.1)
- Concurrent agent execution (Hunter-Gather)
- Auto-dispatch based on triggers
- Shared state via JSON files
- Runlog audit trail

Built with research from:
- OWASP WSTG 4.2 (Web Security Testing Guide)
- PTES (Penetration Testing Execution Standard)
- NIST SP 800-115
- OWASP Testing Guides 2024-2025
- MITRE ATT&CK Framework
- CVSS 4.0 Specification
- PortSwigger Research
- HackTricks & PayloadsAllTheThings

---

*"Hack ethically. Document thoroughly. Improve security."*
