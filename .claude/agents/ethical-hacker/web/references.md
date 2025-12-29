# SPIDER References

## Research Performed

### Searches Conducted
1. "OWASP Testing Guide v4.2"
2. "web application hacking techniques 2025"
3. "SQL injection cheat sheet"
4. "XSS bypass techniques modern"
5. "SSTI exploitation guide"
6. "deserialization attacks"
7. "file upload bypass techniques"

## Primary Sources

### OWASP Resources

#### OWASP Top 10 2021
- **Source**: https://owasp.org/Top10/
- **Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Key Categories**:
  - A01: Broken Access Control
  - A02: Cryptographic Failures
  - A03: Injection
  - A04: Insecure Design
  - A05: Security Misconfiguration
  - A06: Vulnerable Components
  - A07: Authentication Failures
  - A08: Integrity Failures
  - A09: Logging Failures
  - A10: SSRF

#### OWASP Cheat Sheets
- **Source**: https://cheatsheetseries.owasp.org/
- **Key Sheets**:
  - SQL Injection Prevention
  - XSS Prevention
  - Authentication
  - Session Management
  - Input Validation

### Injection Resources

#### SQL Injection
- **PortSwigger**: https://portswigger.net/web-security/sql-injection
- **SQLMap Wiki**: https://github.com/sqlmapproject/sqlmap/wiki
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

#### XSS
- **PortSwigger**: https://portswigger.net/web-security/cross-site-scripting
- **OWASP XSS Guide**: https://owasp.org/www-community/attacks/xss/
- **XSS Payloads**: https://github.com/payloadbox/xss-payload-list

#### Command Injection
- **OWASP**: https://owasp.org/www-community/attacks/Command_Injection
- **HackTricks**: https://book.hacktricks.xyz/pentesting-web/command-injection

### Advanced Techniques

#### Server-Side Template Injection
- **PortSwigger Research**: https://portswigger.net/research/server-side-template-injection
- **HackTricks SSTI**: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

#### Deserialization
- **PortSwigger**: https://portswigger.net/web-security/deserialization
- **ysoserial**: https://github.com/frohoff/ysoserial
- **phpggc**: https://github.com/ambionics/phpggc

#### SSRF
- **PortSwigger**: https://portswigger.net/web-security/ssrf
- **SSRF Bible**: https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/
- **Cloud Metadata SSRF**: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf

## Tool Documentation

### Vulnerability Scanners
| Tool | Documentation |
|------|---------------|
| nikto | https://github.com/sullo/nikto |
| nuclei | https://github.com/projectdiscovery/nuclei |
| wapiti | https://github.com/wapiti-scanner/wapiti |

### SQL Injection
| Tool | Documentation |
|------|---------------|
| sqlmap | https://github.com/sqlmapproject/sqlmap |

### XSS
| Tool | Documentation |
|------|---------------|
| dalfox | https://github.com/hahwul/dalfox |
| XSStrike | https://github.com/s0md3v/XSStrike |

### Directory Discovery
| Tool | Documentation |
|------|---------------|
| ffuf | https://github.com/ffuf/ffuf |
| gobuster | https://github.com/OJ/gobuster |
| feroxbuster | https://github.com/epi052/feroxbuster |

### Proxy Tools
| Tool | Documentation |
|------|---------------|
| Burp Suite | https://portswigger.net/burp/documentation |
| OWASP ZAP | https://www.zaproxy.org/docs/ |

## Research Blogs

### PortSwigger Research
- **URL**: https://portswigger.net/research
- **Key Topics**: Web security, new vulnerability classes, browser security

### Security Researcher Blogs
- Orange Tsai: https://blog.orange.tw/
- James Kettle: https://skeletonscribe.net/
- Corben Leo: https://www.corben.io/

## Cheat Sheets

### Quick Reference
| Topic | Source |
|-------|--------|
| SQL Injection | https://portswigger.net/web-security/sql-injection/cheat-sheet |
| XSS | https://portswigger.net/web-security/cross-site-scripting/cheat-sheet |
| Command Injection | https://book.hacktricks.xyz/pentesting-web/command-injection |
| SSTI | https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection |
| SSRF | https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery |

### Payload Collections
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- SecLists: https://github.com/danielmiessler/SecLists
- FuzzDB: https://github.com/fuzzdb-project/fuzzdb

## Training Resources

### Practice Platforms
| Platform | URL |
|----------|-----|
| PortSwigger Academy | https://portswigger.net/web-security |
| HackTheBox | https://www.hackthebox.com/ |
| TryHackMe | https://tryhackme.com/ |
| PentesterLab | https://pentesterlab.com/ |
| OWASP WebGoat | https://owasp.org/www-project-webgoat/ |

## Version Information

| Resource | Version | Verified |
|----------|---------|----------|
| OWASP Top 10 | 2021 | 2025-01 |
| OWASP Testing Guide | v4.2 | 2025-01 |
| sqlmap | Latest | 2025-01 |
| Burp Suite | Latest | 2025-01 |

## Notes

- Always test in authorized environments only
- Manual testing complements automated scanning
- Document all findings with evidence
- Consider business logic in addition to technical flaws
- Stay updated with latest bypass techniques
