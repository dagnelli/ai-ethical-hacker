# INTERCEPTOR References

## Research Performed

### Searches Conducted
1. "OWASP API Security Top 10 2023"
2. "API penetration testing checklist"
3. "GraphQL hacking techniques"
4. "REST API security testing"
5. "JWT vulnerabilities exploitation"
6. "API rate limiting bypass"

## Primary Sources

### OWASP API Security

#### OWASP API Security Top 10 2023
- **Source**: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- **Project Page**: https://owasp.org/www-project-api-security/
- **Categories**:
  - API1: Broken Object Level Authorization
  - API2: Broken Authentication
  - API3: Broken Object Property Level Authorization
  - API4: Unrestricted Resource Consumption
  - API5: Broken Function Level Authorization
  - API6: Unrestricted Access to Sensitive Business Flows
  - API7: Server Side Request Forgery
  - API8: Security Misconfiguration
  - API9: Improper Inventory Management
  - API10: Unsafe Consumption of APIs

#### OWASP API Security Cheat Sheet
- **Source**: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- **Key Topics**: Authentication, authorization, input validation

### JWT Security

#### JWT.io
- **Source**: https://jwt.io/
- **Description**: JWT decoder and debugger

#### JWT Attacks Guide
- **Source**: https://portswigger.net/web-security/jwt
- **Key Attacks**:
  - None algorithm
  - Weak secrets
  - Algorithm confusion
  - Header injection

#### jwt_tool Documentation
- **Source**: https://github.com/ticarpi/jwt_tool
- **Description**: Comprehensive JWT testing toolkit

### GraphQL Security

#### GraphQL Security Guide
- **Source**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- **Key Topics**: Introspection, query depth, batching attacks

#### HackTricks GraphQL
- **Source**: https://book.hacktricks.xyz/pentesting-web/graphql
- **Key Topics**: Enumeration, injection, DoS attacks

### API Penetration Testing

#### API Security Testing Guide
- **Source**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic
- **Key Topics**: Business logic, authentication, authorization

#### Postman Security Testing
- **Source**: https://learning.postman.com/docs/writing-scripts/script-references/test-examples/
- **Description**: API testing automation

## Tool Documentation

### API Discovery
| Tool | Documentation |
|------|---------------|
| Kiterunner | https://github.com/assetnote/kiterunner |
| Arjun | https://github.com/s0md3v/Arjun |
| ffuf | https://github.com/ffuf/ffuf |

### JWT Tools
| Tool | Documentation |
|------|---------------|
| jwt_tool | https://github.com/ticarpi/jwt_tool |
| jwt-cracker | https://github.com/brendan-rius/c-jwt-cracker |

### GraphQL Tools
| Tool | Documentation |
|------|---------------|
| GraphQLmap | https://github.com/swisskyrepo/GraphQLmap |
| InQL | https://github.com/doyensec/inql |
| graphql-cop | https://github.com/dolevf/graphql-cop |

### Proxy Tools
| Tool | Documentation |
|------|---------------|
| Burp Suite | https://portswigger.net/burp/documentation |
| mitmproxy | https://docs.mitmproxy.org/ |
| Postman | https://www.postman.com/docs |

## API Security Blogs

### Research & Articles
- PortSwigger Research: https://portswigger.net/research
- API Security: https://apisecurity.io/
- Salt Security Blog: https://salt.security/blog/
- 42Crunch Blog: https://42crunch.com/blog/

### Conference Talks
- OWASP API Security talks
- DEF CON API hacking presentations
- Black Hat API security briefings

## Cheat Sheets

### Quick Reference
| Topic | Source |
|-------|--------|
| REST Security | https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html |
| GraphQL Security | https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html |
| JWT Security | https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html |
| API Authentication | https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html |

### Payload Collections
- PayloadsAllTheThings API: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks
- SecLists API: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api

## Training Resources

### Practice Platforms
| Platform | URL |
|----------|-----|
| PortSwigger Labs | https://portswigger.net/web-security/api-testing |
| HackTheBox | https://www.hackthebox.com/ |
| PentesterLab | https://pentesterlab.com/ |
| Damn Vulnerable GraphQL | https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application |
| OWASP crAPI | https://github.com/OWASP/crAPI |

## Version Information

| Resource | Version | Verified |
|----------|---------|----------|
| OWASP API Top 10 | 2023 | 2025-01 |
| jwt_tool | Latest | 2025-01 |
| GraphQLmap | Latest | 2025-01 |

## Notes

- API security requires understanding of business logic
- Automated tools miss many authorization issues
- Manual testing is essential for BOLA/BFLA
- Document all API endpoints discovered
- Test each HTTP method on each endpoint
- Check for API versioning bypass opportunities
