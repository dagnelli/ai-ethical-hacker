# SCRIBE References

## Documentation Standards

### CVSS
- **CVSS v3.1 Specification**: https://www.first.org/cvss/v3.1/specification-document
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **NVD Calculator**: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

### CWE (Common Weakness Enumeration)
- **CWE List**: https://cwe.mitre.org/data/index.html
- **CWE Top 25**: https://cwe.mitre.org/top25/

### CVE (Common Vulnerabilities and Exposures)
- **CVE List**: https://cve.mitre.org/
- **NVD**: https://nvd.nist.gov/

## OWASP Resources

### Testing Guides
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **OWASP ASVS**: https://owasp.org/www-project-application-security-verification-standard/

### Top 10 Lists
- **OWASP Top 10 2021**: https://owasp.org/www-project-top-ten/
- **OWASP API Security Top 10 2023**: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- **OWASP Mobile Top 10**: https://owasp.org/www-project-mobile-top-10/
- **OWASP LLM Top 10**: https://genai.owasp.org/

### Cheat Sheets
- **OWASP Cheat Sheet Series**: https://cheatsheetseries.owasp.org/

## Compliance Frameworks

### PCI DSS
- **PCI Security Standards**: https://www.pcisecuritystandards.org/
- **PCI DSS Requirements**: https://www.pcisecuritystandards.org/document_library/

### NIST
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **NIST 800-53**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

### ISO 27001
- **ISO/IEC 27001**: https://www.iso.org/isoiec-27001-information-security.html

### HIPAA
- **HHS HIPAA**: https://www.hhs.gov/hipaa/

### GDPR
- **GDPR Info**: https://gdpr-info.eu/

## Report Writing Resources

### Templates and Guides
- **PTES Reporting**: http://www.pentest-standard.org/index.php/Reporting
- **Offensive Security Report Guide**: https://www.offensive-security.com/reports/

### Best Practices
- **SANS Penetration Testing Report Writing**: https://www.sans.org/white-papers/

## Vulnerability Databases

| Database | URL | Use |
|----------|-----|-----|
| NVD | https://nvd.nist.gov | Official US vuln database |
| CVE | https://cve.mitre.org | CVE identifiers |
| Exploit-DB | https://www.exploit-db.com | Exploit information |
| VulDB | https://vuldb.com | Vulnerability intelligence |
| Snyk | https://snyk.io/vuln | Open source vulnerabilities |

## Remediation Resources

### Secure Coding
- **OWASP Secure Coding Practices**: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **SEI CERT Coding Standards**: https://wiki.sei.cmu.edu/confluence/display/seccode

### Security Headers
- **Security Headers Scanner**: https://securityheaders.com/
- **Mozilla Observatory**: https://observatory.mozilla.org/

### SSL/TLS
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **Mozilla SSL Configuration Generator**: https://ssl-config.mozilla.org/

## Tools for Reporting

### Screenshot Tools
- Flameshot
- Greenshot
- ShareX

### Report Generation
- Microsoft Word
- LaTeX
- Markdown → PDF converters

### Collaboration
- Git for version control
- Shared drives for evidence

## Writing Style Guides

### General
- Use active voice
- Be specific, not vague
- Quantify impact when possible
- Avoid jargon for executive summaries
- Include sufficient technical detail for technical reports

### Finding Descriptions
1. Clear title describing the issue
2. Technical description of vulnerability
3. Step-by-step reproduction
4. Evidence supporting the finding
5. Business/technical impact
6. Specific remediation steps
7. References to standards

## Quality Assurance

### Review Checklist
```
[ ] All findings documented
[ ] CVSS scores justified
[ ] Evidence attached
[ ] Remediation actionable
[ ] No sensitive data exposed
[ ] Spell-checked
[ ] Peer reviewed
[ ] Client identifiers correct
[ ] Scope boundaries respected
```

### Common Issues
- Vague remediation guidance
- Missing evidence
- Inconsistent severity ratings
- Technical jargon in executive summary
- Missing compliance mapping
- Incomplete finding descriptions

## Version Information

| Standard | Version | Date |
|----------|---------|------|
| CVSS | 3.1 | June 2019 |
| OWASP Top 10 | 2021 | 2021 |
| OWASP API Top 10 | 2023 | 2023 |
| CWE Top 25 | 2024 | 2024 |
| PCI DSS | 4.0 | March 2022 |

## Notes

- Always attribute findings to specific standards (CWE, OWASP)
- Use consistent terminology throughout report
- Tailor executive summary to non-technical audience
- Include positive findings to balance report
- Provide clear next steps and timeline recommendations
- Keep evidence organized and labeled
- Redact sensitive information before sharing
