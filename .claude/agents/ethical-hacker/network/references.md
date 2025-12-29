# PHANTOM References

## Research Performed

### Searches Conducted
1. "Active Directory penetration testing 2025"
2. "Kerberos attacks explained"
3. "NTLM relay attack guide"
4. "BloodHound attack paths"
5. "impacket examples"
6. "Windows lateral movement techniques"
7. "network pivoting techniques"
8. "crackmapexec modules"

## Primary Sources

### Active Directory Security

#### Kerberos Attacks
- **Source**: https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/kerberos-offensive-playbook-enumeration-ticket-abuse/
- **Key Topics**: Kerberoasting, AS-REP, Golden/Silver Tickets

#### 2025 Kerberos Vulnerabilities
- **CVE-2025-33073**: Reflective Kerberos Relay Attack
- **Source**: https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/

#### Microsoft Mitigations
- **Source**: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- **Key Recommendation**: Use gMSA/dMSA for service accounts

### Tool Documentation

#### Impacket
- **Source**: https://github.com/fortra/impacket
- **Examples**: https://github.com/fortra/impacket/tree/master/examples

#### BloodHound
- **Source**: https://github.com/BloodHoundAD/BloodHound
- **Documentation**: https://bloodhound.readthedocs.io/

#### Mimikatz
- **Source**: https://github.com/gentilkiwi/mimikatz
- **Wiki**: https://github.com/gentilkiwi/mimikatz/wiki

#### Rubeus
- **Source**: https://github.com/GhostPack/Rubeus
- **Documentation**: In-tool help

#### NetExec (CrackMapExec)
- **Source**: https://github.com/Pennyw0rth/NetExec
- **Documentation**: https://www.netexec.wiki/

#### Responder
- **Source**: https://github.com/lgandx/Responder

## Knowledge Resources

### HackTricks
- **AD Methodology**: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- **Kerberos Attacks**: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-authentication
- **Lateral Movement**: https://book.hacktricks.xyz/windows-hardening/lateral-movement

### The Hacker Recipes
- **Source**: https://www.thehacker.recipes/
- **AD Section**: https://www.thehacker.recipes/ad/

### ired.team
- **Source**: https://www.ired.team/
- **AD Notes**: Comprehensive AD attack documentation

### SpecterOps
- **Blog**: https://posts.specterops.io/
- **Focus**: BloodHound, AD security research

## Attack Technique References

### MITRE ATT&CK

| Technique | ID | Reference |
|-----------|-----|-----------|
| Kerberoasting | T1558.003 | https://attack.mitre.org/techniques/T1558/003/ |
| AS-REP Roasting | T1558.004 | https://attack.mitre.org/techniques/T1558/004/ |
| Golden Ticket | T1558.001 | https://attack.mitre.org/techniques/T1558/001/ |
| Pass-the-Hash | T1550.002 | https://attack.mitre.org/techniques/T1550/002/ |
| DCSync | T1003.006 | https://attack.mitre.org/techniques/T1003/006/ |
| LLMNR Poisoning | T1557.001 | https://attack.mitre.org/techniques/T1557/001/ |

### WADComs
- **Source**: https://wadcoms.github.io/
- **Description**: Windows/AD command reference

## Cheat Sheets

### Quick References
| Topic | Source |
|-------|--------|
| AD Pentest | https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet |
| Impacket | https://cheatsheet.haax.fr/windows-systems/exploitation/impacket/ |
| Kerberos | https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a |
| BloodHound | https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/ |

## Training Resources

### Practice Labs
| Platform | URL | Focus |
|----------|-----|-------|
| HackTheBox Pro Labs | https://www.hackthebox.com/ | AD environments |
| TryHackMe AD Path | https://tryhackme.com/ | AD learning |
| PentesterLab | https://pentesterlab.com/ | AD badges |

### Certifications
- CRTO (Certified Red Team Operator)
- OSCP (AD focus in updated exam)
- PNPT (Practical Network Penetration Tester)

## Version Information

| Tool | Version | Verified |
|------|---------|----------|
| Impacket | Latest | 2025-01 |
| BloodHound | 4.x | 2025-01 |
| Mimikatz | Latest | 2025-01 |
| Rubeus | Latest | 2025-01 |
| NetExec | Latest | 2025-01 |

## Notes

- AD attacks require understanding of Windows authentication
- Test in authorized environments only
- Document all attack paths discovered
- BloodHound is essential for complex environments
- Always verify SMB signing before relay attacks
- Stay updated on new techniques and CVEs
