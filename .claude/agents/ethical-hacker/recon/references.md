# SHADOW References

## Research Performed

### Searches Conducted
1. "subdomain enumeration techniques 2025 amass subfinder"
2. "reconnaissance methodology 2025"
3. "OSINT framework techniques"
4. "nmap scripting engine best scripts"
5. "passive vs active recon techniques"

## Primary Sources

### Subdomain Enumeration

#### Comprehensive Guide
- **Source**: https://medium.com/@rajeshsahan507/subdomain-enumeration-like-a-pro-complete-step-by-step-guide-2025-edition-692becbf2522
- **Key Points**:
  - Combine multiple tools for best results
  - Passive before active enumeration
  - Verify live hosts with httpx

#### ProjectDiscovery Recon Series
- **Source**: https://projectdiscovery.io/blog/recon-series-2
- **Key Points**:
  - Subfinder for passive enumeration
  - Amass for comprehensive discovery
  - Combine with httpx for verification

#### Tool Comparison
- **Source**: https://www.osintteam.com/passive-subdomain-enumeration-uncovering-more-subdomains-than-subfinder-amass/
- **Key Points**:
  - Amass: 87 passive sources
  - Subfinder: 45 sources
  - Combine both for best coverage

### Nmap Documentation
- **Official Docs**: https://nmap.org/docs.html
- **Book**: https://nmap.org/book/
- **NSE Scripts**: https://nmap.org/nsedoc/

### OSINT Resources
- **OSINT Framework**: https://osintframework.com/
- **IntelTechniques**: https://inteltechniques.com/
- **Shodan**: https://www.shodan.io/
- **Censys**: https://censys.io/

## Tool Documentation

### Port Scanning
| Tool | Documentation |
|------|---------------|
| nmap | https://nmap.org/docs.html |
| masscan | https://github.com/robertdavidgraham/masscan |
| rustscan | https://github.com/RustScan/RustScan |
| autorecon | https://github.com/Tib3rius/AutoRecon |

### DNS Enumeration
| Tool | Documentation |
|------|---------------|
| dnsrecon | https://github.com/darkoperator/dnsrecon |
| fierce | https://github.com/mschwager/fierce |
| dnsenum | https://github.com/fwaeytens/dnsenum |

### Subdomain Enumeration
| Tool | Documentation |
|------|---------------|
| amass | https://github.com/owasp-amass/amass |
| subfinder | https://github.com/projectdiscovery/subfinder |
| assetfinder | https://github.com/tomnomnom/assetfinder |

### Web Reconnaissance
| Tool | Documentation |
|------|---------------|
| httpx | https://github.com/projectdiscovery/httpx |
| whatweb | https://github.com/urbanadventurer/WhatWeb |
| wafw00f | https://github.com/EnableSecurity/wafw00f |

### Directory Discovery
| Tool | Documentation |
|------|---------------|
| ffuf | https://github.com/ffuf/ffuf |
| gobuster | https://github.com/OJ/gobuster |
| feroxbuster | https://github.com/epi052/feroxbuster |

### OSINT
| Tool | Documentation |
|------|---------------|
| theHarvester | https://github.com/laramies/theHarvester |
| recon-ng | https://github.com/lanmaster53/recon-ng |
| spiderfoot | https://github.com/smicallef/spiderfoot |

## Methodologies

### Reconnaissance Workflow
- **Source**: https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology
- **Key Phases**:
  1. Passive information gathering
  2. DNS enumeration
  3. Port scanning
  4. Service enumeration
  5. Web application discovery

### Bug Bounty Recon
- **Source**: https://www.yeswehack.com/learn-bug-bounty/subdomain-enumeration-expand-attack-surface
- **Key Points**:
  - Certificate Transparency is essential
  - Combine passive and active methods
  - Automate with continuous monitoring

## Cheat Sheets

### Nmap Cheat Sheet
- HackTricks: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network#nmap
- SANS: https://www.sans.org/posters/nmap-cheat-sheet/

### Subdomain Enumeration
- **Source**: https://sidxparab.gitbook.io/subdomain-enumeration-guide/
- Comprehensive guide with tool comparisons

## Wordlists

### Recommended Wordlists
| Purpose | Path |
|---------|------|
| Directories | /usr/share/wordlists/dirb/common.txt |
| Subdomains | /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt |
| Files | /usr/share/seclists/Discovery/Web-Content/common.txt |
| Vhosts | /usr/share/seclists/Discovery/DNS/namelist.txt |

### SecLists
- **Source**: https://github.com/danielmiessler/SecLists
- Comprehensive collection of security testing wordlists

## Version Information

| Tool | Version | Verified |
|------|---------|----------|
| nmap | 7.94+ | 2025-01 |
| amass | v4.x | 2025-01 |
| subfinder | v2.x | 2025-01 |
| nuclei | v3.x | 2025-01 |

## Notes

- Always start with passive reconnaissance
- Combine multiple subdomain tools for best coverage
- Verify live hosts before deeper enumeration
- Document all findings with timestamps
- Respect rate limits and scope boundaries
