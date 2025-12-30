# Penetration Test Report
## HackTheBox - Expressway Machine

---

**Classification: Confidential**

| Field | Value |
|-------|-------|
| **Target** | 10.129.18.12 (expressway.htb) |
| **Assessment Type** | HackTheBox CTF - Full Penetration Test |
| **Testing Period** | 2025-12-30 |
| **Tester** | GHOST Framework |
| **Report Version** | 1.0 |
| **Report Date** | 2025-12-30 |

---

# Executive Summary

## Overview

GHOST Framework conducted a penetration test against the HackTheBox Expressway machine (10.129.18.12) on December 30, 2025. The assessment resulted in complete system compromise, achieving both user-level and root-level access.

## Risk Summary

| Severity | Count |
|----------|-------|
| **Critical** | 1 |
| **High** | 2 |
| **Medium** | 0 |
| **Low** | 0 |

**Overall Risk Rating: CRITICAL**

## Key Findings

1. **CVE-2025-32463 - Sudo Chroot Privilege Escalation** (Critical)
   - Vulnerable sudo version allows local privilege escalation to root through chroot escape
   - Immediate patching required

2. **Weak IKE VPN Pre-Shared Key** (High)
   - VPN pre-shared key cracked in seconds using common wordlist
   - Enables unauthorized VPN access to internal network

3. **Credential Reuse - SSH** (High)
   - VPN pre-shared key reused as SSH password
   - Provides direct system access with minimal effort

## Attack Chain Summary

The assessment demonstrated a complete attack chain from external reconnaissance to full root compromise:

```
External Recon → VPN Credential Crack → SSH Access → Privilege Escalation → Root
```

Total time from discovery to root: Minimal (weak credentials + known CVE)

## Strategic Recommendations

1. **Immediate**: Patch sudo to version 1.9.17p1 or later to remediate CVE-2025-32463
2. **Short-term**: Implement strong, unique credentials for all services (VPN, SSH)
3. **Medium-term**: Disable IKE aggressive mode, implement certificate-based VPN authentication
4. **Long-term**: Implement privileged access management (PAM) and credential vaulting

---

# Technical Findings

## Finding 1: CVE-2025-32463 - Sudo Chroot Privilege Escalation

### Risk Rating

| Metric | Value |
|--------|-------|
| **CVSS 3.1 Score** | 9.8 (Critical) |
| **CVSS Vector** | AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **CVE** | CVE-2025-32463 |

### CVSS Breakdown

| Factor | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Local | Requires local system access |
| Attack Complexity | Low | Public exploit available, trivial execution |
| Privileges Required | Low | Standard user account sufficient |
| User Interaction | None | No user interaction required |
| Scope | Changed | Escapes security boundary (chroot) |
| Confidentiality | High | Complete root access |
| Integrity | High | Full system modification capability |
| Availability | High | Complete system control |

### Description

The target system runs sudo version 1.9.17, which is vulnerable to CVE-2025-32463. This vulnerability allows a local attacker with low privileges to escape a chroot environment and achieve root-level access through malicious NSS (Name Service Switch) library loading.

### Affected Resources

- **System**: 10.129.18.12 (expressway.htb)
- **Component**: /usr/local/bin/sudo
- **Version**: 1.9.17

### Impact

- **Technical Impact**: Complete system compromise with root privileges
- **Business Impact**: Full control over the system, ability to access all data, modify configurations, and establish persistent access

### Proof of Concept

```
1. Identify sudo version: sudo --version → 1.9.17
2. Confirm vulnerability via public CVE database
3. Execute publicly available exploit
4. Achieve root shell
```

### Evidence

```
$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17

$ id
uid=0(root) gid=0(root) groups=0(root)
```

**Root Flag Captured**: `938f19c37c770140e5e8726965db9ef0`

### Remediation

1. **Immediate**: Update sudo to version 1.9.17p1 or later
   ```bash
   apt update && apt upgrade sudo
   # Or download from https://www.sudo.ws/
   ```
2. **Alternative**: If immediate patching is not possible, restrict sudo access to essential users only
3. **Detection**: Monitor for unusual sudo usage patterns and chroot-related system calls

### References

- [CVE-2025-32463 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)
- [Sudo Security Advisories](https://www.sudo.ws/security/)

---

## Finding 2: Weak IKE VPN Pre-Shared Key

### Risk Rating

| Metric | Value |
|--------|-------|
| **CVSS 3.1 Score** | 7.5 (High) |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CWE** | CWE-521 (Weak Password Requirements) |
| **OWASP** | A07:2021 - Identification and Authentication Failures |

### CVSS Breakdown

| Factor | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Remotely exploitable over UDP |
| Attack Complexity | Low | Standard tools, common wordlist |
| Privileges Required | None | No authentication required |
| User Interaction | None | No user interaction required |
| Scope | Unchanged | VPN service compromise |
| Confidentiality | High | Network traffic exposure, internal access |
| Integrity | None | No direct integrity impact |
| Availability | None | No availability impact |

### Description

The IKE (Internet Key Exchange) VPN service running on UDP port 500 is configured in aggressive mode, which exposes the group identity and allows extraction of the pre-shared key (PSK) hash. The configured PSK "freakingrockstarontheroad" was cracked in seconds using the common rockyou.txt wordlist, indicating extremely weak credential strength.

### Affected Resources

- **System**: 10.129.18.12 (expressway.htb)
- **Service**: IKE/ISAKMP
- **Port**: UDP 500
- **Identity**: ike@expressway.htb

### Impact

- **Technical Impact**: Unauthorized VPN access to internal network
- **Business Impact**: Network perimeter bypass, potential access to internal resources, lateral movement capability

### Proof of Concept

```bash
# 1. Identify IKE service and aggressive mode support
ike-scan -M -A 10.129.18.12

# 2. Extract PSK hash with group identity
ike-scan -M -A --id=ike@expressway.htb 10.129.18.12 > hash.txt

# 3. Crack PSK hash
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt

# Result: freakingrockstarontheroad (cracked in seconds)
```

### Evidence

```
Starting ike-scan 1.9.5 with 1 hosts
10.129.18.12    Aggressive Mode Handshake returned
    HDR=(CKY-R=...)
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK)
    ID(type=ID_USER_FQDN, data=ike@expressway.htb)

PSK Crack Result:
key "freakingrockstarontheroad" matches hash
```

### Remediation

1. **Immediate**: Change VPN pre-shared key to a strong, random value
   - Minimum 20 characters
   - Mix of uppercase, lowercase, numbers, special characters
   - Generated randomly (not based on dictionary words)

2. **Short-term**: Disable IKE aggressive mode
   ```
   # Cisco example
   crypto isakmp aggressive-mode disable
   ```

3. **Long-term**: Migrate to certificate-based authentication
   - Implement PKI infrastructure
   - Use X.509 certificates for VPN authentication
   - Remove PSK-based authentication entirely

4. **Monitoring**: Implement logging for VPN authentication attempts

### References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [IKE Aggressive Mode Security](https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/14106-ike-aggressive-mode.html)
- [NIST SP 800-77 Guide to IPsec VPNs](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final)

---

## Finding 3: Credential Reuse - SSH

### Risk Rating

| Metric | Value |
|--------|-------|
| **CVSS 3.1 Score** | 8.1 (High) |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| **CWE** | CWE-255 (Credentials Management Errors) |
| **OWASP** | A07:2021 - Identification and Authentication Failures |

### CVSS Breakdown

| Factor | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Remotely exploitable via SSH |
| Attack Complexity | Low | Direct credential reuse |
| Privileges Required | None | Credentials obtained from VPN crack |
| User Interaction | None | No user interaction required |
| Scope | Unchanged | SSH service compromise |
| Confidentiality | High | User-level system access |
| Integrity | High | File system modification capability |
| Availability | None | No direct availability impact |

### Description

The pre-shared key cracked from the IKE VPN service is reused as the SSH password for the user "ike". This credential reuse pattern allows an attacker who compromises one service to immediately gain access to additional services without further exploitation effort.

### Affected Resources

- **System**: 10.129.18.12 (expressway.htb)
- **Service**: SSH (OpenSSH)
- **Port**: TCP 22
- **Username**: ike
- **Password**: freakingrockstarontheroad (reused from VPN PSK)

### Impact

- **Technical Impact**: Direct shell access to the system as user "ike"
- **Business Impact**: Initial foothold for further attack, access to user data and files, platform for privilege escalation

### Proof of Concept

```bash
# SSH authentication using cracked VPN PSK
ssh ike@10.129.18.12
# Password: freakingrockstarontheroad

# Successful authentication - user shell obtained
ike@expressway:~$ id
uid=1000(ike) gid=1000(ike) groups=1000(ike)
```

### Evidence

```
$ ssh ike@10.129.18.12
ike@10.129.18.12's password: [freakingrockstarontheroad]
Welcome to Ubuntu...
ike@expressway:~$ whoami
ike
ike@expressway:~$ cat user.txt
780eab361df4a223714ded01d373ade1
```

**User Flag Captured**: `780eab361df4a223714ded01d373ade1`

### Remediation

1. **Immediate**: Change the SSH password for user "ike" to a unique, strong password

2. **Short-term**: Implement SSH key-only authentication
   ```bash
   # /etc/ssh/sshd_config
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```

3. **Medium-term**: Implement a password management policy
   - Unique passwords per service/system
   - Enterprise password vault solution
   - Regular credential rotation

4. **Long-term**: Implement centralized identity management
   - LDAP/Active Directory integration
   - Multi-factor authentication
   - Privileged Access Management (PAM)

### References

- [CIS Benchmark - SSH](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

---

# Attack Narrative

## Phase 1: Reconnaissance

Initial reconnaissance began with network scanning to identify available services:

```bash
# TCP scan revealed SSH on port 22
nmap -sV -sC 10.129.18.12

# UDP scan discovered IKE VPN on port 500
nmap -sU -p 500 10.129.18.12
```

Key discovery: IKE/ISAKMP service running on UDP 500, indicating VPN infrastructure.

## Phase 2: VPN Credential Attack

Identified IKE aggressive mode support, which exposes identity information:

```bash
# Aggressive mode probe with identity enumeration
ike-scan -M -A --id=ike@expressway.htb 10.129.18.12
```

Extracted PSK hash and cracked using standard wordlist:

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
# Result: freakingrockstarontheroad
```

The weak PSK was cracked in seconds, demonstrating inadequate password strength.

## Phase 3: Initial Access

Leveraging credential reuse, the VPN PSK was successfully used for SSH authentication:

```bash
ssh ike@10.129.18.12
# Password: freakingrockstarontheroad
```

User-level access achieved. User flag captured.

## Phase 4: Privilege Escalation

Local enumeration revealed vulnerable sudo version:

```bash
sudo --version
# Sudo version 1.9.17
```

CVE-2025-32463 affects this version, allowing chroot escape privilege escalation. Exploitation yielded root shell.

Root flag captured.

## Phase 5: Engagement Complete

Full compromise achieved through:
1. Weak VPN credentials
2. Credential reuse across services
3. Unpatched privilege escalation vulnerability

---

# Appendices

## Appendix A: Testing Methodology

This assessment followed the PTES (Penetration Testing Execution Standard) methodology:

1. **Pre-engagement Interactions**: Scope definition (HackTheBox machine)
2. **Intelligence Gathering**: Service enumeration and reconnaissance
3. **Threat Modeling**: Attack path identification
4. **Vulnerability Analysis**: Service-specific vulnerability identification
5. **Exploitation**: Controlled exploitation of discovered vulnerabilities
6. **Post-Exploitation**: Privilege escalation and system compromise
7. **Reporting**: This document

## Appendix B: Tools Used

| Tool | Purpose | Version |
|------|---------|---------|
| nmap | Port scanning and service enumeration | 7.94+ |
| ike-scan | IKE VPN analysis and hash extraction | 1.9.5 |
| psk-crack | PSK hash cracking | 1.9.5 |
| ssh | Remote access | OpenSSH client |

## Appendix C: Testing Timeline

| Time | Activity | Result |
|------|----------|--------|
| T+0 | TCP/UDP port scan | Identified SSH (22), IKE (500) |
| T+5min | IKE aggressive mode probe | Extracted identity and PSK hash |
| T+6min | PSK cracking | Recovered: freakingrockstarontheroad |
| T+7min | SSH access attempt | Success - user shell |
| T+10min | Local enumeration | Identified vulnerable sudo |
| T+15min | Privilege escalation | Root shell achieved |

## Appendix D: Flags Captured

| Flag Type | Hash | Location |
|-----------|------|----------|
| User | `780eab361df4a223714ded01d373ade1` | /home/ike/user.txt |
| Root | `938f19c37c770140e5e8726965db9ef0` | /root/root.txt |

## Appendix E: Compliance Mapping

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Finding |
|--------------|----------------|---------|
| T1110.002 | Brute Force: Password Cracking | Weak IKE PSK |
| T1078.001 | Valid Accounts: Default Accounts | Credential Reuse |
| T1068 | Exploitation for Privilege Escalation | CVE-2025-32463 |

### CIS Controls Mapping

| Control | Description | Finding |
|---------|-------------|---------|
| 4.1 | Establish and Maintain a Secure Configuration Process | Sudo vulnerability |
| 5.2 | Use Unique Passwords | Credential reuse |
| 6.3 | Require MFA for Externally-Exposed Applications | VPN weak auth |

---

# Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-30 | GHOST Framework | Initial release |

---

**End of Report**

*Generated by SCRIBE - GHOST Framework Documentation Agent*
