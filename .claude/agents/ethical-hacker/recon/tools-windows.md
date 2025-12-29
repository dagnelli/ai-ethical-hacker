# SHADOW Tools Reference — Windows/FLARE-VM

> *"Every platform has its tools. Master them all."*

## Port Scanning

### nmap for Windows
**Source**: https://nmap.org/download.html#windows

```powershell
# Quick initial scan
nmap -sC -sV -oA recon\nmap-initial $TARGET

# Full TCP port scan
nmap -p- -T4 -oA recon\nmap-full-tcp $TARGET

# Service version detection
nmap -sV -oA recon\nmap-services $TARGET

# Script scan
nmap --script=default -oA recon\nmap-scripts $TARGET
```

### PowerShell Port Scanning

```powershell
# Quick port scan (no external tools)
function Test-Port {
    param([string]$ComputerName, [int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($ComputerName, $Port)
        $tcp.Close()
        return $true
    } catch {
        return $false
    }
}

# Scan common ports
$ports = @(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080)
foreach ($port in $ports) {
    if (Test-Port -ComputerName $TARGET -Port $port) {
        Write-Host "Port $port is OPEN" -ForegroundColor Green
    }
}

# Scan port range
1..1024 | ForEach-Object {
    if (Test-Port -ComputerName $TARGET -Port $_) {
        Write-Host "Port $_ is OPEN"
    }
}
```

### Advanced IP Scanner
```
# GUI tool for network discovery
# Download from: https://www.advanced-ip-scanner.com/
# Scans for: IP, hostname, MAC, manufacturer, open ports
```

## DNS Enumeration

### PowerShell DNS

```powershell
# Resolve hostname
Resolve-DnsName $DOMAIN

# Specific record types
Resolve-DnsName -Name $DOMAIN -Type A
Resolve-DnsName -Name $DOMAIN -Type MX
Resolve-DnsName -Name $DOMAIN -Type TXT
Resolve-DnsName -Name $DOMAIN -Type NS
Resolve-DnsName -Name $DOMAIN -Type CNAME
Resolve-DnsName -Name $DOMAIN -Type SOA

# Reverse lookup
Resolve-DnsName $IP

# Zone transfer attempt
Resolve-DnsName -Name $DOMAIN -Type AXFR -DnsOnly -Server $NS_SERVER
```

### nslookup

```cmd
# Basic lookup
nslookup $DOMAIN

# Specific record type
nslookup -type=mx $DOMAIN
nslookup -type=txt $DOMAIN
nslookup -type=ns $DOMAIN

# Zone transfer
nslookup
server $NS_SERVER
set type=any
ls -d $DOMAIN
```

### dnscmd (if available)

```cmd
# Enumerate zones
dnscmd /enumzones

# Zone info
dnscmd /zoneinfo $DOMAIN
```

## Active Directory Reconnaissance

### ADRecon
**Source**: https://github.com/adrecon/ADRecon

```powershell
# Run ADRecon
.\ADRecon.ps1

# Specific modules
.\ADRecon.ps1 -Collect Users,Groups,Computers

# Output to specific directory
.\ADRecon.ps1 -OutputDir C:\recon\adrecon

# Generate Excel report
.\ADRecon.ps1 -GenExcel C:\recon\adrecon
```

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
Get-DomainUser -SPN  # Kerberoastable accounts

# Group enumeration
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"

# Computer enumeration
Get-DomainComputer
Get-DomainComputer -OperatingSystem "*Server*"

# Find interesting ACLs
Find-InterestingDomainAcl

# Find local admin access
Find-LocalAdminAccess

# Session hunting
Invoke-UserHunter
Find-DomainUserLocation
```

### SharpHound (BloodHound collector)
**Source**: https://github.com/BloodHoundAD/SharpHound

```powershell
# Run collection
.\SharpHound.exe -c All

# Specific collection methods
.\SharpHound.exe -c DCOnly
.\SharpHound.exe -c Session
.\SharpHound.exe -c Group
.\SharpHound.exe -c LocalAdmin
.\SharpHound.exe -c Trusts

# Stealth mode
.\SharpHound.exe -c All --Stealth

# Output directory
.\SharpHound.exe -c All --OutputDirectory C:\recon\bloodhound
```

### Native AD Commands

```powershell
# Get domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Get domain controllers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Get forest info
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# LDAP queries
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=user)"
$searcher.FindAll()

# Get all users
Get-ADUser -Filter * -Properties *

# Get all computers
Get-ADComputer -Filter * -Properties *

# Get all groups
Get-ADGroup -Filter * -Properties *
```

## Network Information

### PowerShell Network Commands

```powershell
# Network configuration
Get-NetIPConfiguration
Get-NetAdapter
Get-NetRoute

# ARP table
Get-NetNeighbor
arp -a

# DNS cache
Get-DnsClientCache

# Network connections
Get-NetTCPConnection
netstat -ano

# Firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true}
```

### Windows Native Tools

```cmd
# Network info
ipconfig /all
route print
netstat -ano
arp -a

# Network discovery
net view /domain
net view \\$TARGET
net user /domain
net group /domain
net localgroup
net share

# Trust relationships
nltest /domain_trusts
```

## Web Reconnaissance

### PowerShell Web Requests

```powershell
# Basic web request
Invoke-WebRequest -Uri "http://$TARGET" -UseBasicParsing

# Get headers
(Invoke-WebRequest -Uri "http://$TARGET" -UseBasicParsing).Headers

# Follow redirects
Invoke-WebRequest -Uri "http://$TARGET" -MaximumRedirection 5

# Check multiple URLs
$urls = @("http://$TARGET", "http://$TARGET/admin", "http://$TARGET/login")
foreach ($url in $urls) {
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
        Write-Host "$url - $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "$url - Error" -ForegroundColor Red
    }
}
```

### Directory Brute Force (PowerShell)

```powershell
# Simple directory brute force
$wordlist = Get-Content "C:\wordlists\common.txt"
$baseUrl = "http://$TARGET"

foreach ($word in $wordlist) {
    $url = "$baseUrl/$word"
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "FOUND: $url" -ForegroundColor Green
        }
    } catch {
        # 404 or error
    }
}
```

## Certificate Analysis

```powershell
# Get SSL certificate info
$url = "https://$TARGET"
$request = [System.Net.HttpWebRequest]::Create($url)
$request.AllowAutoRedirect = $false
$request.GetResponse() | Out-Null
$cert = $request.ServicePoint.Certificate
$cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)

Write-Host "Subject: $($cert2.Subject)"
Write-Host "Issuer: $($cert2.Issuer)"
Write-Host "Valid From: $($cert2.NotBefore)"
Write-Host "Valid To: $($cert2.NotAfter)"
Write-Host "SANs: $($cert2.DnsNameList)"
```

## Output & Reporting

```powershell
# Create recon directory
New-Item -ItemType Directory -Path "C:\recon" -Force

# Export to JSON
$results | ConvertTo-Json | Out-File "C:\recon\results.json"

# Export to CSV
$results | Export-Csv "C:\recon\results.csv" -NoTypeInformation

# Export to XML
$results | Export-Clixml "C:\recon\results.xml"
```

## Quick Reference

```powershell
# One-liner network scan
1..254 | ForEach-Object { Test-Connection -ComputerName "192.168.1.$_" -Count 1 -ErrorAction SilentlyContinue } | Select-Object Address

# Quick AD enumeration
Get-ADUser -Filter * | Select-Object Name,SamAccountName | Export-Csv users.csv

# Find domain controllers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | Select-Object Name,IPAddress
```
