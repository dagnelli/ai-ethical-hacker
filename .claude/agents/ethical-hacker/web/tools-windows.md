# SPIDER Tools Reference — Windows/FLARE-VM

> *"Every platform. Every tool. No limitations."*

## Web Proxy Tools

### OWASP ZAP (Portable)
**Source**: https://www.zaproxy.org/

```powershell
# Start ZAP
& "C:\Tools\ZAP\zap.bat"

# ZAP workflow:
# 1. Configure browser to use proxy 127.0.0.1:8080
# 2. Manual exploration or automated spider
# 3. Active scan
# 4. Review alerts
# 5. Generate report
```

### Fiddler
**Source**: https://www.telerik.com/fiddler

```powershell
# Start Fiddler
& "C:\Program Files\Fiddler\Fiddler.exe"

# Fiddler workflow:
# 1. Capture traffic
# 2. Analyze requests/responses
# 3. Modify and replay
# 4. Test for vulnerabilities
```

### Burp Suite
```powershell
# Start Burp Suite
& "C:\Tools\Burp\burpsuite.jar"

# Or via Java
java -jar "C:\Tools\Burp\burpsuite_community.jar"
```

## PowerShell Web Testing

### HTTP Request Functions

```powershell
# Basic GET request
function Test-WebRequest {
    param([string]$Url)
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
        return @{
            StatusCode = $response.StatusCode
            Headers = $response.Headers
            Content = $response.Content.Substring(0, [Math]::Min(500, $response.Content.Length))
        }
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

# POST request with data
function Test-WebPost {
    param(
        [string]$Url,
        [hashtable]$Data
    )
    try {
        $response = Invoke-WebRequest -Uri $Url -Method POST -Body $Data -UseBasicParsing
        return @{
            StatusCode = $response.StatusCode
            Content = $response.Content
        }
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

# Test for SQL injection (basic)
function Test-SqlInjection {
    param([string]$Url)
    $payloads = @("'", "''", "1 OR 1=1", "1' OR '1'='1", "1' AND '1'='2")
    foreach ($payload in $payloads) {
        $testUrl = $Url + [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Test-WebRequest -Url $testUrl
        Write-Host "Payload: $payload - Status: $($response.StatusCode)"
    }
}

# Test for XSS (basic)
function Test-Xss {
    param([string]$Url)
    $payloads = @(
        "<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    )
    foreach ($payload in $payloads) {
        $testUrl = $Url + [System.Web.HttpUtility]::UrlEncode($payload)
        $response = Test-WebRequest -Url $testUrl
        if ($response.Content -match [regex]::Escape($payload)) {
            Write-Host "POTENTIAL XSS: $payload" -ForegroundColor Red
        }
    }
}
```

### Directory Brute Force

```powershell
# Directory enumeration
function Find-WebDirectories {
    param(
        [string]$BaseUrl,
        [string]$WordlistPath = "C:\Wordlists\common.txt"
    )

    $wordlist = Get-Content $WordlistPath
    $found = @()

    foreach ($word in $wordlist) {
        $url = "$BaseUrl/$word"
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Host "FOUND: $url [$($response.StatusCode)]" -ForegroundColor Green
                $found += $url
            }
        } catch {
            # 404 or error - continue
        }
    }
    return $found
}

# Extension fuzzing
function Find-WebFiles {
    param(
        [string]$BaseUrl,
        [string]$WordlistPath,
        [string[]]$Extensions = @(".php", ".html", ".txt", ".bak", ".old")
    )

    $wordlist = Get-Content $WordlistPath

    foreach ($word in $wordlist) {
        foreach ($ext in $Extensions) {
            $url = "$BaseUrl/$word$ext"
            try {
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    Write-Host "FOUND: $url" -ForegroundColor Green
                }
            } catch {}
        }
    }
}
```

### Header Analysis

```powershell
# Security headers check
function Test-SecurityHeaders {
    param([string]$Url)

    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
    $headers = $response.Headers

    $securityHeaders = @(
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy"
    )

    Write-Host "=== Security Headers Check: $Url ===" -ForegroundColor Cyan
    foreach ($header in $securityHeaders) {
        if ($headers.ContainsKey($header)) {
            Write-Host "[+] $header : $($headers[$header])" -ForegroundColor Green
        } else {
            Write-Host "[-] $header : MISSING" -ForegroundColor Red
        }
    }
}

# Information disclosure headers
function Get-ServerInfo {
    param([string]$Url)

    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
    $headers = $response.Headers

    $infoHeaders = @("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")

    Write-Host "=== Server Information ===" -ForegroundColor Cyan
    foreach ($header in $infoHeaders) {
        if ($headers.ContainsKey($header)) {
            Write-Host "$header : $($headers[$header])" -ForegroundColor Yellow
        }
    }
}
```

### Cookie Analysis

```powershell
# Cookie security check
function Test-CookieSecurity {
    param([string]$Url)

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    Invoke-WebRequest -Uri $Url -WebSession $session -UseBasicParsing | Out-Null

    Write-Host "=== Cookie Analysis ===" -ForegroundColor Cyan
    foreach ($cookie in $session.Cookies.GetCookies($Url)) {
        Write-Host "Cookie: $($cookie.Name)" -ForegroundColor Yellow
        Write-Host "  Secure: $($cookie.Secure)"
        Write-Host "  HttpOnly: $($cookie.HttpOnly)"
        Write-Host "  Expires: $($cookie.Expires)"
        Write-Host ""
    }
}
```

### Form Analysis

```powershell
# Extract forms from page
function Get-WebForms {
    param([string]$Url)

    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing

    # Parse HTML for forms
    $html = $response.Content
    $formPattern = '<form[^>]*>(.*?)</form>'
    $inputPattern = '<input[^>]*>'

    $forms = [regex]::Matches($html, $formPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    Write-Host "=== Forms Found ===" -ForegroundColor Cyan
    $formIndex = 0
    foreach ($form in $forms) {
        Write-Host "Form $formIndex :" -ForegroundColor Yellow
        $inputs = [regex]::Matches($form.Value, $inputPattern)
        foreach ($input in $inputs) {
            Write-Host "  $($input.Value)"
        }
        $formIndex++
    }
}
```

## Wordlists

### Download/Setup Wordlists

```powershell
# Create wordlist directory
New-Item -ItemType Directory -Path "C:\Wordlists" -Force

# Download SecLists
git clone https://github.com/danielmiessler/SecLists.git C:\Wordlists\SecLists

# Common paths
$WordlistPaths = @{
    Common = "C:\Wordlists\SecLists\Discovery\Web-Content\common.txt"
    Directory = "C:\Wordlists\SecLists\Discovery\Web-Content\directory-list-2.3-medium.txt"
    Parameters = "C:\Wordlists\SecLists\Discovery\Web-Content\burp-parameter-names.txt"
    Passwords = "C:\Wordlists\SecLists\Passwords\Common-Credentials\10-million-password-list-top-10000.txt"
}
```

## Automated Testing Scripts

### Full Web Scan

```powershell
function Start-WebScan {
    param(
        [string]$Url,
        [string]$OutputDir = "C:\WebScan"
    )

    # Create output directory
    New-Item -ItemType Directory -Path $OutputDir -Force

    Write-Host "=== Starting Web Scan: $Url ===" -ForegroundColor Cyan

    # 1. Basic info
    Write-Host "[*] Gathering server information..." -ForegroundColor Yellow
    Get-ServerInfo -Url $Url | Out-File "$OutputDir\server-info.txt"

    # 2. Security headers
    Write-Host "[*] Checking security headers..." -ForegroundColor Yellow
    Test-SecurityHeaders -Url $Url | Out-File "$OutputDir\security-headers.txt"

    # 3. Cookie analysis
    Write-Host "[*] Analyzing cookies..." -ForegroundColor Yellow
    Test-CookieSecurity -Url $Url | Out-File "$OutputDir\cookies.txt"

    # 4. Directory enumeration
    Write-Host "[*] Enumerating directories..." -ForegroundColor Yellow
    $dirs = Find-WebDirectories -BaseUrl $Url
    $dirs | Out-File "$OutputDir\directories.txt"

    # 5. Form analysis
    Write-Host "[*] Analyzing forms..." -ForegroundColor Yellow
    Get-WebForms -Url $Url | Out-File "$OutputDir\forms.txt"

    Write-Host "=== Scan Complete ===" -ForegroundColor Green
    Write-Host "Results saved to: $OutputDir"
}
```

## CURL for Windows

```powershell
# Using curl (available in Windows 10+)
# Basic request
curl.exe http://$TARGET -o response.txt

# With headers
curl.exe -I http://$TARGET

# POST request
curl.exe -X POST http://$TARGET/login -d "user=admin&pass=test"

# With cookies
curl.exe -b "session=xxx" http://$TARGET/admin

# Follow redirects
curl.exe -L http://$TARGET

# Verbose
curl.exe -v http://$TARGET
```

## Output and Reporting

```powershell
# Export results to JSON
$results | ConvertTo-Json -Depth 10 | Out-File "results.json"

# Export to HTML report
function Export-WebScanReport {
    param(
        [hashtable]$Results,
        [string]$OutputPath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head><title>Web Scan Report</title></head>
<body>
<h1>Web Security Scan Report</h1>
<h2>Target: $($Results.Target)</h2>
<h2>Date: $(Get-Date)</h2>
<h3>Findings</h3>
<pre>$($Results | ConvertTo-Json -Depth 5)</pre>
</body>
</html>
"@

    $html | Out-File $OutputPath
}
```

## Quick Reference

```powershell
# Quick security check
Test-SecurityHeaders -Url "http://$TARGET"
Get-ServerInfo -Url "http://$TARGET"

# Quick directory scan
Find-WebDirectories -BaseUrl "http://$TARGET" -WordlistPath "C:\Wordlists\common.txt"

# Quick form analysis
Get-WebForms -Url "http://$TARGET/login"
```
