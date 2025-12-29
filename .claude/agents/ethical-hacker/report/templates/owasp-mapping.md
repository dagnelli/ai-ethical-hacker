# OWASP Mapping Reference

> Quick reference for mapping findings to OWASP categories

---

## OWASP Top 10 2021 (Web Applications)

### A01:2021 - Broken Access Control

**Description**: Failures in access control allow users to act outside their intended permissions.

**Common Vulnerabilities**:
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Privilege escalation
- CORS misconfiguration
- Metadata manipulation (JWT, cookies)

**CWE Mappings**:
- CWE-22: Path Traversal
- CWE-23: Relative Path Traversal
- CWE-35: Path Traversal
- CWE-59: Link Following
- CWE-200: Information Exposure
- CWE-201: Information Exposure Through Sent Data
- CWE-219: Storage of File with Sensitive Data
- CWE-264: Permissions, Privileges, Access Controls
- CWE-275: Permission Issues
- CWE-276: Incorrect Default Permissions
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-352: Cross-Site Request Forgery
- CWE-359: Privacy Violation
- CWE-377: Insecure Temporary File
- CWE-402: Transmission of Private Resources
- CWE-425: Direct Request ('Forced Browsing')
- CWE-441: Unintended Proxy or Intermediary
- CWE-497: Information Exposure Through System Data
- CWE-538: File and Directory Information Exposure
- CWE-540: Information Exposure Through Source Code
- CWE-548: Information Exposure Through Directory Listing
- CWE-552: Files or Directories Accessible to External Parties
- CWE-566: Authorization Bypass Through User-Controlled SQL
- CWE-601: URL Redirection to Untrusted Site
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-651: Information Exposure Through WSDL File
- CWE-668: Exposure of Resource to Wrong Sphere
- CWE-706: Use of Incorrectly-Resolved Name
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-913: Improper Control of Dynamically-Managed Code Resources
- CWE-922: Insecure Storage of Sensitive Information
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute

---

### A02:2021 - Cryptographic Failures

**Description**: Failures related to cryptography which often lead to exposure of sensitive data.

**Common Vulnerabilities**:
- Use of deprecated cryptographic algorithms
- Weak key generation
- Missing encryption for sensitive data
- Improper certificate validation
- Use of hard-coded credentials

**CWE Mappings**:
- CWE-261: Weak Encoding for Password
- CWE-296: Improper Following of Chain of Trust
- CWE-310: Cryptographic Issues
- CWE-319: Cleartext Transmission
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-322: Key Exchange without Entity Authentication
- CWE-323: Reusing a Nonce
- CWE-324: Use of a Key Past its Expiration Date
- CWE-325: Missing Required Cryptographic Step
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of Broken Crypto Algorithm
- CWE-328: Reversible One-Way Hash
- CWE-329: Not Using Random IV with CBC Mode
- CWE-330: Use of Insufficiently Random Values
- CWE-331: Insufficient Entropy
- CWE-335: Incorrect Usage of Seeds in PRNG
- CWE-336: Same Seed in PRNG
- CWE-337: Predictable Seed in PRNG
- CWE-338: Use of Cryptographically Weak PRNG
- CWE-340: Generation of Predictable Numbers
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-523: Unprotected Transport of Credentials
- CWE-720: OWASP Top Ten 2007 A9
- CWE-757: Selection of Less-Secure Algorithm
- CWE-759: Use of One-Way Hash without Salt
- CWE-760: Use of One-Way Hash with Predictable Salt
- CWE-780: Use of RSA Without OAEP
- CWE-818: Insufficient Transport Layer Protection
- CWE-916: Use of Password Hash With Insufficient Effort

---

### A03:2021 - Injection

**Description**: User-supplied data is not validated, filtered, or sanitized by the application.

**Common Vulnerabilities**:
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- XPath Injection
- Expression Language Injection

**CWE Mappings**:
- CWE-20: Improper Input Validation
- CWE-74: Injection
- CWE-75: Failure to Sanitize Data
- CWE-77: Command Injection
- CWE-78: OS Command Injection
- CWE-79: Cross-site Scripting (XSS)
- CWE-80: Improper Neutralization of Script-Related HTML
- CWE-83: Improper Neutralization of Script in Attributes
- CWE-87: Improper Neutralization of Alternate XSS Syntax
- CWE-88: Improper Neutralization of Argument Delimiters
- CWE-89: SQL Injection
- CWE-90: LDAP Injection
- CWE-91: XML Injection
- CWE-93: CRLF Injection
- CWE-94: Code Injection
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
- CWE-96: Improper Neutralization of Directives in Statically Saved Code
- CWE-97: Improper Neutralization of Server-Side Includes
- CWE-98: Improper Control of Filename for Include/Require
- CWE-99: Improper Control of Resource Identifiers
- CWE-100: Deprecated: Technology-Specific Input Validation
- CWE-113: HTTP Response Splitting
- CWE-116: Improper Encoding or Escaping of Output
- CWE-138: Improper Neutralization of Special Elements
- CWE-184: Incomplete List of Disallowed Inputs
- CWE-470: Use of Externally-Controlled Input
- CWE-471: Modification of Assumed-Immutable Data
- CWE-564: SQL Injection: Hibernate
- CWE-610: Externally Controlled Reference
- CWE-643: XPath Injection
- CWE-644: Improper Neutralization of HTTP Headers
- CWE-652: XQuery Injection
- CWE-917: Expression Language Injection

---

### A04:2021 - Insecure Design

**Description**: Risks related to design and architectural flaws.

**Common Vulnerabilities**:
- Missing rate limiting
- Credential recovery vulnerabilities
- Insufficient fraud protection
- Business logic flaws
- Trust boundary violations

**CWE Mappings**:
- CWE-73: External Control of File Name or Path
- CWE-183: Permissive List of Allowed Inputs
- CWE-209: Information Exposure Through Error Message
- CWE-213: Exposure of Sensitive Information
- CWE-235: Improper Handling of Extra Parameters
- CWE-256: Plaintext Storage of a Password
- CWE-257: Storing Passwords in a Recoverable Format
- CWE-266: Incorrect Privilege Assignment
- CWE-269: Improper Privilege Management
- CWE-280: Improper Handling of Insufficient Permissions
- CWE-311: Missing Encryption of Sensitive Data
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-313: Cleartext Storage in a File or on Disk
- CWE-316: Cleartext Storage of Sensitive Information in Memory
- CWE-419: Unprotected Primary Channel
- CWE-430: Deployment of Wrong Handler
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-444: Inconsistent Interpretation of HTTP Requests
- CWE-451: User Interface (UI) Misrepresentation
- CWE-472: External Control of Assumed-Immutable Web Parameter
- CWE-501: Trust Boundary Violation
- CWE-522: Insufficiently Protected Credentials
- CWE-525: Use of Web Browser Cache
- CWE-539: Use of Persistent Cookies
- CWE-579: J2EE Bad Practices: Non-serializable Object
- CWE-598: Use of GET Request Method With Sensitive Query Strings
- CWE-602: Client-Side Enforcement of Server-Side Security
- CWE-642: External Control of Critical State Data
- CWE-646: Reliance on File Name or Extension
- CWE-650: Trusting HTTP Permission Methods on Server Side
- CWE-653: Insufficient Compartmentalization
- CWE-656: Reliance on Security Through Obscurity
- CWE-657: Violation of Secure Design Principles
- CWE-799: Improper Control of Interaction Frequency
- CWE-807: Reliance on Untrusted Inputs
- CWE-840: Business Logic Errors
- CWE-841: Improper Enforcement of Behavioral Workflow
- CWE-927: Use of Implicit Intent
- CWE-1021: Improper Restriction of Rendered UI
- CWE-1173: Improper Use of Validation Framework

---

### A05:2021 - Security Misconfiguration

**Description**: Missing appropriate security hardening or misconfigured permissions.

**Common Vulnerabilities**:
- Default credentials
- Unnecessary features enabled
- Missing security headers
- Verbose error messages
- Outdated software

**CWE Mappings**:
- CWE-2: 7PK - Environment
- CWE-11: ASP.NET Misconfiguration
- CWE-13: ASP.NET Misconfiguration
- CWE-15: External Control of System or Configuration Setting
- CWE-16: Configuration
- CWE-260: Password in Configuration File
- CWE-315: Cleartext Storage of Sensitive Information in Cookie
- CWE-520: .NET Misconfiguration: Use of Impersonation
- CWE-526: Sensitive Information in Environment Variables
- CWE-537: Java Runtime Error Message
- CWE-541: Inclusion of Sensitive Information in Include File
- CWE-547: Use of Hard-coded, Security-relevant Constants
- CWE-611: Improper Restriction of XML External Entity Reference
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-756: Missing Custom Error Page
- CWE-776: Improper Restriction of Recursive Entity References
- CWE-942: Permissive Cross-domain Policy
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-1032: OWASP Top Ten 2017 A6
- CWE-1174: ASP.NET Misconfiguration

---

### A06:2021 - Vulnerable and Outdated Components

**Description**: Using components with known vulnerabilities.

**CWE Mappings**:
- CWE-937: OWASP Top 10 2013 A9
- CWE-1035: 2017 Top 10 A9
- CWE-1104: Use of Unmaintained Third Party Components

---

### A07:2021 - Identification and Authentication Failures

**Description**: Confirmation of user identity, authentication, and session management failures.

**Common Vulnerabilities**:
- Credential stuffing
- Weak passwords allowed
- Ineffective MFA
- Session fixation
- Improper session invalidation

**CWE Mappings**:
- CWE-255: Credentials Management Errors
- CWE-259: Use of Hard-coded Password
- CWE-287: Improper Authentication
- CWE-288: Authentication Bypass Using Alternate Path
- CWE-290: Authentication Bypass by Spoofing
- CWE-294: Authentication Bypass by Capture-replay
- CWE-295: Improper Certificate Validation
- CWE-297: Improper Validation of Certificate with Host Mismatch
- CWE-300: Channel Accessible by Non-Endpoint
- CWE-302: Authentication Bypass by Assumed-Immutable Data
- CWE-304: Missing Critical Step in Authentication
- CWE-306: Missing Authentication for Critical Function
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-346: Origin Validation Error
- CWE-384: Session Fixation
- CWE-521: Weak Password Requirements
- CWE-613: Insufficient Session Expiration
- CWE-620: Unverified Password Change
- CWE-640: Weak Password Recovery Mechanism
- CWE-798: Use of Hard-coded Credentials
- CWE-940: Improper Verification of Source of Communication Channel
- CWE-1216: Lockout Mechanism Errors

---

### A08:2021 - Software and Data Integrity Failures

**Description**: Failures related to code and infrastructure that does not protect against integrity violations.

**Common Vulnerabilities**:
- Insecure deserialization
- CI/CD pipeline compromise
- Unsigned software updates
- Insecure auto-update

**CWE Mappings**:
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-353: Missing Support for Integrity Check
- CWE-426: Untrusted Search Path
- CWE-494: Download of Code Without Integrity Check
- CWE-502: Deserialization of Untrusted Data
- CWE-565: Reliance on Cookies without Validation and Integrity
- CWE-784: Reliance on Cookies without Validation in Security Decision
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-830: Inclusion of Web Functionality from Untrusted Source
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

---

### A09:2021 - Security Logging and Monitoring Failures

**Description**: Insufficient logging, detection, monitoring, and active response.

**CWE Mappings**:
- CWE-117: Improper Output Neutralization for Logs
- CWE-223: Omission of Security-relevant Information
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-778: Insufficient Logging

---

### A10:2021 - Server-Side Request Forgery (SSRF)

**Description**: Web application fetches a remote resource without validating the user-supplied URL.

**CWE Mappings**:
- CWE-918: Server-Side Request Forgery (SSRF)

---

## OWASP API Security Top 10 2023

| ID | Name | Description |
|----|------|-------------|
| API1:2023 | Broken Object Level Authorization | Manipulating object IDs to access other users' data |
| API2:2023 | Broken Authentication | Flaws in authentication mechanisms |
| API3:2023 | Broken Object Property Level Authorization | Exposing or allowing modification of object properties |
| API4:2023 | Unrestricted Resource Consumption | No rate limiting or resource quotas |
| API5:2023 | Broken Function Level Authorization | Access to admin functions by regular users |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Abuse of legitimate business functionality |
| API7:2023 | Server Side Request Forgery | SSRF through API endpoints |
| API8:2023 | Security Misconfiguration | Insecure default configurations |
| API9:2023 | Improper Inventory Management | Outdated or undocumented API endpoints |
| API10:2023 | Unsafe Consumption of APIs | Trusting data from third-party APIs |

---

## OWASP LLM Top 10 2025

| ID | Name | Description |
|----|------|-------------|
| LLM01:2025 | Prompt Injection | Manipulating LLM through crafted inputs |
| LLM02:2025 | Sensitive Information Disclosure | Leaking training data or sensitive info |
| LLM03:2025 | Supply Chain | Compromised model dependencies |
| LLM04:2025 | Data and Model Poisoning | Training data manipulation |
| LLM05:2025 | Insecure Output Handling | Unsafe use of LLM outputs |
| LLM06:2025 | Excessive Agency | LLM taking unauthorized actions |
| LLM07:2025 | System Prompt Leakage | Exposing system prompts |
| LLM08:2025 | Vector and Embedding Weaknesses | RAG pipeline vulnerabilities |
| LLM09:2025 | Misinformation | Generating false/harmful content |
| LLM10:2025 | Unbounded Consumption | Resource exhaustion attacks |

---

## Quick Lookup Table

| Vulnerability | OWASP Web | OWASP API | CWE |
|--------------|-----------|-----------|-----|
| SQL Injection | A03 | - | CWE-89 |
| XSS | A03 | - | CWE-79 |
| CSRF | A01 | - | CWE-352 |
| IDOR | A01 | API1 | CWE-639 |
| Authentication Bypass | A07 | API2 | CWE-287 |
| Privilege Escalation | A01 | API5 | CWE-269 |
| SSRF | A10 | API7 | CWE-918 |
| Deserialization | A08 | - | CWE-502 |
| XXE | A05 | - | CWE-611 |
| Path Traversal | A01 | - | CWE-22 |
