# 🛰️ Nmap-NSE-Script-Collection

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Language-Lua%20100%25-blue.svg" alt="Language: Lua">
  <img src="https://img.shields.io/badge/Nmap-7.40%2B-informational.svg" alt="Nmap 7.40+">
  <img src="https://img.shields.io/badge/Scripts-55-orange.svg" alt="55 Scripts">
  <img src="https://img.shields.io/badge/Security%20Checks-198%2B-critical.svg" alt="198+ Security Checks">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/Maintained%3F-yes-success.svg" alt="Maintained">
</p>

## 📖 Project Overview

A comprehensive collection of custom **Nmap NSE (Nmap Scripting Engine)** scripts specialized in **defensive security auditing** of web servers, DNS infrastructure, SMB/Windows services, SSL/TLS endpoints, database services, and FTP servers. These scripts are engineered to detect common security misconfigurations, including missing critical HTTP security headers, inadequate cookie protection flags, weak cryptographic algorithms, DNS vulnerabilities, SMB misconfigurations, unauthenticated database access, and insecure FTP configurations, among other prevalent security issues frequently overlooked in production environments.

**💻 Project Language:** Lua 100%

---

## 🗂️ Table of Contents

- [📋 Project Contents & Statistics](#-project-contents--statistics)
- [🚀 Installation](#-installation)
- [🌐 HTTP Security Audits](#-http-security-audits)
- [🔍 DNS Security Audits](#-dns-security-audits)
- [🔐 SMB Protocol Security Audits](#-smb-protocol-security-audits)
- [🛡️ SSL/TLS Protocol Security Audits](#️-ssltls-protocol-security-audits)
- [🗄️ Database Security Audits](#️-database-security-audits)
- [📁 FTP Security Audits](#-ftp-security-audits)
- [🎯 Comprehensive Scanning Scenarios](#-comprehensive-scanning-scenarios)
- [📊 Script Reference Summary Table](#-script-reference-summary-table)
- [🔍 Risk Level Guide](#-risk-level-guide)
- [🛠️ Advanced Usage & Customization](#️-advanced-usage--customization)
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🤝 Contributing](#-contributing)
- [🔒 Security Policy](#-security-policy)
- [📝 Changelog](#-changelog)
- [📞 Support & Documentation](#-support--documentation)
- [📄 License](#-license)

---

## 📋 Project Contents & Statistics

### 📁 Directory Structure

```
Nmap-NSE-Script-Collection/
├── HTTP/                    # HTTP Protocol Security Audits (10 scripts)
├── DNS/                     # DNS Infrastructure Security Audits (9 scripts)
├── SMB/                     # SMB/Windows Protocol Security Audits (9 scripts)
├── SSL-TLS/                 # SSL/TLS Protocol Security Audits (9 scripts)
├── DATABASE/                # Database Service Security Audits (9 scripts)
├── FTP/                     # FTP Protocol Security Audits (9 scripts)
└── README.md                # This file
```

### 📊 Statistics
- **Total Scripts:** 55
- **HTTP Scripts:** 10
- **DNS Scripts:** 9
- **SMB Scripts:** 9
- **SSL/TLS Scripts:** 9
- **Database Scripts:** 9
- **FTP Scripts:** 9
- **Total Lines of Code:** 6,967 Lua
- **Security Checks:** 198+

---

## 🚀 Installation

### Prerequisites

- **Nmap** v7.40 or newer
- **Lua** runtime (included with Nmap)
- **Network access** to target systems
- Administrative/root privileges (optional, for system-wide installation)

### Installation Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cd Nmap-NSE-Script-Collection
```

#### 2. Locate Your Nmap NSE Scripts Directory

**Linux/macOS:**
```bash
~/.nmap/scripts
/usr/share/nmap/scripts (system-wide)
```

**Windows:**
```
C:\Program Files\Nmap\scripts
```

#### 3. Install Scripts

**Linux/macOS (Recommended - Symlinks):**
```bash
ln -s $(pwd)/HTTP ~/.nmap/scripts/custom-http
ln -s $(pwd)/DNS ~/.nmap/scripts/custom-dns
ln -s $(pwd)/SMB ~/.nmap/scripts/custom-smb
ln -s $(pwd)/SSL-TLS ~/.nmap/scripts/custom-ssl-tls
ln -s $(pwd)/DATABASE ~/.nmap/scripts/custom-database
ln -s $(pwd)/FTP ~/.nmap/scripts/custom-ftp
```

**Linux/macOS (Direct Copy):**
```bash
cp -r HTTP/* DNS/* SMB/* SSL-TLS/* DATABASE/* FTP/* ~/.nmap/scripts/
chmod +x ~/.nmap/scripts/*.nse
```

**Windows PowerShell (Admin):**
```powershell
Copy-Item -Path "HTTP\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "DNS\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "SMB\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "SSL-TLS\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "DATABASE\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "FTP\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
```

#### 4. Update NSE Database

```bash
nmap --script-updatedb
```

#### 5. Verify Installation

```bash
nmap --script-help http-security-headers
nmap --script-help dns-zone-transfer-check
nmap --script-help smb-null-session-check
nmap --script-help ssl-weak-ciphers
nmap --script-help mysql-empty-password-check
nmap --script-help ftp-anonymous-login
```

---

## 🌐 HTTP Security Audits

### Category Overview
HTTP protocol security audits focusing on web server misconfigurations, header validation, and protocol vulnerabilities.

**Port:** 80/443 | **Protocol:** HTTP/HTTPS

---

### HTTP Scripts List

#### 1. **http-security-headers** - HTTP Security Headers Audit
**Description:** Audits HTTP security headers across multiple application paths for presence and quality.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- CORS headers

**How to Execute:**
```bash
# Basic scan
nmap -p 80,443 --script http-security-headers example.com

# Verbose output
nmap -p 80,443 --script http-security-headers -v example.com

# Multiple targets
nmap -p 80,443 --script http-security-headers 192.168.1.0/24
```

**Sample Output:**
```
| http-security-headers:
|   Headers missing: Strict-Transport-Security, Content-Security-Policy
|   Headers present: X-Frame-Options: DENY
|   Weak configurations: HSTS max-age below recommended
```

---

#### 2. **http-cookie-flags** - Cookie Security Audit
**Description:** Analyzes Set-Cookie headers for protective flags and secure configuration.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Secure flag (HTTPS-only)
- HttpOnly flag (XSS protection)
- SameSite attribute (CSRF protection)
- Domain scope
- Expiry settings

**How to Execute:**
```bash
# Basic scan
nmap -p 80,443 --script http-cookie-flags example.com

# Very verbose
nmap -p 80,443 --script http-cookie-flags -vv example.com

# Custom paths
nmap -p 80,443 --script http-cookie-flags --script-args paths={"/admin","/api"} example.com
```

**Sample Output:**
```
| http-cookie-flags:
|   Flagged cookies:
|     - PHPSESSID: missing Secure flag; missing HttpOnly flag
|   Cookies with adequate flags:
|     - _ga: Secure=true HttpOnly=true SameSite=Strict
```

---

#### 3. **http-cors-config** - CORS Configuration Analysis
**Description:** Evaluates CORS policies for overly permissive configurations.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Wildcard origin (*) allowance
- Credential leakage
- Method restrictions
- Header restrictions

**How to Execute:**
```bash
nmap -p 80,443 --script http-cors-config example.com
nmap -p 80,443 --script http-cors-config -v example.com
```

**Sample Output:**
```
| http-cors-config:
|   Access-Control-Allow-Origin: * (wildcard)
|   Access-Control-Allow-Credentials: true
|   Status: MISCONFIGURED - wildcard origin combined with credentials
```

---

#### 4. **http-cache-audit** - HTTP Caching Strategy
**Description:** Analyzes cache control headers and caching behavior for sensitive data leakage.

**Risk Level:** 🟢 LOW | **Category:** Defensive

**What it checks:**
- Cache-Control directives
- Expires headers
- ETag usage
- Sensitive data caching

**How to Execute:**
```bash
nmap -p 80,443 --script http-cache-audit example.com

# Verbose output
nmap -p 80,443 --script http-cache-audit -v example.com
```

**Sample Output:**
```
| http-cache-audit:
|   Cache-Control: no-store directive missing
|   Expires header: not set
|   Sensitive path cached: /account/profile
```

---

#### 5. **http-error-disclosure** - Information Disclosure Detection
**Description:** Discovers sensitive information exposed through error messages and exception handling.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Stack traces
- Database error messages
- Path disclosure
- Configuration details

**How to Execute:**
```bash
nmap -p 80,443 --script http-error-disclosure example.com
nmap -p 80,443 --script http-error-disclosure -v example.com
```

**Sample Output:**
```
| http-error-disclosure:
|   Stack trace exposed: /api/users (HTTP 500)
|   Path disclosed: /var/www/app/controllers/
|   Database error revealed: MySQL syntax error
```

---

#### 6. **http-methods-enum** - HTTP Methods Enumeration
**Description:** Identifies enabled HTTP methods and flags potentially dangerous ones.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- PUT method (file modification)
- DELETE method (resource deletion)
- CONNECT method (proxy tunneling)
- TRACE method (XST vulnerability)
- Custom methods

**How to Execute:**
```bash
nmap -p 80,443 --script http-methods-enum example.com

# Verbose output
nmap -p 80,443 --script http-methods-enum -v example.com
```

**Sample Output:**
```
| http-methods-enum:
|   Allowed methods: GET, POST, PUT, DELETE, TRACE
|   Dangerous methods enabled: PUT, DELETE, TRACE
```

---

#### 7. **http-server-fingerprint** - Web Server Detection
**Description:** Identifies web server technology, version, and associated information disclosure risks.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Server software identification
- Version extraction
- Framework detection
- Information leakage

**How to Execute:**
```bash
nmap -p 80,443 --script http-server-fingerprint example.com

# Verbose output
nmap -p 80,443 --script http-server-fingerprint -v example.com
```

**Sample Output:**
```
| http-server-fingerprint:
|   Server: Apache/2.4.41 (Ubuntu)
|   Framework detected: PHP/7.4.3
|   Risk: Version disclosure aids targeted exploitation
```

---

#### 8. **http-dir-listing** - Directory Listing Detection
**Description:** Identifies accessible directories with enabled listing (index generation).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Directory browsing enabled
- Accessible paths
- File enumeration

**How to Execute:**
```bash
nmap -p 80,443 --script http-dir-listing example.com

# Verbose output
nmap -p 80,443 --script http-dir-listing -v example.com
```

**Sample Output:**
```
| http-dir-listing:
|   Directory listing ENABLED: /uploads/, /backup/
|   Files exposed: config.php.bak, database.sql
```

---

#### 9. **http-robots-sitemap** - robots.txt & Sitemap Analysis
**Description:** Extracts information from robots.txt and sitemap.xml files.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Disallowed paths
- Crawl delay directives
- Sitemap URLs
- Sensitive endpoint disclosure

**How to Execute:**
```bash
nmap -p 80,443 --script http-robots-sitemap example.com

# Verbose output
nmap -p 80,443 --script http-robots-sitemap -v example.com
```

**Sample Output:**
```
| http-robots-sitemap:
|   Disallowed paths: /admin/, /internal-api/
|   Sitemap: /sitemap.xml (42 URLs)
|   Sensitive path disclosed: /admin/
```

---

#### 10. **http-trace-method** - HTTP TRACE Method Vulnerability
**Description:** Detects and validates the HTTP TRACE method (XST vulnerability).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- TRACE method enablement
- XST vulnerability presence

**How to Execute:**
```bash
nmap -p 80,443 --script http-trace-method example.com
nmap -p 80,443 --script http-trace-method -v example.com
```

**Sample Output:**
```
| http-trace-method:
|   TRACE method: ENABLED
|   XST vulnerability: CONFIRMED
|   Risk: High - cross-site tracing enables cookie theft
```

---

## 🔍 DNS Security Audits

### Category Overview
DNS infrastructure security audits focusing on zone configuration, DNS poisoning risks, and information disclosure.

**Port:** 53 | **Protocol:** DNS (UDP/TCP)

---

### DNS Scripts List

#### 1. **dns-zone-transfer-check** - Zone Transfer Vulnerability (AXFR)
**Description:** Attempts full zone transfer to detect misconfigured DNS servers allowing unauthenticated transfers.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Unauthenticated AXFR requests
- Zone data exposure
- Record types enumeration

**How to Execute:**
```bash
# Specify target domain
nmap -p 53 --script dns-zone-transfer-check \
  --script-args dns-zone-transfer-check.domain=example.com \
  <DNS_SERVER_IP>

# Example
nmap -p 53 --script dns-zone-transfer-check \
  --script-args dns-zone-transfer-check.domain=example.com \
  8.8.8.8
```

**Sample Output:**
```
| dns-zone-transfer-check:
|   Domain: example.com
|   Result: ZONE TRANSFER SUCCEEDED - 247 records returned
|   Record types: A: 50, MX: 5, NS: 4, CNAME: 15
```

---

#### 2. **dns-subdomain-enum** - Subdomain Enumeration
**Description:** Brute forces common subdomain labels to discover subdomains and IP addresses.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- 50+ common subdomains (www, mail, api, dev, admin, etc.)
- A record resolution
- IP address mapping

**How to Execute:**
```bash
# Specify domain
nmap -p 53 --script dns-subdomain-enum \
  --script-args dns-subdomain-enum.domain=example.com \
  <DNS_SERVER_IP>

# Public DNS server
nmap -p 53 --script dns-subdomain-enum \
  --script-args dns-subdomain-enum.domain=example.com \
  8.8.8.8
```

**Sample Output:**
```
| dns-subdomain-enum:
|   Domain: example.com
|   Resolved subdomains:
|     - www.example.com -> 93.184.216.34
|     - mail.example.com -> 93.184.216.35
|     - api.example.com -> 93.184.216.36
```

---

#### 3. **dns-recursion-check** - Open Resolver Detection
**Description:** Detects if DNS server allows recursive queries for external domains (open resolver).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Recursion availability
- External domain resolution
- Open resolver exploitation risk

**How to Execute:**
```bash
# Check if open resolver
nmap -p 53 --script dns-recursion-check <DNS_SERVER_IP>

# Example
nmap -p 53 --script dns-recursion-check 192.168.1.1
nmap -p 53 --script dns-recursion-check 8.8.8.8
```

**Sample Output:**
```
| dns-recursion-check:
|   Status: LIKELY OPEN RESOLVER
|   Evidence:
|     - www.iana.org -> RA=1, rcode=0 (resolved externally)
|     - a.root-servers.net -> RA=1, rcode=0
```

---

#### 4. **dns-amplification-risk** - DNS Amplification Attack Risk
**Description:** Evaluates potential for DNS server abuse in amplification attacks.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Response size amplification
- Amplification factor
- Attack potential

**How to Execute:**
```bash
nmap -p 53 --script dns-amplification-risk <DNS_SERVER_IP>
nmap -p 53 --script dns-amplification-risk -v 192.168.1.1
```

**Sample Output:**
```
| dns-amplification-risk:
|   Query size: 60 bytes -> Response size: 3200 bytes
|   Amplification factor: 53x
|   Risk: HIGH - suitable for DDoS reflection attacks
```

---

#### 5. **dns-cache-snooping** - DNS Cache Snooping Detection
**Description:** Detects if DNS server allows cache snooping queries for information leakage.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Cache snooping ability
- Previously cached queries
- Information disclosure

**How to Execute:**
```bash
nmap -p 53 --script dns-cache-snooping <DNS_SERVER_IP>

# Verbose output
nmap -p 53 --script dns-cache-snooping -v 8.8.8.8
```

**Sample Output:**
```
| dns-cache-snooping:
|   Cached queries detected: www.example.com, mail.example.com
|   Method: non-recursive query (TTL inspection)
|   Status: VULNERABLE - cache contents inferable
```

---

#### 6. **dns-srv-enum** - SRV Record Enumeration
**Description:** Enumerates SRV records for identifying services (Kerberos, LDAP, SIP, etc.).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- _kerberos._tcp/udp records
- _ldap._tcp records
- _sip._tcp/udp records
- Service discovery

**How to Execute:**
```bash
# Enumerate SRV records
nmap -p 53 --script dns-srv-enum \
  --script-args dns-srv-enum.domain=example.com \
  <DNS_SERVER_IP>

# Verbose output
nmap -p 53 --script dns-srv-enum \
  --script-args dns-srv-enum.domain=example.com \
  -v 8.8.8.8
```

**Sample Output:**
```
| dns-srv-enum:
|   Domain: example.com
|   SRV Records:
|     - _kerberos._tcp: kdc1.example.com:88
|     - _ldap._tcp: ldap1.example.com:389
```

---

#### 7. **dns-txt-spf-dmarc-audit** - Email Security Records Audit
**Description:** Analyzes SPF, DMARC, and TXT records for email security configuration.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- SPF record validity
- DMARC policy configuration
- DKIM setup
- Domain verification records

**How to Execute:**
```bash
nmap -p 53 --script dns-txt-spf-dmarc-audit \
  --script-args dns-txt-spf-dmarc-audit.domain=example.com \
  <DNS_SERVER_IP>
```

**Sample Output:**
```
| dns-txt-spf-dmarc-audit:
|   Domain: example.com
|   SPF: v=spf1 include:sendgrid.net ~all
|   DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
|   Status: SECURE
```

---

#### 8. **dns-soa-consistency-check** - SOA Record Consistency
**Description:** Validates SOA record consistency across authoritative nameservers.

**Risk Level:** 🟢 LOW | **Category:** Defensive

**What it checks:**
- SOA consistency
- Serial number matching
- Nameserver agreement

**How to Execute:**
```bash
nmap -p 53 --script dns-soa-consistency-check \
  --script-args dns-soa-consistency-check.domain=example.com \
  <DNS_SERVER_IP>

# Verbose output
nmap -p 53 --script dns-soa-consistency-check \
  --script-args dns-soa-consistency-check.domain=example.com \
  -v 8.8.8.8
```

**Sample Output:**
```
| dns-soa-consistency-check:
|   ns1.example.com: Serial 2026070101
|   ns2.example.com: Serial 2026070101
|   Status: CONSISTENT
```

---

#### 9. **dns-wildcard-detector** - Wildcard DNS Record Detection
**Description:** Detects if domain uses wildcard DNS records.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Wildcard record presence
- Catch-all behavior

**How to Execute:**
```bash
nmap -p 53 --script dns-wildcard-detector \
  --script-args dns-wildcard-detector.domain=example.com \
  <DNS_SERVER_IP>

# Verbose output
nmap -p 53 --script dns-wildcard-detector \
  --script-args dns-wildcard-detector.domain=example.com \
  -v 8.8.8.8
```

**Sample Output:**
```
| dns-wildcard-detector:
|   Query: random-xyz123.example.com -> 93.184.216.34
|   Status: WILDCARD DETECTED
|   Impact: subdomain enumeration results may be unreliable
```

---

## 🔐 SMB Protocol Security Audits

### Category Overview
SMB/Windows protocol security audits focusing on file sharing configuration, authentication, and information disclosure.

**Port:** 139/445 | **Protocol:** SMB (NetBIOS/Direct Hosting)

---

### SMB Scripts List

#### 1. **smb-null-session-check** - Null Session Vulnerability
**Description:** Detects if SMB server allows null session connections (anonymous access).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Null session connectivity
- Anonymous SMB access
- NULL share enumeration

**How to Execute:**
```bash
# Basic check
nmap -p 139,445 --script smb-null-session-check <TARGET>

# Verbose
nmap -p 139,445 --script smb-null-session-check -v example.com

# Specific port
nmap -p 445 --script smb-null-session-check example.com
```

**Sample Output:**
```
| smb-null-session-check:
|   Status: VULNERABLE
|   Message: Null session allowed on SMB server
|   Risk: High - Anonymous access enabled
```

---

#### 2. **smb-guest-access-check** - Guest Account Access
**Description:** Checks if SMB server allows guest account access without credentials.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Guest account enablement
- Anonymous share access
- Unauthenticated listing

**How to Execute:**
```bash
nmap -p 139,445 --script smb-guest-access-check <TARGET>
nmap -p 139,445 --script smb-guest-access-check -v example.com
```

**Sample Output:**
```
| smb-guest-access-check:
|   Status: ENABLED
|   Message: Guest access is permitted
|   Accessible shares: ADMIN$, C$, IPC$
```

---

#### 3. **smb-security-level** - SMB Security Configuration
**Description:** Audits SMB security level and authentication configuration.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Security level setting (user/domain/server)
- Encryption requirements
- Authentication protocols
- Password policy

**How to Execute:**
```bash
nmap -p 139,445 --script smb-security-level <TARGET>
nmap -p 445 --script smb-security-level -v example.com
```

**Sample Output:**
```
| smb-security-level:
|   Security Level: user
|   Encryption: Not required
|   Authentication: NTLM enabled
|   Risk: Weak - Plaintext password allowed
```

---

#### 4. **smb-signing-config** - SMB Message Signing Configuration
**Description:** Validates SMB message signing settings for integrity protection.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Message signing enabled
- Signature enforcement
- Negotiation capability

**How to Execute:**
```bash
nmap -p 139,445 --script smb-signing-config <TARGET>
nmap -p 139,445 --script smb-signing-config -v example.com
```

**Sample Output:**
```
| smb-signing-config:
|   Signing Supported: true
|   Signing Required: false
|   Status: WEAK - Signing optional
```

---

#### 5. **smb-capabilities** - SMB Capabilities Detection
**Description:** Enumerates SMB capabilities and supported features.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Supported SMB versions
- Extended security support
- Unicode capability
- Large file support
- DFS support

**How to Execute:**
```bash
nmap -p 139,445 --script smb-capabilities <TARGET>
nmap -p 445 --script smb-capabilities -v example.com
```

**Sample Output:**
```
| smb-capabilities:
|   Supported SMB: 2.1, 3.0, 3.1.1
|   Extended Security: true
|   Unicode: true
|   DFS: true
```

---

#### 6. **smb-protocol-dialects** - SMB Protocol Dialects
**Description:** Identifies supported SMB protocol dialects and versions.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- SMBv1 support (deprecated)
- SMBv2 support
- SMBv3 support
- Protocol negotiation

**How to Execute:**
```bash
nmap -p 139,445 --script smb-protocol-dialects <TARGET>

# Verbose output
nmap -p 445 --script smb-protocol-dialects -v example.com
```

**Sample Output:**
```
| smb-protocol-dialects:
|   Dialects:
|     - SMB 2.02 (deprecated)
|     - SMB 2.1
|     - SMB 3.0
|   Status: SMBv1 disabled (good)
```

---

#### 7. **smb-extended-security** - Extended Security Audit
**Description:** Audits SMB extended security features and configuration.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Extended security negotiation
- Kerberos support
- SPNEGO support
- Encryption capability

**How to Execute:**
```bash
nmap -p 139,445 --script smb-extended-security <TARGET>
nmap -p 445 --script smb-extended-security -v example.com
```

**Sample Output:**
```
| smb-extended-security:
|   Extended Security: Negotiated
|   Kerberos: Supported
|   SPNEGO: Supported
|   Status: SECURE - modern authentication in use
```

---

#### 8. **smb-share-accessibility** - Share Access Enumeration
**Description:** Enumerates SMB shares and tests accessibility without credentials.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Available shares
- Anonymous accessible shares
- Share permissions
- Writable shares

**How to Execute:**
```bash
nmap -p 139,445 --script smb-share-accessibility <TARGET>
nmap -p 445 --script smb-share-accessibility -v example.com
```

**Sample Output:**
```
| smb-share-accessibility:
|   Shares enumerated: 5
|   Anonymous accessible:
|     - ADMIN$ (read-write)
|     - C$ (read-only)
|   Restricted: USERS, DATA
```

---

#### 9. **smb-buffer-limits** - SMB Buffer Configuration
**Description:** Checks SMB buffer size and connection limits.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Max buffer size
- Connection limits
- Performance settings
- DoS vulnerability potential

**How to Execute:**
```bash
nmap -p 139,445 --script smb-buffer-limits <TARGET>

# Verbose output
nmap -p 445 --script smb-buffer-limits -v example.com
```

**Sample Output:**
```
| smb-buffer-limits:
|   Max buffer size: 65536 bytes
|   Max connections: unlimited
|   Max open files: 2048
```

---

## 🛡️ SSL/TLS Protocol Security Audits

### Category Overview
SSL/TLS cryptographic protocol audits focusing on certificate validation, cipher strength, and protocol version security.

**Port:** 443 | **Protocol:** HTTPS/TLS

---

### SSL/TLS Scripts List

#### 1. **ssl-weak-ciphers** - Weak Cipher Suite Detection
**Description:** Identifies weak or deprecated TLS cipher suites accepted by server.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- NULL ciphers (no encryption)
- Export-grade ciphers (40-bit)
- DES/3DES ciphers (weak)
- RC4 ciphers (broken)
- Anonymous Diffie-Hellman (no auth)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-weak-ciphers example.com

# Verbose output
nmap -p 443 --script ssl-weak-ciphers -v example.com

# Multiple ports
nmap -p 443,8443 --script ssl-weak-ciphers example.com
```

**Sample Output:**
```
| ssl-weak-ciphers:
|   Weak ciphers ACCEPTED:
|     - RC4 ciphers: TLS_RSA_WITH_RC4_128_SHA
|     - 3DES ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA
|   Weak ciphers REJECTED:
|     - NULL ciphers
|     - Export-grade ciphers
```

---

#### 2. **ssl-protocol-versions** - TLS Version Support Analysis
**Description:** Audits supported TLS/SSL protocol versions and identifies deprecated implementations.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- SSLv3 (deprecated)
- TLSv1.0 (deprecated)
- TLSv1.1 (weak)
- TLSv1.2 (secure)
- TLSv1.3 (recommended)

**How to Execute:**
```bash
# Detect protocol versions
nmap -p 443 --script ssl-protocol-versions example.com

# Verbose output
nmap -p 443 --script ssl-protocol-versions -v example.com
```

**Sample Output:**
```
| ssl-protocol-versions:
|   Supported:
|     - TLSv1.0 (WEAK - deprecated)
|     - TLSv1.1 (WEAK - deprecated)
|     - TLSv1.2 (SECURE)
|     - TLSv1.3 (SECURE - recommended)
|   Recommendation: Disable TLSv1.0/1.1
```

---

#### 3. **ssl-cert-info** - Certificate Information Extraction
**Description:** Extracts and displays detailed SSL/TLS certificate information.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Subject and Issuer details
- Public key information
- Validity dates
- Alternative names (SANs)
- Key usage extensions
- Certificate chain

**How to Execute:**
```bash
# Extract certificate details
nmap -p 443 --script ssl-cert-info example.com

# Verbose output
nmap -p 443 --script ssl-cert-info -v example.com
```

**Sample Output:**
```
| ssl-cert-info:
|   Subject: CN=example.com
|   Issuer: CN=Let's Encrypt Authority X3
|   Version: 3
|   Public Key: RSA 2048-bit
|   Validity: 2024-01-01 to 2025-01-01
|   SANs: www.example.com, api.example.com
```

---

#### 4. **ssl-cert-expiry** - Certificate Expiry Validation
**Description:** Monitors SSL certificate expiration dates and provides renewal alerts.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Certificate expiration date
- Days until expiry
- Renewal status
- Grace period alerts

**How to Execute:**
```bash
# Check expiry
nmap -p 443 --script ssl-cert-expiry example.com

# Verbose
nmap -p 443 --script ssl-cert-expiry -v example.com
```

**Sample Output:**
```
| ssl-cert-expiry:
|   Subject: CN=example.com
|   Expires: 2025-06-15
|   Days remaining: 45
|   Status: WARNING - expires in 45 days
```

---

#### 5. **ssl-cert-hostname-mismatch** - Hostname Verification
**Description:** Validates certificate hostname matches the target domain.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Certificate CN matching
- SAN matching
- Wildcard compatibility
- MITM vulnerability

**How to Execute:**
```bash
nmap -p 443 --script ssl-cert-hostname-mismatch example.com
nmap -p 443 --script ssl-cert-hostname-mismatch -v example.com
```

**Sample Output:**
```
| ssl-cert-hostname-mismatch:
|   Target: example.com
|   Certificate CN: other-domain.com
|   Status: MISMATCH DETECTED
|   Risk: Critical - MITM possible
```

---

#### 6. **ssl-cert-weak-signature** - Weak Signature Algorithm Detection
**Description:** Identifies certificates signed with weak or deprecated algorithms.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- MD5 signature (broken)
- SHA-1 signature (weak)
- SHA-256 with small keys
- Signature algorithm security

**How to Execute:**
```bash
nmap -p 443 --script ssl-cert-weak-signature example.com

# Verbose output
nmap -p 443 --script ssl-cert-weak-signature -v example.com
```

**Sample Output:**
```
| ssl-cert-weak-signature:
|   Subject: CN=oldcert.com
|   Signature Algorithm: SHA1withRSA
|   Status: WEAK - deprecated
|   Recommendation: Replace certificate
```

---

#### 7. **ssl-compression-check** - TLS Compression Vulnerability
**Description:** Detects TLS compression enablement (CRIME vulnerability risk).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Compression enablement
- CRIME vulnerability risk
- Deflate support

**How to Execute:**
```bash
nmap -p 443 --script ssl-compression-check example.com

# Verbose output
nmap -p 443 --script ssl-compression-check -v example.com
```

**Sample Output:**
```
| ssl-compression-check:
|   Compression: ENABLED
|   Vulnerability: CRIME attack possible
|   Recommendation: Disable compression
```

---

#### 8. **ssl-ocsp-stapling** - OCSP Stapling Configuration
**Description:** Validates OCSP stapling implementation for certificate status verification.

**Risk Level:** 🟢 LOW | **Category:** Defensive

**What it checks:**
- OCSP stapling enabled
- Response validity
- Staple freshness

**How to Execute:**
```bash
nmap -p 443 --script ssl-ocsp-stapling example.com

# Verbose output
nmap -p 443 --script ssl-ocsp-stapling -v example.com
```

**Sample Output:**
```
| ssl-ocsp-stapling:
|   OCSP Stapling: NOT ENABLED
|   Response validity: N/A
|   Recommendation: enable stapling to reduce revocation-check latency
```

---

#### 9. **ssl-secure-renegotiation** - TLS Renegotiation Security
**Description:** Verifies secure renegotiation support (prevents CVE-2009-3555).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Renegotiation support
- Secure renegotiation flag
- CVE-2009-3555 protection

**How to Execute:**
```bash
nmap -p 443 --script ssl-secure-renegotiation example.com

# Verbose output
nmap -p 443 --script ssl-secure-renegotiation -v example.com
```

**Sample Output:**
```
| ssl-secure-renegotiation:
|   Secure Renegotiation: SUPPORTED
|   Legacy Renegotiation: DISABLED
|   CVE-2009-3555: NOT VULNERABLE
```

---

## 🗄️ Database Security Audits

### Category Overview
Database service security audits focusing on unauthenticated access, default/weak credentials, and transport encryption across MongoDB, Microsoft SQL Server, MySQL/MariaDB, PostgreSQL, and Redis.

**Port:** 1433/3306/5432/6379/27017 | **Protocol:** Database wire protocols (TCP)

---

### Database Scripts List

#### 1. **mongodb-unauthenticated-check** - MongoDB Unauthenticated Access Check
**Description:** Sends an unauthenticated hello/isMaster command to a MongoDB instance and inspects the response to determine whether the handshake is processed without credentials.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Unauthenticated hello/isMaster command handling
- maxWireVersion disclosure
- isWritablePrimary / ismaster role disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 27017 --script mongodb-unauthenticated-check example.com

# Verbose output
nmap -p 27017 --script mongodb-unauthenticated-check -v example.com
```

**Sample Output:**
```
| mongodb-unauthenticated-check:
|   Unauthenticated hello/isMaster accepted: true
|   maxWireVersion: 17
|   isWritablePrimary: true
|   Assessment: Server processed an unauthenticated hello/isMaster command. Confirm separately whether data-bearing commands are also permitted.
```

---

#### 2. **mssql-prelogin-check** - MSSQL PRELOGIN Encryption & Version Check
**Description:** Sends a TDS PRELOGIN packet to a Microsoft SQL Server instance and parses the response to report the product version and TLS encryption enforcement.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Server version (from PRELOGIN VERSION option)
- Encryption requirement (OFF / ON / REQUIRED / NOT SUPPORTED)
- TLS enforcement before login

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script mssql-prelogin-check example.com

# Verbose output
nmap -p 1433 --script mssql-prelogin-check -v example.com
```

**Sample Output:**
```
| mssql-prelogin-check:
|   Server version (from PRELOGIN): 15.0 build 4236
|   Encryption setting: ENCRYPT_OFF - encryption not requested by server
```

---

#### 3. **mysql-banner-grab** - MySQL/MariaDB Handshake Fingerprint
**Description:** Connects to a MySQL/MariaDB service and parses the initial handshake packet to extract protocol version, server version string, and capability flags.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol version
- Server version string and family (MySQL vs MariaDB)
- Connection thread ID
- Capability flags

**How to Execute:**
```bash
# Basic scan
nmap -p 3306 --script mysql-banner-grab example.com

# Verbose output
nmap -p 3306 --script mysql-banner-grab -v example.com
```

**Sample Output:**
```
| mysql-banner-grab:
|   Protocol version: 10
|   Server version string: 8.0.36-0ubuntu0.22.04.1
|   Server family: MySQL (Oracle) or compatible
|   Capability flags (lower 16 bits): 0xFFFF
```

---

#### 4. **mysql-empty-password-check** - MySQL Root Empty Password Check
**Description:** Attempts to authenticate as the root account with an empty password and reports whether the server accepts the login.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Root account login with a blank password
- mysql_native_password authentication response
- Server error codes on rejection

**How to Execute:**
```bash
# Basic scan
nmap -p 3306 --script mysql-empty-password-check example.com

# Verbose output
nmap -p 3306 --script mysql-empty-password-check -v example.com
```

**Sample Output:**
```
| mysql-empty-password-check:
|   Login as root with empty password: SUCCESS
|   Assessment: CRITICAL - the root account accepts an empty password. This grants full database access to anyone.
```

---

#### 5. **mysql-ssl-support-check** - MySQL/MariaDB TLS Capability Check
**Description:** Parses handshake capability flags to determine whether the server advertises CLIENT_SSL support for encrypted connections.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- CLIENT_SSL capability flag
- CLIENT_PROTOCOL_41 support
- CLIENT_SECURE_CONNECTION support
- CLIENT_PLUGIN_AUTH support

**How to Execute:**
```bash
# Basic scan
nmap -p 3306 --script mysql-ssl-support-check example.com

# Verbose output
nmap -p 3306 --script mysql-ssl-support-check -v example.com
```

**Sample Output:**
```
| mysql-ssl-support-check:
|   Raw capability flags: 0x81BEFF
|   CLIENT_SSL advertised: false
|   Assessment: Server did not advertise CLIENT_SSL - connections to this instance are limited to plaintext.
```

---

#### 6. **postgresql-ssl-support-check** - PostgreSQL TLS Negotiation Check
**Description:** Sends a PostgreSQL SSLRequest packet and checks the server's single-byte response to determine whether encrypted connections can be negotiated.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- SSLRequest response (S/N)
- Pre-authentication TLS availability
- Plaintext-only fallback risk

**How to Execute:**
```bash
# Basic scan
nmap -p 5432 --script postgresql-ssl-support-check example.com

# Verbose output
nmap -p 5432 --script postgresql-ssl-support-check -v example.com
```

**Sample Output:**
```
| postgresql-ssl-support-check:
|   SSL/TLS negotiation supported: YES
|   Assessment: Server is willing to negotiate TLS before authentication. Confirm client configuration actually requires it (sslmode=require or stronger).
```

---

#### 7. **postgresql-trust-auth-check** - PostgreSQL Trust Authentication Check
**Description:** Sends a StartupMessage for the postgres user and inspects the authentication response to detect "trust" authentication, which allows login without credentials.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Authentication method requested by the server
- Immediate AuthenticationOk (trust auth)
- Cleartext password fallback

**How to Execute:**
```bash
# Basic scan
nmap -p 5432 --script postgresql-trust-auth-check example.com

# Verbose output
nmap -p 5432 --script postgresql-trust-auth-check -v example.com
```

**Sample Output:**
```
| postgresql-trust-auth-check:
|   Authentication method requested: AuthenticationOk (no password required - trust/peer-equivalent)
|   Assessment: CRITICAL - server granted AuthenticationOk immediately for the postgres user with no credentials supplied (trust authentication).
```

---

#### 8. **redis-admin-command-exposure** - Redis Administrative Command Exposure
**Description:** Uses the read-only COMMAND INFO subcommand to check whether high-risk administrative Redis commands are present and callable, without invoking them destructively.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- FLUSHALL / FLUSHDB availability
- CONFIG / SHUTDOWN / DEBUG availability
- SLAVEOF / REPLICAOF / MODULE / SCRIPT availability

**How to Execute:**
```bash
# Basic scan
nmap -p 6379 --script redis-admin-command-exposure example.com

# Verbose output
nmap -p 6379 --script redis-admin-command-exposure -v example.com
```

**Sample Output:**
```
| redis-admin-command-exposure:
|   High-risk commands present and callable: FLUSHALL, CONFIG, SHUTDOWN
|   Assessment: One or more administrative commands remain enabled under the current (lack of) authentication - consider renaming or disabling them via rename-command, and enforcing requirepass/ACLs.
```

---

#### 9. **redis-unauthenticated-access** - Redis Unauthenticated Access Check
**Description:** Sends PING and INFO commands without an AUTH command and reports whether the server processes them, extracting version and configuration details on success.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Unauthenticated PING response
- Unauthenticated INFO command access
- Redis version, OS, and mode disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6379 --script redis-unauthenticated-access example.com

# Verbose output
nmap -p 6379 --script redis-unauthenticated-access -v example.com
```

**Sample Output:**
```
| redis-unauthenticated-access:
|   Unauthenticated PING accepted: true
|   Redis version: 7.2.4
|   Assessment: VULNERABLE - Redis instance is fully accessible without authentication.
```

---

## 📁 FTP Security Audits

### Category Overview
FTP protocol security audits focusing on anonymous access, cleartext credential exposure, and file-transfer misconfigurations.

**Port:** 21 | **Protocol:** FTP (Control Channel)

---

### FTP Scripts List

#### 1. **ftp-anonymous-login** - Anonymous FTP Login Check
**Description:** Attempts anonymous FTP login using common anonymous credential pairs and reports whether unauthenticated access is permitted.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- anonymous / anonymous@example.com
- anonymous / anonymous
- ftp / ftp
- anonymous with blank password

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-anonymous-login example.com

# Verbose output
nmap -p 21 --script ftp-anonymous-login -v example.com
```

**Sample Output:**
```
| ftp-anonymous-login:
|   Credential attempts: anonymous / anonymous@example.com -> SUCCESS
|   Welcome message on success: 230 Login successful.
|   Result: VULNERABLE - anonymous/unauthenticated FTP access is permitted.
```

---

#### 2. **ftp-banner-grab** - FTP Server Banner Fingerprint
**Description:** Grabs the FTP welcome banner and fingerprints the server software and version, flagging known end-of-life or notably outdated releases.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Server software identification (vsftpd, ProFTPD, Pure-FTPd, FileZilla, etc.)
- Version extraction
- Outdated version detection

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-banner-grab example.com

# Verbose output
nmap -p 21 --script ftp-banner-grab -v example.com
```

**Sample Output:**
```
| ftp-banner-grab:
|   Raw banner: 220 (vsFTPd 2.3.4)
|   Identified server software: vsftpd
|   Detected version: 2.3.4
|   Version assessment: Version 2.3.4 is older than the vsftpd baseline (3.0.0) - check for known CVEs against this release.
```

---

#### 3. **ftp-bounce-check** - FTP Bounce Precondition Check
**Description:** Checks whether the server accepts PORT commands specifying an address unrelated to the client's control connection, a precondition for the classic FTP bounce technique.

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- PORT command acceptance for third-party addresses
- Classic FTP bounce precondition
- Proxy/tunneling abuse potential

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-bounce-check example.com

# Verbose output
nmap -p 21 --script ftp-bounce-check -v example.com
```

**Sample Output:**
```
| ftp-bounce-check:
|   PORT command tests: 10.0.0.1 -> ACCEPTED (200)
|   Assessment: POTENTIALLY VULNERABLE - server accepted PORT commands referencing addresses unrelated to the control connection.
```

---

#### 4. **ftp-cleartext-enforcement** - Cleartext Credential Enforcement Check
**Description:** Attempts a plaintext USER/PASS login without negotiating TLS first and reports whether the server processes credentials in the clear.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Plaintext login processing
- TLS requirement before authentication
- Credential exposure over the network

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-cleartext-enforcement example.com

# Verbose output
nmap -p 21 --script ftp-cleartext-enforcement -v example.com
```

**Sample Output:**
```
| ftp-cleartext-enforcement:
|   USER command response code: 331
|   Cleartext login enforcement: Server processed a plaintext authentication attempt without requiring TLS first - credentials sent over this control channel would be transmitted unencrypted.
```

---

#### 5. **ftp-command-enum** - FTP Command & Feature Enumeration
**Description:** Enumerates FEAT-advertised extensions and probes for individually risky commands, flagging SITE EXEC as historically associated with remote command execution.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- FEAT extension advertisement
- SITE EXEC / SITE CHMOD availability
- MDTM, SIZE, REST, RNFR/RNTO support

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-command-enum example.com

# Verbose output
nmap -p 21 --script ftp-command-enum -v example.com
```

**Sample Output:**
```
| ftp-command-enum:
|   FEAT extensions advertised: UTF8, MDTM, SIZE, REST STREAM
|   Commands implemented: SITE HELP, MDTM, SIZE, REST
|   Notable risk findings: SITE EXEC appears to be implemented - historically linked to remote command execution vulnerabilities in some FTP daemons.
```

---

#### 6. **ftp-directory-listing** - Anonymous Directory Listing Audit
**Description:** Logs in anonymously and lists common directories, scanning returned filenames for sensitive keyword patterns.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Anonymous directory listing access
- Sensitive filename patterns (backup, config, .sql, id_rsa, .env, etc.)
- File enumeration across common paths

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-directory-listing example.com

# Verbose output
nmap -p 21 --script ftp-directory-listing -v example.com
```

**Sample Output:**
```
| ftp-directory-listing:
|   Directories successfully listed: 4
|   Total filenames observed: 27
|   Sensitive-looking files found: /backup/db_dump.sql (matched keyword: sql)
```

---

#### 7. **ftp-passive-mode-check** - Passive Mode Address Configuration Check
**Description:** Sends PASV and EPSV commands and inspects the returned data-channel address, flagging private-IP addresses advertised over a public control connection.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- PASV advertised IP/port
- Private-IP vs. public control-address mismatch
- EPSV (extended passive mode) support

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-passive-mode-check example.com

# Verbose output
nmap -p 21 --script ftp-passive-mode-check -v example.com
```

**Sample Output:**
```
| ftp-passive-mode-check:
|   PASV advertised address: 192.168.1.50:52341
|   PASV misconfiguration: Server advertised a private/internal address over a connection made to a non-private control address.
|   EPSV supported: YES - extended passive mode port 52341
```

---

#### 8. **ftp-tls-support** - Explicit FTPS Support Check
**Description:** Checks whether the server supports explicit FTPS via AUTH TLS/AUTH SSL commands and FEAT-advertised PBSZ/PROT mechanisms.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- AUTH TLS acceptance
- AUTH SSL acceptance
- FEAT mechanisms (PBSZ, PROT, CCC)

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-tls-support example.com

# Verbose output
nmap -p 21 --script ftp-tls-support -v example.com
```

**Sample Output:**
```
| ftp-tls-support:
|   FEAT mechanisms mentioning TLS/SSL: auth tls, pbsz, prot
|   AUTH TLS accepted: true
|   Assessment: Explicit FTPS is supported - credentials and data CAN be protected if the client negotiates TLS.
```

---

#### 9. **ftp-writable-dirs** - Anonymous Writable Directory Check
**Description:** Logs in anonymously and attempts to upload a small test file into common directories to determine which are writable by unauthenticated users, deleting the file immediately afterward.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Anonymous write access to common directories
- Malware-staging / defacement exposure
- Upload-and-cleanup verification

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-writable-dirs example.com

# Verbose output
nmap -p 21 --script ftp-writable-dirs -v example.com
```

**Sample Output:**
```
| ftp-writable-dirs:
|   Anonymous-writable directories: /incoming, /upload
|   Assessment: VULNERABLE - one or more directories accept anonymous file uploads.
```

---

## 🎯 Comprehensive Scanning Scenarios

### Scenario 1: Full Infrastructure Security Audit

```bash
nmap -p 21,53,80,139,443,445,1433,3306,5432,6379,27017 \
  --script 'http-*,dns-*,smb-*,ssl-*,ftp-*,mongodb-*,mssql-*,mysql-*,postgresql-*,redis-*' \
  --script-args \
    dns-zone-transfer-check.domain=example.com,\
    dns-subdomain-enum.domain=example.com \
  -sV -v \
  -oX infrastructure-audit.xml \
  example.com
```

### Scenario 2: HTTP Only Audit

```bash
nmap -p 80,443 \
  --script 'http-*' \
  -v \
  -oA http-audit \
  example.com
```

### Scenario 3: DNS Infrastructure Audit

```bash
nmap -p 53 \
  --script 'dns-*' \
  --script-args \
    dns-zone-transfer-check.domain=example.com,\
    dns-subdomain-enum.domain=example.com \
  -v \
  8.8.8.8
```

### Scenario 4: Windows SMB Audit

```bash
nmap -p 139,445 \
  --script 'smb-*' \
  -v \
  -oA smb-audit \
  192.168.1.0/24
```

### Scenario 5: SSL/TLS Complete Audit

```bash
nmap -p 443,8443 \
  --script 'ssl-*' \
  -sV -v \
  -oX tls-audit.xml \
  example.com
```

### Scenario 6: Database Infrastructure Audit

```bash
nmap -p 1433,3306,5432,6379,27017 \
  --script 'mongodb-*,mssql-*,mysql-*,postgresql-*,redis-*' \
  -v \
  -oA database-audit \
  example.com
```

### Scenario 7: FTP Server Audit

```bash
nmap -p 21 \
  --script 'ftp-*' \
  -v \
  -oA ftp-audit \
  example.com
```

### Scenario 8: Quick Security Assessment

```bash
nmap -p 21,53,80,139,443,445,3306 \
  --script http-security-headers,ssl-weak-ciphers,\
dns-zone-transfer-check,smb-null-session-check,\
ftp-anonymous-login,mysql-empty-password-check \
  --script-args dns-zone-transfer-check.domain=example.com \
  example.com
```

---

## 📊 Script Reference Summary Table

| Protocol | Script Name | Port | Risk Level | Category | Check Type |
|----------|-------------|------|-----------|----------|-----------|
| **HTTP** | http-security-headers | 80/443 | 🟡 MEDIUM | Defensive | Headers |
| **HTTP** | http-cookie-flags | 80/443 | 🟡 MEDIUM | Defensive | Cookies |
| **HTTP** | http-cors-config | 80/443 | 🟡 MEDIUM | Discovery | CORS |
| **HTTP** | http-cache-audit | 80/443 | 🟢 LOW | Defensive | Caching |
| **HTTP** | http-error-disclosure | 80/443 | 🟡 MEDIUM | Discovery | Errors |
| **HTTP** | http-methods-enum | 80/443 | 🟡 MEDIUM | Discovery | Methods |
| **HTTP** | http-server-fingerprint | 80/443 | 🟢 LOW | Discovery | Fingerprint |
| **HTTP** | http-dir-listing | 80/443 | 🟡 MEDIUM | Discovery | Listing |
| **HTTP** | http-robots-sitemap | 80/443 | 🟢 LOW | Discovery | Meta |
| **HTTP** | http-trace-method | 80/443 | 🟠 HIGH | Vulnerability | XST |
| **DNS** | dns-zone-transfer-check | 53 | 🔴 CRITICAL | Vulnerability | AXFR |
| **DNS** | dns-subdomain-enum | 53 | 🟡 MEDIUM | Discovery | Enumeration |
| **DNS** | dns-recursion-check | 53 | 🔴 CRITICAL | Vulnerability | Recursion |
| **DNS** | dns-amplification-risk | 53 | 🟠 HIGH | Vulnerability | Amplification |
| **DNS** | dns-cache-snooping | 53 | 🟡 MEDIUM | Discovery | Cache |
| **DNS** | dns-srv-enum | 53 | 🟢 LOW | Discovery | SRV Records |
| **DNS** | dns-txt-spf-dmarc-audit | 53 | 🟡 MEDIUM | Defensive | Email |
| **DNS** | dns-soa-consistency-check | 53 | 🟢 LOW | Defensive | SOA |
| **DNS** | dns-wildcard-detector | 53 | 🟢 LOW | Discovery | Wildcards |
| **SMB** | smb-null-session-check | 139/445 | 🟠 HIGH | Vulnerability | Auth |
| **SMB** | smb-guest-access-check | 139/445 | 🟠 HIGH | Vulnerability | Auth |
| **SMB** | smb-security-level | 139/445 | 🟡 MEDIUM | Defensive | Config |
| **SMB** | smb-signing-config | 139/445 | 🟡 MEDIUM | Defensive | Signing |
| **SMB** | smb-capabilities | 139/445 | 🟢 LOW | Discovery | Features |
| **SMB** | smb-protocol-dialects | 139/445 | 🟢 LOW | Discovery | Dialects |
| **SMB** | smb-extended-security | 139/445 | 🟡 MEDIUM | Defensive | Security |
| **SMB** | smb-share-accessibility | 139/445 | 🟡 MEDIUM | Discovery | Shares |
| **SMB** | smb-buffer-limits | 139/445 | 🟢 LOW | Discovery | Limits |
| **SSL/TLS** | ssl-weak-ciphers | 443 | 🔴 CRITICAL | Vulnerability | Ciphers |
| **SSL/TLS** | ssl-protocol-versions | 443 | 🟠 HIGH | Discovery | Versions |
| **SSL/TLS** | ssl-cert-info | 443 | 🟢 LOW | Discovery | Certificate |
| **SSL/TLS** | ssl-cert-expiry | 443 | 🟡 MEDIUM | Defensive | Expiry |
| **SSL/TLS** | ssl-cert-hostname-mismatch | 443 | 🔴 CRITICAL | Vulnerability | Hostname |
| **SSL/TLS** | ssl-cert-weak-signature | 443 | 🟠 HIGH | Vulnerability | Signature |
| **SSL/TLS** | ssl-compression-check | 443 | 🟠 HIGH | Vulnerability | Compression |
| **SSL/TLS** | ssl-ocsp-stapling | 443 | 🟢 LOW | Defensive | OCSP |
| **SSL/TLS** | ssl-secure-renegotiation | 443 | 🟡 MEDIUM | Defensive | Renegotiation |
| **Database** | mongodb-unauthenticated-check | 27017 | 🟠 HIGH | Vulnerability | Auth |
| **Database** | mssql-prelogin-check | 1433 | 🟡 MEDIUM | Defensive | Encryption |
| **Database** | mysql-banner-grab | 3306 | 🟢 LOW | Discovery | Fingerprint |
| **Database** | mysql-empty-password-check | 3306 | 🔴 CRITICAL | Vulnerability | Credentials |
| **Database** | mysql-ssl-support-check | 3306 | 🟡 MEDIUM | Defensive | TLS |
| **Database** | postgresql-ssl-support-check | 5432 | 🟡 MEDIUM | Defensive | TLS |
| **Database** | postgresql-trust-auth-check | 5432 | 🔴 CRITICAL | Vulnerability | Auth |
| **Database** | redis-admin-command-exposure | 6379 | 🟠 HIGH | Vulnerability | Commands |
| **Database** | redis-unauthenticated-access | 6379 | 🔴 CRITICAL | Vulnerability | Auth |
| **FTP** | ftp-anonymous-login | 21 | 🟠 HIGH | Vulnerability | Auth |
| **FTP** | ftp-banner-grab | 21 | 🟢 LOW | Discovery | Fingerprint |
| **FTP** | ftp-bounce-check | 21 | 🟡 MEDIUM | Vulnerability | Bounce |
| **FTP** | ftp-cleartext-enforcement | 21 | 🟡 MEDIUM | Defensive | Encryption |
| **FTP** | ftp-command-enum | 21 | 🟡 MEDIUM | Discovery | Commands |
| **FTP** | ftp-directory-listing | 21 | 🟡 MEDIUM | Discovery | Listing |
| **FTP** | ftp-passive-mode-check | 21 | 🟢 LOW | Discovery | PASV/EPSV |
| **FTP** | ftp-tls-support | 21 | 🟡 MEDIUM | Defensive | TLS |
| **FTP** | ftp-writable-dirs | 21 | 🔴 CRITICAL | Vulnerability | Write Access |

---

## 🔍 Risk Level Guide

### 🔴 CRITICAL - Immediate Action Required
- Exploit possible without authentication
- Complete system compromise risk
- Immediate vulnerability patch needed
- Examples: Zone transfer allowed, weak ciphers, database trust authentication

### 🟠 HIGH - High Priority
- Significant security impact
- Increased attack surface
- Should be addressed soon
- Examples: Deprecated TLS, guest access, null sessions

### 🟡 MEDIUM - Medium Priority
- Moderate security issue
- Defense in depth improvement
- Should be addressed
- Examples: Cache snooping, weak signing, missing security headers

### 🟢 LOW - Informational
- General information gathering
- Configuration details
- Non-critical findings
- Examples: Version detection, feature enumeration, banner fingerprinting

---

## 🛠️ Advanced Usage & Customization

### Combine Multiple Categories

```bash
# All HTTP and SMB audits
nmap -p 80,139,443,445 --script 'http-*,smb-*' -v example.com

# All security checks except discovery
nmap -p 53,80,139,443,445 \
  --script 'http-security-*,dns-*,smb-security-*,ssl-*' \
  example.com

# All FTP and Database audits (Database has no single prefix - list each vendor)
nmap -p 21,1433,3306,5432,6379,27017 \
  --script 'ftp-*,mongodb-*,mssql-*,mysql-*,postgresql-*,redis-*' \
  -v example.com
```

### Custom Script Arguments

```bash
# Specify custom domain for DNS checks
nmap -p 53 --script 'dns-*' \
  --script-args \
    dns-zone-transfer-check.domain=example.com,\
    dns-subdomain-enum.domain=example.com,\
    dns-txt-spf-dmarc-audit.domain=example.com \
  8.8.8.8

# Custom ports and arguments
nmap -p 443,8443 --script 'ssl-*' \
  --script-args ssl.ciphers=all \
  example.com
```

### Output Formats

```bash
# XML output (best for parsing)
nmap -p 80,443,53 --script 'http-*,dns-*' -oX results.xml example.com

# Normal text
nmap -p 80,443,53 --script 'http-*,dns-*' -oN results.txt example.com

# Grepable (for grep/awk)
nmap -p 80,443,53 --script 'http-*,dns-*' -oG results.grep example.com

# All formats
nmap -p 80,443,53 --script 'http-*,dns-*' -oA results example.com
```

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** These scripts are for:
- ✅ Authorized security testing
- ✅ Defensive security audits
- ✅ Educational purposes
- ✅ Compliance verification

**PROHIBITED:**
- ❌ Unauthorized network scanning
- ❌ Malicious purposes
- ❌ Legal violations

---

## 🛠️ Troubleshooting

```bash
# Verify installation
nmap --script-help http-security-headers

# Update database
nmap --script-updatedb

# Increase timeout
nmap -p 80,443 --script http-security-headers \
  --script-args http.timeout=30000 example.com

# Debug mode
nmap -p 80,443 --script http-security-headers -d -vv example.com
```

---

## 🤝 Contributing

Contributions are welcome! Whether it's a new script, a bug fix, or a documentation improvement:

1. **Fork** the repository
2. Create a feature branch (`git checkout -b feature/new-script-name`)
3. Follow the existing script structure and comment style (see any script in `HTTP/` or `DNS/` as a reference)
4. Test your script locally with `nmap --script-help <your-script>` and against a real/lab target
5. Commit your changes with a clear message
6. Open a **Pull Request** describing what the script/change does and why

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines (coding style, PR checklist, and how new scripts get reviewed).

---

## 🔒 Security Policy

Found a bug in a script that causes a **false positive/negative**, a crash, or unsafe behavior against a target? Please **do not** open a public issue with exploit details for anything beyond what these scripts already do (informational/defensive checks).

- For script bugs or false positives → open a normal [GitHub Issue](../../issues)
- For anything sensitive → see [SECURITY.md](SECURITY.md) for responsible disclosure steps

---

## 📝 Changelog

All notable changes to this project are documented in [CHANGELOG.md](CHANGELOG.md), following the [Keep a Changelog](https://keepachangelog.com/) format and [Semantic Versioning](https://semver.org/).

---

## 📞 Support & Documentation

- **GitHub Issues:** [Report bugs and feature requests](../../issues)
- **Discussions:** Use GitHub Discussions (if enabled) for usage questions
- **Nmap Documentation:** https://nmap.org/
- **NSE Guide:** https://nmap.org/book/nse-usage.html

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

These scripts are designed to run within the Nmap Scripting Engine (NSE); Nmap itself remains licensed under its own terms, available at [Nmap Legal](https://nmap.org/book/man-legal.html).

---

## 📊 Project Summary

- **Total Scripts:** 55
- **HTTP Scripts:** 10 (port 80/443)
- **DNS Scripts:** 9 (port 53)
- **SMB Scripts:** 9 (port 139/445)
- **SSL/TLS Scripts:** 9 (port 443)
- **Database Scripts:** 9 (port 1433/3306/5432/6379/27017)
- **FTP Scripts:** 9 (port 21)
- **Total Lines of Code:** 6,967 Lua
- **Security Checks:** 198+
- **Supported Nmap:** 7.40+

---

**Quick Start:**
```bash
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cp -r Nmap-NSE-Script-Collection/{HTTP,DNS,SMB,SSL-TLS,DATABASE,FTP}/* ~/.nmap/scripts/
nmap --script-updatedb
nmap -p 21,53,80,139,443,445,1433,3306,5432,6379,27017 --script 'http-*,dns-*,smb-*,ssl-*,ftp-*,mongodb-*,mssql-*,mysql-*,postgresql-*,redis-*' example.com
```

**All 55 scripts are production-ready and immediately deployable!** 🚀

---

<p align="center">Made with 🛡️ for the defensive security community — ⭐ star this repo if it's useful to you!</p>
