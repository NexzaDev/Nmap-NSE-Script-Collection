# 🛰️ Nmap-NSE-Script-Collection

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Language-Lua%20100%25-blue.svg" alt="Language: Lua">
  <img src="https://img.shields.io/badge/Nmap-7.40%2B-informational.svg" alt="Nmap 7.40+">
  <img src="https://img.shields.io/badge/Scripts-103-orange.svg" alt="103 Scripts">
  <img src="https://img.shields.io/badge/Security%20Checks-390%2B-critical.svg" alt="390+ Security Checks">
  <img src="https://github.com/NexzaDev/Nmap-NSE-Script-Collection/actions/workflows/luacheck.yml/badge.svg" alt="Lua Lint Status">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/Maintained%3F-yes-success.svg" alt="Maintained">
  <img src="https://img.shields.io/badge/Docker-Test%20Environment-2496ED.svg?logo=docker&logoColor=white" alt="Docker test environment">
  <img src="https://img.shields.io/github/last-commit/NexzaDev/Nmap-NSE-Script-Collection.svg?color=blue" alt="Last commit">
  <img src="https://img.shields.io/github/issues/NexzaDev/Nmap-NSE-Script-Collection.svg?color=yellow" alt="Open issues">
</p>

<p align="center">
  <a href="#-http-security-audits"><img src="https://img.shields.io/badge/🌐_HTTP-10_scripts-blue?style=flat-square" /></a>
  <a href="#-dns-security-audits"><img src="https://img.shields.io/badge/🔍_DNS-9_scripts-blue?style=flat-square" /></a>
  <a href="#-smb-protocol-security-audits"><img src="https://img.shields.io/badge/🔐_SMB-9_scripts-blue?style=flat-square" /></a>
  <a href="#️-ssltls-protocol-security-audits"><img src="https://img.shields.io/badge/🛡️_SSL%2FTLS-9_scripts-blue?style=flat-square" /></a>
  <a href="#️-database-security-audits"><img src="https://img.shields.io/badge/🗄️_DATABASE-9_scripts-blue?style=flat-square" /></a>
  <a href="#-ftp-security-audits"><img src="https://img.shields.io/badge/📁_FTP-9_scripts-blue?style=flat-square" /></a>
  <br/>
  <a href="#-docker-engine--registry-security-audits"><img src="https://img.shields.io/badge/🐳_DOCKER-16_scripts-blue?style=flat-square" /></a>
  <a href="#-graphql-api-security-audits"><img src="https://img.shields.io/badge/🔮_GRAPHQL-16_scripts-blue?style=flat-square" /></a>
  <a href="#-mqtt--iot-protocol-security-audits"><img src="https://img.shields.io/badge/📡_MQTT-16_scripts-blue?style=flat-square" /></a>
  <a href="#-testing"><img src="https://img.shields.io/badge/🧪_Testing-Docker_localhost-2496ED?style=flat-square" /></a>
  <a href="#-whats-new"><img src="https://img.shields.io/badge/🆕_What's_New-orange?style=flat-square" /></a>
</p>

## 📖 Project Overview

A comprehensive collection of custom **Nmap NSE (Nmap Scripting Engine)** scripts specialized in **defensive security auditing** of web servers, DNS infrastructure, SMB/Windows services, SSL/TLS endpoints, database services, FTP servers, Docker Engine & Registry ecosystems, GraphQL APIs, and MQTT / IoT message brokers. These scripts are engineered to detect common security misconfigurations, including missing critical HTTP security headers, inadequate cookie protection flags, weak cryptographic algorithms, DNS vulnerabilities, SMB misconfigurations, unauthenticated database access, and insecure FTP configurations, among other prevalent security issues frequently overlooked in production environments.

**💻 Project Language:** Lua 100%

---

## 🗂️ Table of Contents

- [🆕 What's New](#-whats-new)
- [📋 Project Contents & Statistics](#-project-contents--statistics)
- [🚀 Installation](#-installation)
- [🌐 HTTP Security Audits](#-http-security-audits)
- [🔍 DNS Security Audits](#-dns-security-audits)
- [🔐 SMB Protocol Security Audits](#-smb-protocol-security-audits)
- [🛡️ SSL/TLS Protocol Security Audits](#️-ssltls-protocol-security-audits)
- [🗄️ Database Security Audits](#️-database-security-audits)
- [📁 FTP Security Audits](#-ftp-security-audits)
- [🐳 Docker Engine & Registry Security Audits](#-docker-engine--registry-security-audits)
- [🔮 GraphQL API Security Audits](#-graphql-api-security-audits)
- [📡 MQTT & IoT Protocol Security Audits](#-mqtt--iot-protocol-security-audits)
- [🎯 Comprehensive Scanning Scenarios](#-comprehensive-scanning-scenarios)
- [📊 Script Reference Summary Table](#-script-reference-summary-table)
- [🔍 Risk Level Guide](#-risk-level-guide)
- [🛠️ Advanced Usage & Customization](#️-advanced-usage--customization)
- [🧪 Testing](#-testing)
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🤝 Contributing](#-contributing)
- [🔒 Security Policy](#-security-policy)
- [📝 Changelog](#-changelog)
- [📞 Support & Documentation](#-support--documentation)
- [📄 License](#-license)

---

## 🆕 What's New

Recent additions to the project, on top of the original 55-script collection:

- 🧪 **Local Docker test environment** — spin up deliberately misconfigured HTTP, FTP, and Redis targets with `docker compose up -d` and run scripts straight against `localhost`. No more testing blind against production systems. See [Testing](#-testing) and [TESTING.md](TESTING.md).
- ⚙️ **CI linting** — every push/PR now runs `luacheck` automatically via GitHub Actions (`.github/workflows/luacheck.yml`).
- 📝 **Contribution & governance docs** — [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md) formalize how the project accepts scripts, handles disclosure, and tracks version history.
- 🐛 **Issue templates** — structured bug report and feature request templates under `.github/ISSUE_TEMPLATE/`.
- 📂 **Collapsible category sections** — each protocol category below (HTTP, DNS, SMB, SSL/TLS, Database, FTP) is now collapsed by default with a one-click expand, so the README stays easy to scan despite covering 55 scripts in full detail.
- 🧭 **Quick category navigation** — jump straight to any protocol category using the badge links right under the header.

---

## 📋 Project Contents & Statistics

### 📁 Directory Structure

```
Nmap-NSE-Script-Collection/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md          # Bug report issue template
│   │   └── feature_request.md     # Feature request issue template
│   └── workflows/
│       └── luacheck.yml           # CI: Lua linting on every push/PR
├── HTTP/                    # HTTP Protocol Security Audits (10 scripts)
├── DNS/                     # DNS Infrastructure Security Audits (9 scripts)
├── SMB/                     # SMB/Windows Protocol Security Audits (9 scripts)
├── SSL-TLS/                 # SSL/TLS Protocol Security Audits (9 scripts)
├── DATABASE/                # Database Service Security Audits (9 scripts)
├── FTP/                     # FTP Protocol Security Audits (9 scripts)
├── DOCKER/                  # Docker Engine & Registry Security Audits (16 scripts)
├── GRAPHQL/                 # GraphQL API Security Audits (16 scripts)
├── MQTT/                    # MQTT & IoT Protocol Security Audits (16 scripts)
├── test-fixtures/
│   └── http/
│       └── index.html       # Test page used by the HTTP target container
├── docker-compose.yml       # Local test environment (HTTP, FTP, Redis targets)
├── CHANGELOG.md             # Version history
├── CONTRIBUTING.md          # Contribution guidelines
├── LICENSE                  # MIT License
├── README.md                # This file
├── SECURITY.md              # Responsible disclosure policy
└── TESTING.md                # How to test scripts locally with Docker
```

### 📊 Statistics
- **Total Scripts:** 103
- **HTTP Scripts:** 10
- **DNS Scripts:** 9
- **SMB Scripts:** 9
- **SSL/TLS Scripts:** 9
- **Database Scripts:** 9
- **FTP Scripts:** 9
- **Docker Scripts:** 16
- **GraphQL Scripts:** 16
- **MQTT / IoT Scripts:** 16
- **Total Lines of Code:** 11,492 Lua
- **Security Checks:** 390+

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
ln -s $(pwd)/DOCKER ~/.nmap/scripts/custom-docker
ln -s $(pwd)/GRAPHQL ~/.nmap/scripts/custom-graphql
ln -s $(pwd)/MQTT ~/.nmap/scripts/custom-mqtt
```

**Linux/macOS (Direct Copy):**
```bash
cp -r HTTP/* DNS/* SMB/* SSL-TLS/* DATABASE/* FTP/* DOCKER/* GRAPHQL/* MQTT/* ~/.nmap/scripts/
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
Copy-Item -Path "DOCKER\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "GRAPHQL\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "MQTT\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
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

<details>
<summary><b>🌐 HTTP Security Audits — 10 scripts (click to expand)</b></summary>

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

</details>

<details>
<summary><b>🔍 DNS Security Audits — 9 scripts (click to expand)</b></summary>

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

</details>

<details>
<summary><b>🔐 SMB Protocol Security Audits — 9 scripts (click to expand)</b></summary>

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

</details>

<details>
<summary><b>🛡️ SSL/TLS Protocol Security Audits — 9 scripts (click to expand)</b></summary>

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

</details>

<details>
<summary><b>🗄️ Database Security Audits — 9 scripts (click to expand)</b></summary>

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

</details>

<details>
<summary><b>📁 FTP Security Audits — 9 scripts (click to expand)</b></summary>

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

</details>


<details>
<summary><b>🐳 Docker Engine & Registry Security Audits — 16 scripts (click to expand)</b></summary>

## 🐳 Docker Engine & Registry Security Audits

### Category Overview
Container infrastructure security audits focusing on unauthenticated Docker daemon REST APIs, container breakout vectors (privileged mode, dangerous capabilities, host volume mounts), Docker Registry v2 data/manifest leakage, Swarm cluster token exposure, and Go runtime profiling endpoints.

**Port:** 2375/2376/5000/2377/4243 | **Protocol:** HTTP/HTTPS REST API (Docker wire protocol)

---

### Docker Scripts List

#### 1. **docker-unauthenticated-api** - Unauthenticated Docker Daemon API Check
**Description:** Detects unauthenticated access to the Docker Engine REST API on ports 2375/2376/4243, extracts system metadata, container counts, OS/kernel version, and alerts on full root daemon takeover risk.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Unauthenticated API access (/version, /info, /_ping)
- Engine version, API version, and Git commit
- Host OS, architecture, kernel, and storage driver
- Container counts and daemon security options

**How to Execute:**
```bash
# Basic scan
nmap -p 2375,2376 --script docker-unauthenticated-api example.com

# Verbose output
nmap -p 2375,2376 --script docker-unauthenticated-api -v example.com
```

**Sample Output:**
```
| docker-unauthenticated-api:
|   Status: VULNERABLE - Unauthenticated Docker Daemon API Exposed
|   Risk Level: 🔴 CRITICAL
|   CVSS Score: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
|   Daemon Details:
|     Docker Engine Version: 24.0.7
|     Docker API Version: 1.43
|     Operating System: linux
|     Architecture: x86_64
|     Kernel Version: 5.15.0-89-generic
|   Host & Cluster Metrics:
|     Total Containers: 8
|     Running Containers: 5
|     Storage Driver: overlay2
|   Remediation:
|     1. TLS Authentication: Enable mutual TLS (mTLS) with --tlsverify.
|     2. Network Binding: Never bind TCP 2375 to 0.0.0.0.
```

---

#### 2. **docker-container-inspect-secrets** - Container Environment Secrets Leak
**Description:** Queries /containers/json and inspects container metadata to detect exposed plaintext secrets, passwords, tokens, and private keys in environment variables (Config.Env) and labels.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Exposed database passwords in environment variables
- Cloud credentials (AWS_SECRET_ACCESS_KEY, API tokens)
- JWT secrets and private keys in container metadata
- Automatic secret masking in output

**How to Execute:**
```bash
# Basic scan
nmap -p 2375,2376 --script docker-container-inspect-secrets example.com

# Inspect up to 50 containers
nmap -p 2375 --script docker-container-inspect-secrets --script-args docker-container-inspect-secrets.max_containers=50 example.com
```

**Sample Output:**
```
| docker-container-inspect-secrets:
|   Status: VULNERABLE - 4 sensitive variables discovered across inspected containers
|   Risk Level: 🔴 CRITICAL
|   Leaked Container Secrets:
|     db_prod (ID: 3b1a8f9c1024):
|       ENV: POSTGRES_PASSWORD = su************1!
|       ENV: DATABASE_URL = po************5432
|     api_service (ID: f4e8201a9100):
|       ENV: AWS_SECRET_ACCESS_KEY = AK************89
```

---

#### 3. **docker-privileged-containers** - Privileged Container & Capability Audit
**Description:** Identifies containers running with HostConfig.Privileged: true, dangerous Linux capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN), disabled Seccomp/AppArmor confinement, or direct host device mappings.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Privileged execution flag (Privileged: true)
- Dangerous Linux capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_NET_ADMIN)
- Disabled containment profiles (apparmor=unconfined, seccomp=unconfined)
- Direct physical disk or memory device bindings (/dev/kmem, /dev/sda)

**How to Execute:**
```bash
nmap -p 2375,2376 --script docker-privileged-containers example.com
nmap -p 2375 --script docker-privileged-containers -v example.com
```

**Sample Output:**
```
| docker-privileged-containers:
|   Status: VULNERABLE - 2 container(s) running with excessive privileges or dangerous capabilities
|   Risk Level: 🔴 CRITICAL
|   Over-Privileged Containers:
|     worker_node (ID: a1b2c3d4e5f6):
|       🔴 CRITICAL: Privileged mode is ENABLED (HostConfig.Privileged: true)
|       🔴 CAPABILITY: SYS_ADMIN (Allows mounting filesystems and direct container breakout)
```

---

#### 4. **docker-volume-host-mounts** - Sensitive Host Filesystem Mounts
**Description:** Audits container mount points and binds for dangerous host root or sensitive directory exposures (/var/run/docker.sock, /, /etc, /root, /proc, /sys).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Docker socket mounts (/var/run/docker.sock)
- Host root filesystem binds (/)
- Sensitive host configuration mounts (/etc/shadow, /etc, /root)
- Read-Write vs. Read-Only mount permissions

**How to Execute:**
```bash
nmap -p 2375,2376 --script docker-volume-host-mounts example.com
```

**Sample Output:**
```
| docker-volume-host-mounts:
|   Status: VULNERABLE - 1 container(s) mount critical host filesystem paths or Docker socket
|   Risk Level: 🔴 CRITICAL
|   Dangerous Mounts:
|     monitoring_agent (ID: 7a8b9c0d1e2f):
|       🔴 CRITICAL [Read-Write (RW)] Host '/var/run/docker.sock' -> Container '/var/run/docker.sock' (Docker socket mount allows full host takeover)
```

---

#### 5. **docker-registry-unauth-catalog** - Unauthenticated Docker Registry Catalog Access
**Description:** Detects open Docker Registry v2 services and enumerates private container repositories hosted in the registry via /v2/_catalog without authentication.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Unauthenticated /v2/ base endpoint access
- Private repository catalog enumeration (/v2/_catalog)
- Repository discovery count and image listings

**How to Execute:**
```bash
nmap -p 5000,443 --script docker-registry-unauth-catalog example.com
```

**Sample Output:**
```
| docker-registry-unauth-catalog:
|   Status: VULNERABLE - Unauthenticated Docker Registry v2 Catalog Access
|   Risk Level: 🔴 CRITICAL
|   CVSS Score: 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
|   Total Repositories Discovered: 12
|   Exposed Repositories:
|     - internal/payment-gateway
|     - internal/auth-service
|     - proprietary/core-engine
```

---

#### 6. **docker-registry-manifest-leak** - Image Manifest & Build Secret Extraction
**Description:** Downloads image manifests (/v2/<repo>/manifests/<tag>) to inspect container layer history, Dockerfile build commands, and baked-in secret strings.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Layer history and v1Compatibility metadata
- Commands executed during image build (RUN, CMD)
- Embedded secrets and environment variables in image layers

**How to Execute:**
```bash
nmap -p 5000 --script docker-registry-manifest-leak --script-args docker-registry-manifest-leak.repo=frontend example.com
```

**Sample Output:**
```
| docker-registry-manifest-leak:
|   Status: VULNERABLE - Sensitive environment variables or secrets discovered in manifest metadata.
|   Risk Level: 🟡 MEDIUM
|   Repository: frontend
|   Inspected Tag: latest
|   Manifest Leak Findings:
|     EXPOSED SECRET IN LAYER ENV: NPM_TOKEN=npm_9921004812a
```

---

#### 7. **docker-registry-delete-allowed** - Unauthenticated Registry Image Deletion
**Description:** Tests whether a Docker Registry v2 endpoint permits unauthenticated DELETE requests on manifests and tags, allowing remote image wiping.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- DELETE method enablement (REGISTRY_STORAGE_DELETE_ENABLED)
- Unauthenticated manifest deletion permissions
- CI/CD pipeline destruction and DoS risk

**How to Execute:**
```bash
nmap -p 5000 --script docker-registry-delete-allowed example.com
```

**Sample Output:**
```
| docker-registry-delete-allowed:
|   Status: VULNERABLE - Unauthenticated DELETE accepted by router (HTTP 404 Not Found)
|   Risk Level: 🟠 HIGH
|   DELETE Probe Status Code: 404
|   Assessment: The registry evaluated DELETE without requiring authentication.
```

---

#### 8. **docker-swarm-node-leak** - Docker Swarm Topology & Join Token Leak
**Description:** Queries /swarm, /nodes, and /services on an accessible Docker daemon to extract Swarm cluster topology, node hostnames, and manager/worker join tokens.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Swarm cluster state and Cluster ID
- Worker and Manager Join Tokens (permits node injection)
- Node hostnames, roles, states, and deployed service lists

**How to Execute:**
```bash
nmap -p 2375,2377 --script docker-swarm-node-leak example.com
```

**Sample Output:**
```
| docker-swarm-node-leak:
|   Status: VULNERABLE - Docker Swarm Cluster Configuration Exposed
|   Risk Level: 🟡 MEDIUM
|   Cluster ID: 9v1k3m4n5o6p7q8r9s0t
|   Join Tokens:
|     Manager Join Token (CRITICAL): SWMTKN-1-49nj1...-20v1...
|     Worker Join Token: SWMTKN-1-49nj1...-88aa...
|   Swarm Nodes:
|     Host: swarm-mgr-01 (ID: node_01, Role: manager, State: ready)
```

---

#### 9. **docker-build-cache-leak** - Intermediate Build Cache & ARG Secret Leak
**Description:** Enumerates dangling image layers (/images/json?all=1) and inspects image build history (/images/{id}/history) for residual build arguments (ARG) and build-time secret injection.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Dangling and intermediate image layers (<none>:<none>)
- Build arguments (ARG) leaked in image history
- Temporary build commands with curl/wget tokens

**How to Execute:**
```bash
nmap -p 2375 --script docker-build-cache-leak example.com
```

**Sample Output:**
```
| docker-build-cache-leak:
|   Status: VULNERABLE - 2 suspicious build layer commands discovered containing potential secrets
|   Risk Level: 🟡 MEDIUM
|   Exposed Build History:
|     [sha256:4a1b] | ARG GITHUB_TOKEN=ghp_910283019283
```

---

#### 10. **docker-network-host-mode** - Host Network Mode & Wildcard Binding Audit
**Description:** Identifies containers configured with host networking (NetworkMode: host) or publishing ports to 0.0.0.0 without localhost binding.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Host network mode enablement (bypasses container isolation)
- Ports published on 0.0.0.0 vs. 127.0.0.1
- Network namespace sharing risks

**How to Execute:**
```bash
nmap -p 2375 --script docker-network-host-mode example.com
```

**Sample Output:**
```
| docker-network-host-mode:
|   Status: VULNERABLE - Found containers with host networking mode or public wildcard port bindings
|   Risk Level: 🟡 MEDIUM
|   Host Network Mode Containers:
|     - net_debugger (ID: 3a9c8e102f)
|   Exposed 0.0.0.0 Port Mappings:
|     - redis_cache -> 0.0.0.0:6379 (maps to container port 6379)
```

---

#### 11. **docker-cgroup-resource-limits** - Missing Resource Constraints Audit
**Description:** Audits containers for missing cgroup resource limits (Memory: 0, PidsLimit: 0 / -1, CpuShares: 0) and disabled OOM killer.

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Memory ceiling (Memory: 0 MB = unbounded)
- PID ceiling (PidsLimit: unbounded = vulnerable to fork bomb)
- CPU quota enforcement
- OOM killer disablement status (OomKillDisable: true)

**How to Execute:**
```bash
nmap -p 2375 --script docker-cgroup-resource-limits example.com
```

**Sample Output:**
```
| docker-cgroup-resource-limits:
|   Status: VULNERABLE - 3 container(s) lack critical cgroup resource constraints
|   Risk Level: 🟡 MEDIUM
|   Unconstrained Containers:
|     app_web (ID: 5e6f7a8b9c):
|       - No Memory Limit (Memory: 0 MB)
|       - No Process Limit (PidsLimit: unbounded - vulnerable to fork-bomb)
```

---

#### 12. **docker-daemon-security-opts** - Daemon Hardening & Security Profiles
**Description:** Evaluates daemon security options in /info for mandatory access control (AppArmor/SELinux), Seccomp filtering, and User Namespace remapping (userns-remap).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- AppArmor / SELinux presence
- Seccomp default syscall filter status
- User Namespace remapping (userns-remap / rootless mode)
- LiveRestoreEnabled configuration

**How to Execute:**
```bash
nmap -p 2375 --script docker-daemon-security-opts example.com
```

**Sample Output:**
```
| docker-daemon-security-opts:
|   Status: VULNERABLE / HARDENING DEFICIENT - Missing critical daemon security profiles
|   Risk Level: 🟡 MEDIUM
|   Active Security Options: name=seccomp,profile=default
|   Identified Weaknesses:
|     - MISSING: No Mandatory Access Control (neither AppArmor nor SELinux is active on daemon)
|     - MISSING: User Namespaces (userns-remap / rootless) not active; container root is real host root (UID 0)
```

---

#### 13. **docker-debug-pprof-exposure** - Go Runtime Profiling & Debug Leak
**Description:** Probes Docker daemon endpoints for exposed Go pprof debug interfaces (/debug/pprof, /debug/vars) that leak memory allocations, stack traces, and command lines.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Go runtime pprof menu (/debug/pprof/)
- Goroutine stack traces (/debug/pprof/goroutine)
- Command line arguments (/debug/pprof/cmdline)
- Expvar internal runtime metrics (/debug/vars)

**How to Execute:**
```bash
nmap -p 2375,2376 --script docker-debug-pprof-exposure example.com
```

**Sample Output:**
```
| docker-debug-pprof-exposure:
|   Status: VULNERABLE - 3 Go debug profiling endpoint(s) exposed to untrusted requests
|   Risk Level: 🟠 HIGH
|   Exposed Endpoints:
|     - /debug/pprof/ (HTTP 200) - Pprof Index
|     - /debug/pprof/goroutine?debug=1 (HTTP 200) - Goroutine execution stack traces
|     - /debug/pprof/cmdline (HTTP 200) - Process command line arguments
|   Leaked Command Line: dockerd -H tcp://0.0.0.0:2375 --debug
```

---

#### 14. **docker-event-stream-exposure** - Real-Time Event Stream Surveillance
**Description:** Checks if the Docker daemon /events streaming endpoint is accessible unauthenticated, allowing real-time surveillance of container workload actions.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Streaming API accessibility (/events)
- Real-time container creation, execution, and destroy event leaks
- Operational telemetry surveillance

**How to Execute:**
```bash
nmap -p 2375 --script docker-event-stream-exposure example.com
```

**Sample Output:**
```
| docker-event-stream-exposure:
|   Status: VULNERABLE - Unauthenticated Docker /events streaming API exposed
|   Risk Level: 🟡 MEDIUM
|   Assessment: The Docker daemon accepted an unauthenticated connection to the real-time event stream.
```

---

#### 15. **docker-socket-proxy-misconfig** - Socket Proxy Mutating Verb Filter Bypass
**Description:** Tests Docker socket security proxies for method-filtering misconfigurations, checking whether POST, PUT, and DELETE endpoints are blocked or improperly forwarded.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- POST /containers/create filter enforcement
- POST /build image compilation filter enforcement
- DELETE /containers resource destruction filter enforcement

**How to Execute:**
```bash
nmap -p 2375,8080 --script docker-socket-proxy-misconfig example.com
```

**Sample Output:**
```
| docker-socket-proxy-misconfig:
|   Status: VULNERABLE - Socket proxy permits mutating HTTP verbs (POST/DELETE) to Docker daemon
|   Risk Level: 🔴 CRITICAL
|   Method Filter Evaluation:
|     POST /containers/create (Container Spawning): 🔴 PERMITTED (Proxy forwards POST)
|     POST /build (Image Compilation): BLOCKED / PROTECTED (HTTP 403)
|     DELETE /containers (Resource Deletion): 🔴 PERMITTED (Proxy forwards DELETE)
```

---

#### 16. **docker-version-cve-fingerprint** - Known Container Vulnerability Fingerprint
**Description:** Fingerprints Docker Engine, containerd, and runc versions against known historical container escape vulnerabilities (CVE-2024-21626, CVE-2019-5736, CVE-2019-14271, CVE-2020-13401).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Docker version extraction and SemVer comparison
- CVE-2024-21626 (Leaky Vessels runc workdir breakout)
- CVE-2019-5736 (runc root overwrite container breakout)
- CVE-2019-14271 (docker cp library injection)

**How to Execute:**
```bash
nmap -p 2375 --script docker-version-cve-fingerprint example.com
```

**Sample Output:**
```
| docker-version-cve-fingerprint:
|   Risk Level: 🟢 LOW
|   Docker Version: 18.09.1
|   API Version: 1.39
|   Potential Known CVE Matches:
|     - CVE-2019-5736: runc container breakout allowing malicious container to overwrite host runc binary
```

---

</details>

<details>
<summary><b>🔮 GraphQL API Security Audits — 16 scripts (click to expand)</b></summary>

## 🔮 GraphQL API Security Audits

### Category Overview
GraphQL endpoint security audits focusing on production schema introspection leaks, batch query brute-force amplification, field suggestion reverse engineering, alias multiplication DoS, depth/cost complexity limit bypasses, interactive IDE exposures, and unauthenticated mutation surfaces.

**Port:** 80/443/3000/4000/5000/8000/8080/8443 | **Protocol:** GraphQL over HTTP/WebSocket

---

### GraphQL Scripts List

#### 1. **graphql-introspection-enabled** - Schema Introspection Leak Detection
**Description:** Executes __schema and __type introspection queries to detect whether GraphQL introspection is enabled in production, mapping all queries, mutations, types, and input objects.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Full schema introspection support (__schema, __type)
- Query, Mutation, and Subscription root operation types
- Custom object types, scalar types, and exposed schema architecture

**How to Execute:**
```bash
# Basic scan
nmap -p 80,443 --script graphql-introspection-enabled example.com

# Custom path
nmap -p 8080 --script graphql-introspection-enabled --script-args graphql-introspection-enabled.path=/api/v1/graphql example.com
```

**Sample Output:**
```
| graphql-introspection-enabled:
|   Status: VULNERABLE - GraphQL Introspection is ENABLED in Production
|   Risk Level: 🔴 CRITICAL
|   CVSS Score: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
|   Endpoint: /graphql
|   Schema Architecture:
|     Query Root Type: Query
|     Mutation Root Type (Mutating APIs available): Mutation
|     Subscription Root Type (Real-time active): Subscription
|     Total Custom Types Discovered: 48
|     Sample Exposed Types: User, AdminAccount, PaymentMethod, Order, Token
```

---

#### 2. **graphql-field-suggestions** - Field Suggestion Schema Reverse Engineering
**Description:** Tests if a GraphQL endpoint returns didactic field suggestions ("Did you mean 'password'?") when supplied with typos on sensitive fields, enabling schema reverse engineering.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Didactic error messages ("Did you mean ...?")
- Schema field leakage despite disabled introspection
- Sensitive keyword suggestion triggers

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-field-suggestions example.com
```

**Sample Output:**
```
| graphql-field-suggestions:
|   Status: VULNERABLE - GraphQL Field Suggestions Leakage Detected
|   Risk Level: 🟡 MEDIUM
|   Endpoint: /graphql
|   Observed Suggestions:
|     - Probe 'passwrd' triggered suggestion: 'password'
|     - Probe 'auth_tkn' triggered suggestion: 'authToken'
```

---

#### 3. **graphql-batch-query-abuse** - Array Batch Query Brute-Force Amplification
**Description:** Tests whether a GraphQL server processes JSON array batch queries ([{}, {}, ...]) without batch size limits, allowing rate-limit bypass and credential stuffing amplification.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Array-based batch request parsing
- Concurrent query execution without per-request rate limits
- Rate-limiting and WAF threshold bypass vectors

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-batch-query-abuse example.com
```

**Sample Output:**
```
| graphql-batch-query-abuse:
|   Status: VULNERABLE - Array-based Batch Query Execution Allowed (15 queries executed simultaneously)
|   Risk Level: 🔴 CRITICAL
|   Endpoint: /graphql
|   Batch Size Tested: 15
|   Assessment: Attackers can execute credential stuffing and token guessing at 10x-100x amplification per HTTP connection.
```

---

#### 4. **graphql-circular-query-depth** - Query Depth Limiting & Recursion DoS
**Description:** Sends deeply nested circular/recursive queries to test if query depth limiting (e.g. graphql-depth-limit) is enforced or if arbitrary nesting is resolved.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Query AST depth validation
- Circular relationship traversal limits
- Exponential resolver execution DoS risk

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-circular-query-depth example.com
```

**Sample Output:**
```
| graphql-circular-query-depth:
|   Status: VULNERABLE - Deep Query Nesting Accepted (Depth 12 resolved without restriction)
|   Risk Level: 🟠 HIGH
|   Endpoint: /graphql
|   Assessment: The GraphQL engine does not enforce query depth limiting.
```

---

#### 5. **graphql-alias-overloading** - Alias Overloading & Computation Amplification
**Description:** Tests for field alias multiplication ({ a1: user, a2: user, ... a50: user }) to evaluate whether the server limits alias counts or executes all resolvers in parallel.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Alias count limit enforcement
- Multiplier resource consumption
- CPU / database worker exhaustion vectors

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-alias-overloading example.com
```

**Sample Output:**
```
| graphql-alias-overloading:
|   Status: VULNERABLE - Server resolved 50 aliased fields without restriction
|   Risk Level: 🔴 CRITICAL
|   Endpoint: /graphql
|   Alias Count Tested: 50
```

---

#### 6. **graphql-debug-trace-exposure** - Apollo Tracing & Debug Metric Leak
**Description:** Detects whether a GraphQL server returns sensitive debugging extensions (Apollo Tracing, exception stack traces, execution durations) in response payloads.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Apollo Tracing extension presence (extensions.tracing)
- Execution durations per resolver
- Database query latency and stack trace leaks

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-debug-trace-exposure example.com
```

**Sample Output:**
```
| graphql-debug-trace-exposure:
|   Status: VULNERABLE - Sensitive GraphQL Debugging Extensions Exposed in Responses
|   Risk Level: 🟡 MEDIUM
|   Endpoint: /graphql
|   Exposed Extensions:
|     - Apollo Tracing Extension (Execution timings, duration, and resolver paths exposed)
```

---

#### 7. **graphql-unauth-mutation-detection** - Unauthenticated Mutation Schema Discovery
**Description:** Discovers exposed mutating root operations (Mutation schema type) and checks whether state-altering operations are accessible without authentication tokens.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Exposed Mutation root operations
- Sensitive mutations (resetPassword, updateUser, deleteRecord, adminAction)
- Missing access control middleware on mutation schemas

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-unauth-mutation-detection example.com
```

**Sample Output:**
```
| graphql-unauth-mutation-detection:
|   Status: VULNERABLE - Unauthenticated Access to GraphQL Mutation Schema
|   Risk Level: 🔴 CRITICAL
|   Endpoint: /graphql
|   Total Exposed Mutations Discovered: 18
|   Sensitive High-Risk Mutations: 6
|   Sample High-Impact Operations:
|     - updateAccountPassword
|     - deleteUserRecord
|     - grantAdminRole
```

---

#### 8. **graphql-get-mutation-bypass** - GET Method Mutation Execution (CSRF Risk)
**Description:** Evaluates whether the GraphQL engine executes mutations submitted via HTTP GET query parameters, violating HTTP semantics and exposing the API to CSRF.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Mutation execution via HTTP GET
- CSRF vulnerability in browser contexts
- WAF POST-inspection bypass

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-get-mutation-bypass example.com
```

**Sample Output:**
```
| graphql-get-mutation-bypass:
|   Status: VULNERABLE - GraphQL Mutations Accepted via HTTP GET
|   Risk Level: 🟠 HIGH
|   Endpoint: /graphql
|   Assessment: The GraphQL engine successfully processed a mutation submitted over HTTP GET.
```

---

#### 9. **graphql-content-type-bypass** - Content-Type Parsing & CORS Preflight Bypass
**Description:** Tests if the GraphQL server accepts requests with text/plain, urlencoded, or missing Content-Type headers, enabling Cross-Site GraphQL Execution without CORS preflights.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- text/plain GraphQL query execution (CORS preflight bypass)
- application/x-www-form-urlencoded parsing
- Strict application/json enforcement

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-content-type-bypass example.com
```

**Sample Output:**
```
| graphql-content-type-bypass:
|   Status: VULNERABLE - Permissive Content-Type Parsing Enables Cross-Origin Bypass
|   Risk Level: 🟡 MEDIUM
|   Content-Type Acceptance Matrix:
|     text/plain (CORS Preflight Bypass): 🔴 ACCEPTED (Vulnerable to Cross-Origin Simple Request CSRF)
|     application/x-www-form-urlencoded: 🔴 ACCEPTED
```

---

#### 10. **graphql-schema-directive-leak** - Custom Security Directives & RBAC Leak
**Description:** Audits custom schema directives (__schema { directives { ... } }) to uncover internal authorization policies, role definitions (@auth, @hasRole, @admin), and hidden decorators.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Custom directive names and arguments
- RBAC policy leakage (@hasRole, @auth, @admin)
- Security boundary architecture mapping

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-schema-directive-leak example.com
```

**Sample Output:**
```
| graphql-schema-directive-leak:
|   Status: VULNERABLE - Internal Access Control & Authorization Directives Exposed
|   Risk Level: 🟡 MEDIUM
|   Custom Directives: auth, hasRole, rateLimit, internal
|   Security & RBAC Directives: auth, hasRole
```

---

#### 11. **graphql-ide-exposure** - Interactive GraphQL IDE Console Exposure
**Description:** Detects exposed interactive developer IDE interfaces (GraphiQL, GraphQL Playground, Altair GraphQL Client, Apollo Sandbox) enabled in production environments.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- GraphiQL web console presence
- GraphQL Playground web console presence
- Altair GraphQL client interface
- Apollo Studio Sandbox exposure

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-ide-exposure example.com
```

**Sample Output:**
```
| graphql-ide-exposure:
|   Status: VULNERABLE - Interactive GraphQL IDE Interface Exposed in Production
|   Risk Level: 🟡 MEDIUM
|   Exposed Interfaces:
|     - /graphiql -> GraphiQL (Official IDE) (HTTP 200)
|     - /playground -> GraphQL Playground (Prisma) (HTTP 200)
```

---

#### 12. **graphql-subscription-websocket** - Unauthenticated WebSocket Subscription
**Description:** Evaluates whether a GraphQL WebSocket subscription endpoint accepts unauthenticated WebSocket upgrades using graphql-ws or subscriptions-transport-ws protocols.

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- WebSocket protocol upgrade handshake
- graphql-ws / subscriptions-transport-ws subprotocols
- Token validation during HTTP upgrade phase

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-subscription-websocket example.com
```

**Sample Output:**
```
| graphql-subscription-websocket:
|   Status: VULNERABLE - Unauthenticated GraphQL WebSocket Subscription Endpoint Exposed
|   Risk Level: 🟡 MEDIUM
|   WebSocket Endpoint: /subscriptions
|   Negotiated Protocol: graphql-ws
```

---

#### 13. **graphql-error-info-disclosure** - Error Verbosity & Backend Stack Disclosure
**Description:** Probes GraphQL endpoints with malformed syntax and invalid types to audit error messages for database syntax errors, ORM traces (Prisma, Sequelize), and filesystem paths.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- SQL syntax and database dialect disclosures
- ORM framework leaks (Prisma, Sequelize, TypeORM)
- Absolute filesystem path leaks
- Unhandled runtime stack traces

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-error-info-disclosure example.com
```

**Sample Output:**
```
| graphql-error-info-disclosure:
|   Status: VULNERABLE - Sensitive Backend Technology Stack Leaked in Error Responses
|   Risk Level: 🟡 MEDIUM
|   Disclosed Details:
|     - [ORM / Framework] Matched pattern 'PrismaClient' during Invalid Field & Argument
|     - [Filesystem Path] Matched pattern '/usr/src/app' during Syntax Error
```

---

#### 14. **graphql-persisted-queries-audit** - Automatic Persisted Queries (APQ) Audit
**Description:** Audits Automatic Persisted Queries (APQ) support and checks whether arbitrary unpersisted raw queries are simultaneously accepted, bypassing query allowlists.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- APQ protocol support (extensions.persistedQuery)
- Dual mode enforcement (whether raw queries bypass allowlists)
- Persisted query cache poisoning risk

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-persisted-queries-audit example.com
```

**Sample Output:**
```
| graphql-persisted-queries-audit:
|   Status: VULNERABLE - Incomplete Persisted Query Enforcement (Raw Queries Permitted)
|   Risk Level: 🟡 MEDIUM
|   APQ Extension Support: ENABLED (PersistedQueryNotFound returned)
|   Raw Query Fallback Allowed: true
```

---

#### 15. **graphql-cost-analysis-bypass** - Query Cost Analysis & Complexity Audit
**Description:** Evaluates whether the GraphQL server implements Query Cost Analysis to reject computationally heavy requests or processes high-complexity multi-field queries unrestricted.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Query complexity calculation
- Multi-field expansion rate-limiting
- Algorithmic complexity exhaustion protection

**How to Execute:**
```bash
nmap -p 80,443 --script graphql-cost-analysis-bypass example.com
```

**Sample Output:**
```
| graphql-cost-analysis-bypass:
|   Status: VULNERABLE - No Query Cost / Complexity Analysis Enforced
|   Risk Level: 🟡 MEDIUM
|   Assessment: The server executed a multi-field heavy query without calculating complexity.
```

---

#### 16. **graphql-endpoint-discovery** - Comprehensive GraphQL Path Discovery
**Description:** Probes 35+ standard and framework-specific GraphQL endpoints (/graphql, /api/graphql, /query, /gql, /hasura/v1/graphql) with GET/POST to identify active interfaces.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- 35+ standard and uncommon GraphQL URL paths
- HTTP method acceptance matrix (POST, GET, OPTIONS)
- GraphQL engine fingerprinting

**How to Execute:**
```bash
nmap -p 80,443,8080 --script graphql-endpoint-discovery example.com
```

**Sample Output:**
```
| graphql-endpoint-discovery:
|   Status: IDENTIFIED - One or more active GraphQL API endpoints discovered on target.
|   Risk Level: 🟢 LOW
|   Total Discovered GraphQL Endpoints: 2
|   Discovered Endpoints:
|     - /api/v1/graphql (HTTP 200, POST accepted)
|     - /graphql (HTTP 200, POST accepted)
```

---

</details>

<details>
<summary><b>📡 MQTT & IoT Protocol Security Audits — 16 scripts (click to expand)</b></summary>

## 📡 MQTT & IoT Protocol Security Audits

### Category Overview
MQTT and IoT messaging protocol security audits focusing on unauthenticated broker access, wildcard subscription data harvesting (#), internal $SYS metric exposure, default IoT credentials, anonymous message publishing, retained message persistence, cleartext credential transmission, and mutual TLS (mTLS) client certificate enforcement.

**Port:** 1883/8883/1884/8884 | **Protocol:** MQTT 3.1, MQTT 3.1.1, MQTT 5.0 (Binary Wire Protocol)

---

### MQTT Scripts List

#### 1. **mqtt-unauthenticated-broker** - Open Anonymous MQTT Broker Detection
**Description:** Sends an MQTT 3.1.1 CONNECT packet without credentials and evaluates the broker CONNACK response. Detects open brokers that allow unauthenticated clients to connect and access all topics.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Anonymous connection acceptance (CONNACK Return Code 0x00)
- Unauthenticated access to all publish/subscribe topics
- Session Present flag and connection parameters

**How to Execute:**
```bash
# Basic scan
nmap -p 1883,8883 --script mqtt-unauthenticated-broker example.com

# Verbose output
nmap -p 1883,8883 --script mqtt-unauthenticated-broker -v example.com
```

**Sample Output:**
```
| mqtt-unauthenticated-broker:
|   Status: VULNERABLE - Unauthenticated Anonymous MQTT Broker Access Permitted
|   Risk Level: 🔴 CRITICAL
|   CVSS Score: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
|   Protocol: MQTT 3.1.1
|   CONNACK Return Code: 0x00 (Connection Accepted (No authentication required))
|   Session Present Flag: false
|   Remediation: Disable anonymous broker access (allow_anonymous false in Mosquitto).
```

---

#### 2. **mqtt-wildcard-subscribe-all** - Root Wildcard '#' Topic Subscription
**Description:** Connects anonymously, subscribes to the root multi-level wildcard topic (#), and intercepts live message broadcasts to audit sensitive IoT telemetry, device commands, and credentials.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Unrestricted wildcard subscription permissions (#)
- Inbound live message interception
- Payload data sanitization and inspection

**How to Execute:**
```bash
# Listen for 5 seconds
nmap -p 1883 --script mqtt-wildcard-subscribe-all example.com

# Listen for 10 seconds with custom message limit
nmap -p 1883 --script mqtt-wildcard-subscribe-all --script-args mqtt-wildcard-subscribe-all.timeout=10,mqtt-wildcard-subscribe-all.max_messages=20 example.com
```

**Sample Output:**
```
| mqtt-wildcard-subscribe-all:
|   Status: VULNERABLE - Unrestricted Wildcard Subscription Allowed on '#'
|   Risk Level: 🔴 CRITICAL
|   Subscribed Topic: # (All topics)
|   Captured Live Messages Count: 3
|   Captured Topic Feeds:
|     - Topic: sensors/livingroom/temp | Payload: {"temp": 21.5, "humidity": 45}
|     - Topic: vehicles/fleet_01/gps | Payload: {"lat": 37.7749, "lon": -122.4194}
|     - Topic: devices/smartplug_04/cmd | Payload: STATE=ON
```

---

#### 3. **mqtt-sys-topic-leak** - Broker Internal $SYS Topic Hierarchy Leak
**Description:** Subscribes to the internal $SYS/# system hierarchy and harvests operational details: broker software version, uptime, connected client count, and memory statistics.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Broker version ($SYS/broker/version)
- System uptime and active client counts
- Message throughput and memory usage statistics

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-sys-topic-leak example.com
```

**Sample Output:**
```
| mqtt-sys-topic-leak:
|   Status: VULNERABLE - $SYS Hierarchy Accessible (5 metrics retrieved)
|   Risk Level: 🟡 MEDIUM
|   Disclosed $SYS Metrics:
|     broker/version: mosquitto version 2.0.18
|     broker/uptime: 86420 seconds
|     broker/clients/connected: 42
|     broker/subscriptions/count: 128
```

---

#### 4. **mqtt-default-credentials** - Default & Factory Credential Testing
**Description:** Tests common default and factory IoT broker credentials (admin/admin, root/root, mosquitto/mosquitto, emqx/public, hivemq/hivemq, user/password) against the MQTT authentication service.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Default administrative credentials
- Common vendor default account pairs
- Non-destructive authentication verification

**How to Execute:**
```bash
nmap -p 1883,8883 --script mqtt-default-credentials example.com
```

**Sample Output:**
```
| mqtt-default-credentials:
|   Status: VULNERABLE - 1 default credential pair(s) accepted by MQTT broker
|   Risk Level: 🔴 CRITICAL
|   Valid Default Credentials:
|     - Username: 'admin' | Password: 'password'
```

---

#### 5. **mqtt-anonymous-publish-test** - Anonymous Message Injection & Write Audit
**Description:** Connects anonymously and attempts to PUBLISH a diagnostic QoS 1 test message to an audit topic, evaluating whether unauthenticated users possess write/command injection permissions.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Anonymous PUBLISH packet processing
- Broker PUBACK acknowledgment
- Unauthorized IoT actuation / command injection vectors

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-anonymous-publish-test example.com
```

**Sample Output:**
```
| mqtt-anonymous-publish-test:
|   Status: VULNERABLE - Anonymous Clients Permitted to PUBLISH Messages (PUBACK Received)
|   Risk Level: 🔴 CRITICAL
|   Tested Topic: audit/nmap/write-check
|   PUBACK Status: Acknowledged by Broker (Write access confirmed)
```

---

#### 6. **mqtt-retained-message-harvest** - Retained Message & Secret Harvesting
**Description:** Harvests retained messages (RETAIN=1) stored persistently on the broker to identify lingering secrets, passwords, device state dumps, and network tokens.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Persisted retained message harvesting
- Sensitive configuration payloads in broker memory
- Lingering device registration records

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-retained-message-harvest example.com
```

**Sample Output:**
```
| mqtt-retained-message-harvest:
|   Status: DISCOVERED - 2 retained message(s) extracted from broker storage
|   Risk Level: 🟡 MEDIUM
|   Total Retained Messages Captured: 2
|   Retained Messages:
|     - Topic: 'config/wifi' | Data: 'SSID=CorpIoT;PSK=WpaSecretKey2026'
|     - Topic: 'devices/gateway/status' | Data: 'firmware=v1.4.2;ip=192.168.10.50'
```

---

#### 7. **mqtt-cleartext-credential-risk** - Cleartext Credential Transmission
**Description:** Checks whether the broker accepts authentication credentials over unencrypted TCP (port 1883) without requiring TLS encryption, exposing passwords to passive sniffing.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Plain TCP credential processing
- Lack of TLS enforcement on authentication ports
- Passive network eavesdropping vulnerability

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-cleartext-credential-risk example.com
```

**Sample Output:**
```
| mqtt-cleartext-credential-risk:
|   Status: VULNERABLE - MQTT Broker Processes Cleartext Credentials over Plain TCP
|   Risk Level: 🟡 MEDIUM
|   Transport Layer Security: NONE (Plaintext TCP Port 1883)
|   CONNACK Return Code: 0x04
|   Assessment: The broker evaluated credentials submitted over an unencrypted channel.
```

---

#### 8. **mqtt-clientid-spoof-hijack** - Client ID Collision & Session Hijacking
**Description:** Connects with well-known/privileged Client IDs (gateway, bridge, admin, master) to test if the broker permits Client ID spoofing and terminates existing client sessions.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Arbitrary Client ID acceptance without certificate binding
- Session takeover and connection termination (kicking)
- Denial of Service against critical IoT gateways

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-clientid-spoof-hijack example.com
```

**Sample Output:**
```
| mqtt-clientid-spoof-hijack:
|   Status: VULNERABLE - 3 fixed/privileged Client ID(s) accepted anonymously
|   Risk Level: 🟠 HIGH
|   Accepted Client IDs: gateway, bridge, admin
|   Assessment: An attacker can hijack existing sessions and repeatedly disconnect legitimate IoT devices.
```

---

#### 9. **mqtt-topic-permission-bypass** - Sensitive Topic ACL Enforcement Audit
**Description:** Tests topic Access Control List (ACL) enforcement by attempting subscription to restricted administrative paths (admin/#, system/#, control/#, config/#) after anonymous connect.

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- SUBACK return codes (0x00 granted vs 0x80 failure)
- Administrative topic path restrictions
- Missing topic authorization rules

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-topic-permission-bypass example.com
```

**Sample Output:**
```
| mqtt-topic-permission-bypass:
|   Status: VULNERABLE - 2 sensitive topic paths granted subscription without ACL restriction
|   Risk Level: 🟡 MEDIUM
|   Unrestricted Sensitive Topics:
|     - Topic: 'control/#' (SUBACK: 0x00 Granted)
|     - Topic: 'config/#' (SUBACK: 0x00 Granted)
```

---

#### 10. **mqtt-will-message-injection** - Last Will & Testament (LWT) Spoofing
**Description:** Connects with custom Last Will and Testament (LWT) topics to test if the broker validates publisher ACLs during CONNECT or accepts arbitrary will definitions.

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Last Will topic registration handling
- Pre-connection ACL enforcement on will topics
- Fake emergency/offline status injection risk

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-will-message-injection example.com
```

**Sample Output:**
```
| mqtt-will-message-injection:
|   Status: VULNERABLE - Arbitrary Last Will & Testament Registration Permitted
|   Risk Level: 🟡 MEDIUM
|   Tested Will Topic: system/status/audit_lwt_check
```

---

#### 11. **mqtt-keepalive-dos-tolerance** - KeepAlive=0 & Zombie Connection DoS
**Description:** Tests how the broker handles KeepAlive=0 (disabled inactivity timeout), checking whether maximum server keepalive limits are enforced or if idle connections persist indefinitely.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- KeepAlive=0 negotiation handling
- Server Keep Alive property override
- Idle connection table exhaustion risk

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-keepalive-dos-tolerance example.com
```

**Sample Output:**
```
| mqtt-keepalive-dos-tolerance:
|   Status: VULNERABLE - Broker Accepts KeepAlive=0 (Infinite Idle Timeout Allowed)
|   Risk Level: 🟡 MEDIUM
|   KeepAlive Tested: 0 seconds (Infinite Inactivity Allowed)
```

---

#### 12. **mqtt-qos2-handshake-audit** - QoS 2 Exactly-Once State Machine Conformance
**Description:** Executes the complete four-step QoS 2 state machine (PUBLISH -> PUBREC -> PUBREL -> PUBCOMP) to test broker protocol conformance, state retention, and timeouts.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Four-way QoS 2 handshake execution
- PUBREC, PUBREL, and PUBCOMP packet exchanges
- State-machine timeout and protocol conformance

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-qos2-handshake-audit example.com
```

**Sample Output:**
```
| mqtt-qos2-handshake-audit:
|   Status: CONFORMANT - Broker fully and correctly implements MQTT QoS 2 Exactly-Once state machine.
|   Risk Level: 🟡 MEDIUM
|   QoS 2 Handshake State Machine:
|     Step 1: PUBLISH (QoS 2): SENT
|     Step 2: PUBREC Received: SUCCESS (0x50)
|     Step 3: PUBREL: SENT (0x62)
|     Step 4: PUBCOMP Received: SUCCESS (0x70)
```

---

#### 13. **mqtt-protocol-version-support** - Protocol Version Matrix (3.1, 3.1.1, 5.0)
**Description:** Probes the MQTT broker with MQTT 3.1 (MQIsdp), MQTT 3.1.1 (Standard), and MQTT 5.0 CONNECT headers to record supported specifications and version downgrade behavior.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- MQTT 3.1 legacy MQIsdp support
- MQTT 3.1.1 standard support
- MQTT 5.0 enhanced protocol support

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-protocol-version-support example.com
```

**Sample Output:**
```
| mqtt-protocol-version-support:
|   Risk Level: 🟢 LOW
|   Protocol Version Matrix:
|     MQTT 3.1 (Legacy MQIsdp): SUPPORTED (Connection Accepted)
|     MQTT 3.1.1 (Standard): SUPPORTED (Connection Accepted)
|     MQTT 5.0 (Modern OASIS): SUPPORTED (Connection Accepted)
```

---

#### 14. **mqtt-packet-size-limit** - Maximum Packet Size & Oversized Header Handling
**Description:** Sends malformed and oversized Variable Length Integer packet headers to evaluate broker maximum packet size limits and defense against memory exhaustion.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Maximum packet size enforcement
- 4-byte Variable Length Integer handling (256 MB declared length)
- Connection termination upon oversized input

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-packet-size-limit example.com
```

**Sample Output:**
```
| mqtt-packet-size-limit:
|   Status: SECURE - Broker immediately terminated connection upon receiving oversized packet length header.
|   Risk Level: 🟡 MEDIUM
|   Oversized Length Header: 256 MB Variable Length Integer (0xFF 0xFF 0xFF 0x7F)
```

---

#### 15. **mqtt-tls-client-cert-check** - Mutual TLS (mTLS) Client Certificate Enforcement
**Description:** Initiates a TLS handshake on secure MQTT port 8883 without supplying a client certificate, checking whether mutual TLS (mTLS) is strictly enforced or optional.

**Risk Level:** 🟠 HIGH | **Category:** Defensive

**What it checks:**
- Client certificate verification requirement
- Anonymous TLS handshake acceptance
- Certificate authority (CA) trust enforcement

**How to Execute:**
```bash
nmap -p 8883 --script mqtt-tls-client-cert-check example.com
```

**Sample Output:**
```
| mqtt-tls-client-cert-check:
|   Status: VULNERABLE - Mutual TLS (mTLS) is NOT Enforced on Secure MQTT Port
|   Risk Level: 🟠 HIGH
|   Client Certificate Enforcement: OPTIONAL / DISABLED (Anonymous TLS Handshake Succeeded)
|   Assessment: The broker completed the TLS handshake without demanding or validating a client certificate.
```

---

#### 16. **mqtt-broker-fingerprint** - Broker Engine & Implementation Fingerprinting
**Description:** Analyzes MQTT 3.1.1 and MQTT 5.0 CONNACK response bytes, Reason Codes, User Properties, and disconnect timing to fingerprint broker software (Mosquitto, EMQX, HiveMQ, VerneMQ).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- MQTT 5.0 CONNACK User Properties
- Implementation-specific disconnect timing
- Broker engine identification (Mosquitto, EMQX, HiveMQ, VerneMQ)

**How to Execute:**
```bash
nmap -p 1883,8883 --script mqtt-broker-fingerprint example.com
```

**Sample Output:**
```
| mqtt-broker-fingerprint:
|   Risk Level: 🟢 LOW
|   Detected Broker Engine: Eclipse Mosquitto
```

---

</details>

## 🎯 Comprehensive Scanning Scenarios

### Scenario 1: Full Infrastructure Security Audit

```bash
nmap -p 21,53,80,139,443,445,1433,1883,2375,2376,3306,5000,5432,6379,8883,27017 \
  --script 'http-*,dns-*,smb-*,ssl-*,ftp-*,mongodb-*,mssql-*,mysql-*,postgresql-*,redis-*,docker-*,graphql-*,mqtt-*' \
  --script-args \
    dns-zone-transfer-check.domain=example.com,\
    dns-subdomain-enum.domain=example.com \
  -sV -v \
  -oX full-infrastructure-audit.xml \
  example.com
```

### Scenario 1b: Docker Daemon & Container Ecosystem Audit

```bash
nmap -p 2375,2376,5000,2377,4243 \
  --script 'docker-*' \
  -v \
  -oA docker-audit \
  example.com
```

### Scenario 1c: GraphQL API Security Assessment

```bash
nmap -p 80,443,3000,4000,5000,8000,8080,8443 \
  --script 'graphql-*' \
  -v \
  -oA graphql-audit \
  example.com
```

### Scenario 1d: MQTT & IoT Broker Security Assessment

```bash
nmap -p 1883,8883,1884,8884 \
  --script 'mqtt-*' \
  -v \
  -oA mqtt-audit \
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
| **Docker** | docker-unauthenticated-api | 2375/2376 | 🔴 CRITICAL | Vulnerability | REST API |
| **Docker** | docker-container-inspect-secrets | 2375/2376 | 🔴 CRITICAL | Vulnerability | Secrets |
| **Docker** | docker-privileged-containers | 2375/2376 | 🔴 CRITICAL | Vulnerability | Privileges |
| **Docker** | docker-volume-host-mounts | 2375/2376 | 🔴 CRITICAL | Vulnerability | Mounts |
| **Docker** | docker-registry-unauth-catalog | 5000 | 🔴 CRITICAL | Vulnerability | Registry |
| **Docker** | docker-registry-manifest-leak | 5000 | 🟡 MEDIUM | Discovery | Manifests |
| **Docker** | docker-registry-delete-allowed | 5000 | 🟠 HIGH | Vulnerability | Deletion |
| **Docker** | docker-swarm-node-leak | 2375/2377 | 🟡 MEDIUM | Discovery | Swarm |
| **Docker** | docker-build-cache-leak | 2375 | 🟡 MEDIUM | Discovery | Build Cache |
| **Docker** | docker-network-host-mode | 2375 | 🟡 MEDIUM | Defensive | Networking |
| **Docker** | docker-cgroup-resource-limits | 2375 | 🟡 MEDIUM | Vulnerability | cgroups |
| **Docker** | docker-daemon-security-opts | 2375 | 🟡 MEDIUM | Defensive | Hardening |
| **Docker** | docker-debug-pprof-exposure | 2375 | 🟠 HIGH | Vulnerability | Debug/pprof |
| **Docker** | docker-event-stream-exposure | 2375 | 🟡 MEDIUM | Discovery | Events |
| **Docker** | docker-socket-proxy-misconfig | 2375/8080 | 🔴 CRITICAL | Vulnerability | Socket Proxy |
| **Docker** | docker-version-cve-fingerprint | 2375 | 🟢 LOW | Discovery | CVE Match |
| **GraphQL** | graphql-introspection-enabled | 80/443 | 🔴 CRITICAL | Vulnerability | Introspection |
| **GraphQL** | graphql-field-suggestions | 80/443 | 🟡 MEDIUM | Discovery | Suggestions |
| **GraphQL** | graphql-batch-query-abuse | 80/443 | 🔴 CRITICAL | Vulnerability | Batching |
| **GraphQL** | graphql-circular-query-depth | 80/443 | 🟠 HIGH | Vulnerability | Query Depth |
| **GraphQL** | graphql-alias-overloading | 80/443 | 🔴 CRITICAL | Vulnerability | Aliases |
| **GraphQL** | graphql-debug-trace-exposure | 80/443 | 🟡 MEDIUM | Discovery | Tracing |
| **GraphQL** | graphql-unauth-mutation-detection | 80/443 | 🔴 CRITICAL | Vulnerability | Mutations |
| **GraphQL** | graphql-get-mutation-bypass | 80/443 | 🟠 HIGH | Vulnerability | GET Method |
| **GraphQL** | graphql-content-type-bypass | 80/443 | 🟡 MEDIUM | Defensive | Content-Type |
| **GraphQL** | graphql-schema-directive-leak | 80/443 | 🟡 MEDIUM | Discovery | Directives |
| **GraphQL** | graphql-ide-exposure | 80/443 | 🟡 MEDIUM | Discovery | Web IDE |
| **GraphQL** | graphql-subscription-websocket | 80/443 | 🟡 MEDIUM | Vulnerability | WebSocket |
| **GraphQL** | graphql-error-info-disclosure | 80/443 | 🟡 MEDIUM | Discovery | Errors |
| **GraphQL** | graphql-persisted-queries-audit | 80/443 | 🟡 MEDIUM | Defensive | APQ |
| **GraphQL** | graphql-cost-analysis-bypass | 80/443 | 🟡 MEDIUM | Defensive | Complexity |
| **GraphQL** | graphql-endpoint-discovery | 80/443 | 🟢 LOW | Discovery | Endpoints |
| **MQTT** | mqtt-unauthenticated-broker | 1883/8883 | 🔴 CRITICAL | Vulnerability | Auth |
| **MQTT** | mqtt-wildcard-subscribe-all | 1883/8883 | 🔴 CRITICAL | Vulnerability | Wildcard |
| **MQTT** | mqtt-sys-topic-leak | 1883/8883 | 🟡 MEDIUM | Discovery | $SYS Topics |
| **MQTT** | mqtt-default-credentials | 1883/8883 | 🔴 CRITICAL | Vulnerability | Credentials |
| **MQTT** | mqtt-anonymous-publish-test | 1883/8883 | 🔴 CRITICAL | Vulnerability | Publish |
| **MQTT** | mqtt-retained-message-harvest | 1883/8883 | 🟡 MEDIUM | Discovery | Retained Data |
| **MQTT** | mqtt-cleartext-credential-risk | 1883 | 🟡 MEDIUM | Defensive | Cleartext Auth |
| **MQTT** | mqtt-clientid-spoof-hijack | 1883/8883 | 🟠 HIGH | Vulnerability | Client ID |
| **MQTT** | mqtt-topic-permission-bypass | 1883/8883 | 🟡 MEDIUM | Vulnerability | Topic ACL |
| **MQTT** | mqtt-will-message-injection | 1883/8883 | 🟡 MEDIUM | Vulnerability | Last Will |
| **MQTT** | mqtt-keepalive-dos-tolerance | 1883/8883 | 🟡 MEDIUM | Defensive | KeepAlive |
| **MQTT** | mqtt-qos2-handshake-audit | 1883/8883 | 🟡 MEDIUM | Defensive | QoS 2 |
| **MQTT** | mqtt-protocol-version-support | 1883/8883 | 🟢 LOW | Discovery | Versions |
| **MQTT** | mqtt-packet-size-limit | 1883/8883 | 🟡 MEDIUM | Defensive | Packet Size |
| **MQTT** | mqtt-tls-client-cert-check | 8883 | 🟠 HIGH | Defensive | mTLS |
| **MQTT** | mqtt-broker-fingerprint | 1883/8883 | 🟢 LOW | Discovery | Fingerprint |

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

## 🧪 Testing

This project includes a local, Docker-based test environment so scripts can be validated against real (deliberately misconfigured) targets instead of just reviewed for correctness.

> ⚠️ These targets are intentionally insecure. Only run this on your own machine, on an isolated network. Never expose these ports outside `localhost`.

### Quick start

```bash
# Start the test targets (HTTP, FTP, Redis)
docker compose up -d

# Run a script against the HTTP target
nmap -p 8080 --script ./HTTP/http-security-headers.nse localhost

# Run a script against the FTP target
nmap -p 2121 --script ./FTP/ftp-anonymous-login.nse localhost

# Tear down when done
docker compose down
```

| Target | Port | Simulates |
|---|---|---|
| `http-target` | `localhost:8080` | Plain HTTP server, no security headers |
| `ftp-target` | `localhost:2121` | Anonymous FTP login enabled |
| `redis-target` | `localhost:6380` | Redis with authentication disabled |

Full instructions, expected outputs per script category, and how to add a test target for a new script are documented in **[TESTING.md](TESTING.md)**.

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
4. Test your script locally with `nmap --script-help <your-script>` and against a real/lab target — see **[Testing](#-testing)** for the local Docker environment
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

- **Total Scripts:** 103
- **HTTP Scripts:** 10 (port 80/443)
- **DNS Scripts:** 9 (port 53)
- **SMB Scripts:** 9 (port 139/445)
- **SSL/TLS Scripts:** 9 (port 443)
- **Database Scripts:** 9 (port 1433/3306/5432/6379/27017)
- **FTP Scripts:** 9 (port 21)
- **Docker Scripts:** 16 (port 2375/2376/5000/2377/4243)
- **GraphQL Scripts:** 16 (port 80/443/3000/4000/8080)
- **MQTT / IoT Scripts:** 16 (port 1883/8883/1884)
- **Total Lines of Code:** 11,492 Lua
- **Security Checks:** 390+
- **Supported Nmap:** 7.40+

---

**Quick Start:**
```bash
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cp -r Nmap-NSE-Script-Collection/{HTTP,DNS,SMB,SSL-TLS,DATABASE,FTP,DOCKER,GRAPHQL,MQTT}/* ~/.nmap/scripts/
nmap --script-updatedb
nmap -p 21,53,80,139,443,445,1433,1883,2375,2376,3306,5000,5432,6379,8883,27017 --script 'http-*,dns-*,smb-*,ssl-*,ftp-*,mongodb-*,mssql-*,mysql-*,postgresql-*,redis-*,docker-*,graphql-*,mqtt-*' example.com
```

**All 103 scripts are production-ready and immediately deployable!** 🚀

---

<p align="center">Made with 🛡️ for the defensive security community — ⭐ star this repo if it's useful to you!</p>
