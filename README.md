# Nmap-NSE-Script-Collection

## Project Overview

A comprehensive collection of custom **Nmap NSE (Nmap Scripting Engine)** scripts specialized in **defensive security auditing** of web servers, DNS infrastructure, and SSL/TLS endpoints. These scripts are engineered to detect common security misconfigurations, including missing critical HTTP security headers, inadequate cookie protection flags, weak cryptographic algorithms, DNS vulnerabilities, and other prevalent security issues frequently overlooked in production environments.

**Project Language:** Lua 100%

---

## 📋 Project Contents

### 📁 Directory Structure

```
Nmap-NSE-Script-Collection/
├── HTTP/                                   # HTTP Protocol Security Audits
│   ├── http-security-headers.nse           # Security Headers Audit
│   ├── http-cookie-flags.nse               # Cookie Protection Audit
│   ├── http-cors-config.nse                # CORS Configuration Analysis
│   ├── http-cache-audit.nse                # HTTP Caching Strategy Check
│   ├── http-error-disclosure.nse           # Information Disclosure Detection
│   ├── http-methods-enum.nse               # HTTP Methods Enumeration
│   ├── http-server-fingerprint.nse         # Server Technology Detection
│   ├── http-dir-listing.nse                # Directory Listing Detection
│   ├── http-robots-sitemap.nse             # robots.txt & Sitemap Analysis
│   └── http-trace-method.nse               # HTTP TRACE Method Vulnerability Check
│
├── DNS/                                    # DNS Infrastructure Security Audits
│   ├── dns-zone-transfer-check.nse         # Zone Transfer Vulnerability (AXFR)
│   ├── dns-subdomain-enum.nse              # Subdomain Enumeration via Brute Force
│   ├── dns-recursion-check.nse             # Open Resolver Detection
│   ├── dns-amplification-risk.nse          # DNS Amplification Attack Risk
│   ├── dns-cache-snooping.nse              # DNS Cache Snooping Detection
│   ├── dns-srv-enum.nse                    # SRV Record Enumeration
│   ├── dns-txt-spf-dmarc-audit.nse         # SPF/DMARC Email Security Audit
│   ├── dns-soa-consistency-check.nse       # SOA Record Consistency Validation
│   ├── dns-wildcard-detector.nse           # Wildcard DNS Record Detection
│   └── dns-amplification-risk.nse          # DNS Amplification Vulnerability Check
│
├── SSL-TLS/                                # SSL/TLS Protocol Security Audits
│   ├── ssl-weak-ciphers.nse                # Weak Cipher Suite Detection
│   ├── ssl-protocol-versions.nse           # TLS Version Support Analysis
│   ├── ssl-cert-info.nse                   # Certificate Information Extraction
│   ├── ssl-cert-expiry.nse                 # Certificate Expiry Validation
│   ├── ssl-cert-hostname-mismatch.nse      # Hostname Verification Check
│   ├── ssl-cert-weak-signature.nse         # Weak Signature Algorithm Detection
│   ├── ssl-compression-check.nse           # TLS Compression Vulnerability Check
│   ├── ssl-ocsp-stapling.nse               # OCSP Stapling Configuration Audit
│   └── ssl-secure-renegotiation.nse        # TLS Secure Renegotiation Verification
│
└── README.md                               # This file
```

---

## 🚀 Installation

### Prerequisites

- **Nmap** v7.40 or newer
- **Lua** runtime (included with Nmap)
- **Network access** to target systems (local or remote)
- Administrative/root privileges (optional, for system-wide installation)

### Installation Steps

#### 1. **Clone the Repository**

```bash
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cd Nmap-NSE-Script-Collection
```

#### 2. **Locate Your Nmap NSE Scripts Directory**

Depending on your operating system:

**Linux/macOS:**
```bash
# User-level default location
~/.nmap/scripts

# System-wide location (requires root)
/usr/share/nmap/scripts
```

**Windows:**
```
C:\Program Files\Nmap\scripts
```

**Verify Nmap installation:**
```bash
nmap --version
```

#### 3. **Copy Scripts to NSE Directory**

**Option A: Symbolic Link (Recommended)**

**Linux/macOS:**
```bash
# Create symlinks for easy updates
ln -s $(pwd)/HTTP ~/.nmap/scripts/custom-http
ln -s $(pwd)/DNS ~/.nmap/scripts/custom-dns
ln -s $(pwd)/SSL-TLS ~/.nmap/scripts/custom-ssl-tls

# Verify installation
ls -la ~/.nmap/scripts/ | grep custom
```

**Option B: Direct Copy**

**Linux/macOS:**
```bash
cp -r HTTP/* ~/.nmap/scripts/
cp -r DNS/* ~/.nmap/scripts/
cp -r SSL-TLS/* ~/.nmap/scripts/
chmod +x ~/.nmap/scripts/*.nse
```

**Windows (PowerShell - Run as Administrator):**
```powershell
# Method 1: Symbolic Link (Windows 10+)
$source = (Get-Location).Path
New-Item -ItemType SymbolicLink `
  -Path "C:\Program Files\Nmap\scripts\custom-http" `
  -Target "$source\HTTP" -Force

New-Item -ItemType SymbolicLink `
  -Path "C:\Program Files\Nmap\scripts\custom-dns" `
  -Target "$source\DNS" -Force

New-Item -ItemType SymbolicLink `
  -Path "C:\Program Files\Nmap\scripts\custom-ssl-tls" `
  -Target "$source\SSL-TLS" -Force

# Method 2: Direct Copy
Copy-Item -Path "HTTP\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "DNS\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
Copy-Item -Path "SSL-TLS\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
```

#### 4. **Update NSE Database**

```bash
nmap --script-updatedb
```

#### 5. **Verify Installation**

```bash
# Check if scripts are recognized
nmap --script-help http-security-headers
nmap --script-help dns-zone-transfer-check

# List all custom scripts
nmap --script-help | grep -E "(http-|dns-|ssl-)" | head -30
```

---

## 📖 Usage Guide

### Basic Syntax

```bash
nmap -p <PORT> --script <SCRIPT_NAME> [OPTIONS] <TARGET>
```

### Common Options

```bash
-p <port>              # Specify port(s)
-sV                    # Version detection
-sC                    # Default scripts
-v                     # Verbose output
-vv                    # Very verbose output
-oN <file>             # Normal output
-oX <file>             # XML output
-oG <file>             # Grepable output
-oA <file>             # All formats
```

---

## 🌐 HTTP Security Scripts

### 1. **http-security-headers** - Security Headers Audit

Comprehensive audit of HTTP security headers across multiple application paths. Evaluates both presence and quality of configurations.

**Headers Checked:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Embedder-Policy (COEP)
- Cross-Origin-Resource-Policy (CORP)
- X-XSS-Protection

**Basic Usage:**
```bash
nmap -p 80,443 --script http-security-headers example.com
```

**Advanced Usage:**
```bash
nmap -p 80,443 --script http-security-headers -v example.com
nmap -p 80,443 --script http-security-headers -sV example.com
nmap -p 80,443 --script http-security-headers 192.168.1.0/24
```

---

### 2. **http-cookie-flags** - Cookie Security Audit

Analyzes Set-Cookie headers for protective flags and secure configuration.

**Checks Performed:**
- Secure flag (HTTPS-only transmission)
- HttpOnly flag (XSS protection)
- SameSite attribute (CSRF protection)
- Domain scope analysis
- Expiry validation

**Usage:**
```bash
nmap -p 80,443 --script http-cookie-flags example.com
nmap -p 80,443 --script http-cookie-flags -vv example.com
```

---

### 3. **http-cors-config** - CORS Configuration Analysis

Evaluates Cross-Origin Resource Sharing (CORS) policies for overly permissive configurations.

```bash
nmap -p 80,443 --script http-cors-config example.com
```

---

### 4. **http-methods-enum** - HTTP Methods Enumeration

Identifies enabled HTTP methods and flags potentially dangerous ones.

```bash
nmap -p 80,443 --script http-methods-enum example.com
```

**Dangerous Methods Detected:**
- PUT (file upload/modification)
- DELETE (resource deletion)
- CONNECT (proxy tunneling)
- TRACE (HTTP request reflection)

---

### 5. **http-server-fingerprint** - Web Server Detection

Identifies web server technology, version, and associated information disclosure risks.

```bash
nmap -p 80,443 --script http-server-fingerprint example.com
```

---

### 6. **http-error-disclosure** - Error-Based Information Disclosure

Discovers sensitive information exposed through error messages.

```bash
nmap -p 80,443 --script http-error-disclosure example.com
```

---

### 7. **http-dir-listing** - Directory Listing Detection

Identifies accessible directories with enabled listing.

```bash
nmap -p 80,443 --script http-dir-listing example.com
```

---

### 8. **http-cache-audit** - HTTP Caching Strategy

Analyzes cache control headers and caching behavior.

```bash
nmap -p 80,443 --script http-cache-audit example.com
```

---

### 9. **http-robots-sitemap** - robots.txt & Sitemap Analysis

Extracts information from robots.txt and sitemap.xml files.

```bash
nmap -p 80,443 --script http-robots-sitemap example.com
```

---

### 10. **http-trace-method** - HTTP TRACE Method Vulnerability

Detects the HTTP TRACE method (XST vulnerability).

```bash
nmap -p 80,443 --script http-trace-method example.com
```

---

## 🔍 DNS Security Scripts

### 1. **dns-zone-transfer-check** - Zone Transfer Vulnerability (AXFR)

Attempts a full zone transfer (AXFR) to detect misconfigured DNS servers allowing unauthenticated transfers.

**Risk Level:** 🔴 **CRITICAL** - Exposes complete DNS zone data

**Usage:**
```bash
# Specify target domain
nmap -p 53 --script dns-zone-transfer-check \
  --script-args dns-zone-transfer-check.domain=example.com \
  <DNS_SERVER_IP>

# Example with specific DNS server
nmap -p 53 --script dns-zone-transfer-check \
  --script-args dns-zone-transfer-check.domain=example.com \
  8.8.8.8
```

**Sample Output:**
```
| dns-zone-transfer-check:
|   Domain tested: example.com
|   DNS response code: 0
|   Result: ZONE TRANSFER SUCCEEDED - 247 record(s) returned
|   Record types observed:
|     - A: 50
|     - MX: 5
|     - NS: 4
|     - CNAME: 15
```

---

### 2. **dns-subdomain-enum** - Subdomain Enumeration

Brute forces common subdomain labels to discover subdomains and their IP addresses.

**Common Subdomains Tested:** 50+ (www, mail, api, dev, admin, staging, etc.)

**Usage:**
```bash
nmap -p 53 --script dns-subdomain-enum \
  --script-args dns-subdomain-enum.domain=example.com \
  <DNS_SERVER_IP>

# Against public DNS
nmap -p 53 --script dns-subdomain-enum \
  --script-args dns-subdomain-enum.domain=example.com \
  8.8.8.8
```

**Sample Output:**
```
| dns-subdomain-enum:
|   Domain tested: example.com
|   Subdomain labels tried: 50
|   Resolved subdomains:
|     - www.example.com -> 93.184.216.34
|     - mail.example.com -> 93.184.216.35
|     - api.example.com -> 93.184.216.36
|     - admin.example.com -> 93.184.216.37
```

---

### 3. **dns-recursion-check** - Open Resolver Detection

Detects if a DNS server allows recursive queries for external domains (open resolver).

**Risk Level:** 🔴 **CRITICAL** - Can be abused for DNS amplification attacks

**Usage:**
```bash
nmap -p 53 --script dns-recursion-check <DNS_SERVER_IP>

# Example
nmap -p 53 --script dns-recursion-check 192.168.1.1
```

**Sample Output:**
```
| dns-recursion-check:
|   Open resolver behavior: LIKELY OPEN RESOLVER - server recursed and resolved external domains
|   Evidence:
|     - www.iana.org -> RA=1, rcode=0, 1 answer(s) returned (server resolved externally)
|     - a.root-servers.net -> RA=1, rcode=0, 1 answer(s) returned
```

---

### 4. **dns-amplification-risk** - DNS Amplification Attack Risk

Evaluates the potential for the DNS server to be used in amplification attacks.

```bash
nmap -p 53 --script dns-amplification-risk <DNS_SERVER_IP>
```

---

### 5. **dns-cache-snooping** - DNS Cache Snooping Detection

Detects if a DNS server allows cache snooping queries.

**Risk Level:** 🟡 **MEDIUM** - Can leak cached query information

```bash
nmap -p 53 --script dns-cache-snooping <DNS_SERVER_IP>
```

---

### 6. **dns-srv-enum** - SRV Record Enumeration

Enumerates SRV records for a domain (useful for identifying services like Kerberos, LDAP, SIP).

**Usage:**
```bash
nmap -p 53 --script dns-srv-enum \
  --script-args dns-srv-enum.domain=example.com \
  <DNS_SERVER_IP>
```

**Sample Output:**
```
| dns-srv-enum:
|   Domain: example.com
|   SRV Records Found:
|     - _kerberos._tcp: kdc1.example.com:88
|     - _ldap._tcp: ldap1.example.com:389
|     - _kerberos._udp: kdc1.example.com:88
```

---

### 7. **dns-txt-spf-dmarc-audit** - Email Security Records Audit

Analyzes SPF, DMARC, and other TXT records for email security configuration.

**Checks:**
- SPF record validation
- DMARC policy analysis
- DKIM configuration
- Domain verification records

**Usage:**
```bash
nmap -p 53 --script dns-txt-spf-dmarc-audit \
  --script-args dns-txt-spf-dmarc-audit.domain=example.com \
  <DNS_SERVER_IP>
```

**Sample Output:**
```
| dns-txt-spf-dmarc-audit:
|   Domain: example.com
|   SPF Record: v=spf1 include:sendgrid.net ~all
|   DMARC Policy: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
|   Configuration Status: SECURE
```

---

### 8. **dns-soa-consistency-check** - SOA Record Consistency

Validates SOA (Start of Authority) record consistency across authoritative nameservers.

```bash
nmap -p 53 --script dns-soa-consistency-check \
  --script-args dns-soa-consistency-check.domain=example.com \
  <DNS_SERVER_IP>
```

---

### 9. **dns-wildcard-detector** - Wildcard DNS Record Detection

Detects if a domain uses wildcard DNS records.

```bash
nmap -p 53 --script dns-wildcard-detector \
  --script-args dns-wildcard-detector.domain=example.com \
  <DNS_SERVER_IP>
```

---

### 10. **dns-amplification-risk** - DNS Amplification Risk Assessment

Comprehensive assessment of DNS amplification attack vulnerability.

```bash
nmap -p 53 --script dns-amplification-risk <DNS_SERVER_IP>
```

---

## 🔐 SSL/TLS Security Scripts

### 1. **ssl-weak-ciphers** - Weak Cipher Suite Detection

Identifies weak or deprecated TLS cipher suites accepted by the server.

**Weak Cipher Categories:**
- NULL ciphers (no encryption)
- Export-grade ciphers (40-bit)
- DES/3DES ciphers
- RC4 stream ciphers
- Anonymous Diffie-Hellman

**Usage:**
```bash
nmap -p 443 --script ssl-weak-ciphers example.com
```

---

### 2. **ssl-protocol-versions** - TLS Version Support

Audits supported TLS/SSL protocol versions.

**Versions Checked:**
- SSLv3 (deprecated)
- TLSv1.0 (deprecated)
- TLSv1.1 (weak)
- TLSv1.2 (secure)
- TLSv1.3 (recommended)

**Usage:**
```bash
nmap -p 443 --script ssl-protocol-versions example.com
```

---

### 3. **ssl-cert-info** - Certificate Information Extraction

Extracts detailed SSL/TLS certificate information.

```bash
nmap -p 443 --script ssl-cert-info example.com
```

---

### 4. **ssl-cert-expiry** - Certificate Expiry Validation

Monitors SSL certificate expiration dates.

```bash
nmap -p 443 --script ssl-cert-expiry example.com
```

---

### 5. **ssl-cert-hostname-mismatch** - Hostname Verification

Validates certificate hostname matches the target domain.

```bash
nmap -p 443 --script ssl-cert-hostname-mismatch example.com
```

---

### 6. **ssl-cert-weak-signature** - Weak Signature Algorithm Detection

Identifies certificates with weak signature algorithms.

```bash
nmap -p 443 --script ssl-cert-weak-signature example.com
```

---

### 7. **ssl-compression-check** - TLS Compression Vulnerability

Detects TLS compression enablement (CRIME vulnerability).

```bash
nmap -p 443 --script ssl-compression-check example.com
```

---

### 8. **ssl-ocsp-stapling** - OCSP Stapling Configuration

Validates OCSP stapling implementation.

```bash
nmap -p 443 --script ssl-ocsp-stapling example.com
```

---

### 9. **ssl-secure-renegotiation** - TLS Renegotiation Security

Verifies secure renegotiation support.

```bash
nmap -p 443 --script ssl-secure-renegotiation example.com
```

---

## 🎯 Comprehensive Scanning Scenarios

### Scenario 1: Full Infrastructure Security Audit

```bash
nmap -p 53,80,443 \
  --script http-security-headers,http-cookie-flags,http-cors-config,\
http-methods-enum,http-server-fingerprint,\
dns-zone-transfer-check,dns-subdomain-enum,dns-recursion-check,\
ssl-weak-ciphers,ssl-protocol-versions,ssl-cert-info,ssl-cert-expiry \
  --script-args dns-zone-transfer-check.domain=example.com,\
dns-subdomain-enum.domain=example.com \
  -sV -v \
  -oX security-audit.xml \
  example.com
```

### Scenario 2: DNS Infrastructure Audit

```bash
nmap -p 53 \
  --script 'dns-*' \
  --script-args dns-zone-transfer-check.domain=example.com,\
dns-subdomain-enum.domain=example.com \
  -v \
  8.8.8.8
```

### Scenario 3: Web Server Complete Audit

```bash
nmap -p 80,443 \
  --script 'http-*,ssl-*' \
  -sV -v \
  -oA web-audit \
  example.com
```

### Scenario 4: Quick Security Assessment

```bash
nmap -p 53,80,443 \
  --script http-security-headers,ssl-weak-ciphers,\
dns-zone-transfer-check,dns-recursion-check \
  --script-args dns-zone-transfer-check.domain=example.com \
  example.com
```

### Scenario 5: Batch Processing

```bash
cat > targets.txt << EOF
example.com
site1.com
site2.com
EOF

nmap -p 80,443 \
  --script http-security-headers,ssl-weak-ciphers \
  -iL targets.txt \
  -oX batch-results.xml
```

---

## 📊 Script Reference Tables

### HTTP Scripts

| Script Name | Port | Category | Threat Level |
|-------------|------|----------|--------------|
| http-security-headers | 80/443 | Defensive | MEDIUM |
| http-cookie-flags | 80/443 | Defensive | MEDIUM |
| http-cors-config | 80/443 | Discovery | MEDIUM |
| http-cache-audit | 80/443 | Defensive | LOW |
| http-error-disclosure | 80/443 | Discovery | MEDIUM |
| http-methods-enum | 80/443 | Discovery | MEDIUM |
| http-server-fingerprint | 80/443 | Discovery | LOW |
| http-dir-listing | 80/443 | Discovery | MEDIUM |
| http-robots-sitemap | 80/443 | Discovery | LOW |
| http-trace-method | 80/443 | Vulnerability | HIGH |

### DNS Scripts

| Script Name | Port | Category | Threat Level |
|-------------|------|----------|--------------|
| dns-zone-transfer-check | 53 | Vulnerability | CRITICAL |
| dns-subdomain-enum | 53 | Discovery | MEDIUM |
| dns-recursion-check | 53 | Vulnerability | CRITICAL |
| dns-amplification-risk | 53 | Vulnerability | HIGH |
| dns-cache-snooping | 53 | Discovery | MEDIUM |
| dns-srv-enum | 53 | Discovery | LOW |
| dns-txt-spf-dmarc-audit | 53 | Defensive | MEDIUM |
| dns-soa-consistency-check | 53 | Defensive | LOW |
| dns-wildcard-detector | 53 | Discovery | LOW |

### SSL/TLS Scripts

| Script Name | Port | Category | Threat Level |
|-------------|------|----------|--------------|
| ssl-weak-ciphers | 443 | Vulnerability | CRITICAL |
| ssl-protocol-versions | 443 | Discovery | HIGH |
| ssl-cert-info | 443 | Discovery | LOW |
| ssl-cert-expiry | 443 | Defensive | MEDIUM |
| ssl-cert-hostname-mismatch | 443 | Vulnerability | CRITICAL |
| ssl-cert-weak-signature | 443 | Vulnerability | HIGH |
| ssl-compression-check | 443 | Vulnerability | HIGH |
| ssl-ocsp-stapling | 443 | Defensive | LOW |
| ssl-secure-renegotiation | 443 | Defensive | MEDIUM |

---

## 🔍 Output Interpretation Guide

### Severity Levels

#### 🔴 **CRITICAL** - Immediate Action Required
- Weak ciphers accepted
- Zone transfers allowed
- Open DNS resolver
- Self-signed certificates
- Hostname mismatch
- HTTP TRACE enabled

#### 🟠 **HIGH** - High Priority
- Incomplete CSP
- Missing security headers
- Deprecated TLS versions
- Weak signatures

#### 🟡 **MEDIUM** - Medium Priority
- Weak policies
- Cache snooping
- Subdomain enumeration possible

#### 🟢 **LOW** - Informational
- Version disclosure
- Technology detection

---

## 🛠️ Troubleshooting

### Scripts Not Found

```bash
nmap --script-updatedb
nmap --script-help dns-zone-transfer-check
ls -la ~/.nmap/scripts/ | grep dns
```

### Connection Timeouts

```bash
nmap -p 53,80,443 \
  --script http-security-headers \
  --script-args http.timeout=30000 \
  --host-timeout 1h \
  example.com
```

### Permission Issues

```bash
chmod +x ~/.nmap/scripts/*.nse
chmod 755 ~/.nmap/scripts/
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

## 📞 Support

- **GitHub Issues:** Report bugs and feature requests
- **GitHub Discussions:** Share ideas and best practices
- **Nmap Documentation:** https://nmap.org/

---

## 📄 License

Licensed under the **same terms as Nmap**.
See [Nmap Legal](https://nmap.org/book/man-legal.html)

---

## 📊 Project Statistics

- **Total Scripts:** 30
- **HTTP Scripts:** 10
- **DNS Scripts:** 10
- **SSL/TLS Scripts:** 9
- **Security Checks:** 70+
- **Lines of Code:** 2,000+ Lua

---

**Quick Start:**
```bash
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cp -r Nmap-NSE-Script-Collection/{HTTP,DNS,SSL-TLS}/* ~/.nmap/scripts/
nmap --script-updatedb
nmap -p 80,443,53 --script 'http-*,dns-*,ssl-*' -v example.com
```

**All scripts are production-ready and immediately deployable!**
