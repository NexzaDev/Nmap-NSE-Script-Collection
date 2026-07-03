# Nmap-NSE-Script-Collection

## Project Overview

A comprehensive collection of custom **Nmap NSE (Nmap Scripting Engine)** scripts specialized in **defensive security auditing** of web servers and SSL/TLS endpoints. These scripts are engineered to detect common security misconfigurations, including missing critical HTTP security headers, inadequate cookie protection flags, weak cryptographic algorithms, and other prevalent vulnerabilities that are frequently overlooked in production environments.

**Project Language:** Lua 100%

---

## 📋 Project Contents

### 📁 Directory Structure

```
Nmap-NSE-Script-Collection/
├── HTTP/                          # HTTP Protocol Security Audits
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
├── SSL-TLS/                       # SSL/TLS Protocol Security Audits
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
└── README.md                      # This file
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
ln -s $(pwd)/SSL-TLS ~/.nmap/scripts/custom-ssl-tls

# Verify installation
ls -la ~/.nmap/scripts/ | grep custom
```

**Option B: Direct Copy**

**Linux/macOS:**
```bash
cp -r HTTP/* ~/.nmap/scripts/
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
  -Path "C:\Program Files\Nmap\scripts\custom-ssl-tls" `
  -Target "$source\SSL-TLS" -Force

# Method 2: Direct Copy
Copy-Item -Path "HTTP\*" -Destination "C:\Program Files\Nmap\scripts\" -Recurse -Force
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

# List all custom scripts
nmap --script-help | grep -E "(http-|ssl-)" | head -20
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
# Verbose output
nmap -p 80,443 --script http-security-headers -v example.com

# With version detection
nmap -p 80,443 --script http-security-headers -sV example.com

# Multiple targets
nmap -p 80,443 --script http-security-headers 192.168.1.0/24

# Save results
nmap -p 80,443 --script http-security-headers -oX results.xml example.com
```

**Sample Output:**
```
| http-security-headers:
|   Paths checked: 15
|   Headers missing on all checked paths:
|     - Strict-Transport-Security
|     - Content-Security-Policy
|   Headers present (first observed value):
|     - X-Frame-Options: DENY
|     - X-Content-Type-Options: nosniff
|   Weak or incomplete configurations:
|     - Strict-Transport-Security (seen at /login): max-age=3600 is below recommended minimum
```

**Interpretation:**
- ✅ All security headers present and properly configured = Best practice compliance
- ⚠️ Missing headers = Potential vulnerabilities to common attacks
- 🔴 Weak configurations = Reduced protection effectiveness

---

### 2. **http-cookie-flags** - Cookie Security Audit

Analyzes Set-Cookie headers for protective flags and secure configuration across common application paths.

**Checks Performed:**
- Secure flag (HTTPS-only transmission)
- HttpOnly flag (XSS protection)
- SameSite attribute (CSRF protection)
- Domain scope analysis
- Expiry validation
- Sensitive cookie detection (session, auth, token patterns)

**Basic Usage:**
```bash
nmap -p 80,443 --script http-cookie-flags example.com
```

**Detailed Analysis:**
```bash
# Verbose output with all details
nmap -p 80,443 --script http-cookie-flags -vv example.com

# Custom paths
nmap -p 80,443 --script http-cookie-flags --script-args \
  http.paths="{/admin,/api,/dashboard}" example.com
```

**Sample Output:**
```
| http-cookie-flags:
|   Flagged cookies:
|     - PHPSESSID (seen at /login, sensitive=true) -> 
|       missing Secure flag; missing HttpOnly flag
|     - auth_token (seen at /api, sensitive=true) -> 
|       missing SameSite attribute
|   Cookies with adequate flags:
|     - _ga (seen at /) -> Secure=true HttpOnly=true SameSite=Strict
|     - _gid (seen at /) -> Secure=true HttpOnly=true SameSite=Strict
|   Total cookies inspected: 12
```

**Risk Assessment:**
- 🔴 **CRITICAL:** Session/auth cookies missing Secure or HttpOnly
- 🟠 **HIGH:** Missing SameSite attribute on sensitive cookies
- 🟡 **MEDIUM:** Persistent expiry on authentication cookies

---

### 3. **http-cors-config** - CORS Configuration Analysis

Evaluates Cross-Origin Resource Sharing (CORS) policies for overly permissive configurations.

```bash
nmap -p 80,443 --script http-cors-config example.com
```

**Checks:**
- Wildcard origin (*) allowance
- Credential transmission with flexible origins
- Method restrictions
- Header restrictions

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

**Detection:**
- Server software identification
- Version extraction
- Framework detection
- Information leakage assessment

---

### 6. **http-error-disclosure** - Error-Based Information Disclosure

Discovers sensitive information exposed through error messages and exception handling.

```bash
nmap -p 80,443 --script http-error-disclosure example.com
```

**Detects:**
- Stack traces
- Database error messages
- Path disclosure
- Configuration details

---

### 7. **http-dir-listing** - Directory Listing Detection

Identifies accessible directories with enabled listing (index generation).

```bash
nmap -p 80,443 --script http-dir-listing example.com
```

---

### 8. **http-cache-audit** - HTTP Caching Strategy

Analyzes cache control headers and caching behavior.

```bash
nmap -p 80,443 --script http-cache-audit example.com
```

**Checks:**
- Cache-Control directives
- Expires headers
- ETag usage
- Sensitive data caching

---

### 9. **http-robots-sitemap** - robots.txt & Sitemap Analysis

Extracts information from robots.txt and sitemap.xml files.

```bash
nmap -p 80,443 --script http-robots-sitemap example.com
```

---

### 10. **http-trace-method** - HTTP TRACE Method Vulnerability

Detects and validates the HTTP TRACE method (XST vulnerability).

```bash
nmap -p 80,443 --script http-trace-method example.com
```

---

## 🔐 SSL/TLS Security Scripts

### 1. **ssl-weak-ciphers** - Weak Cipher Suite Detection

Identifies weak or deprecated TLS cipher suites accepted by the server.

**Weak Cipher Categories Tested:**
- NULL ciphers (no encryption at all)
- Export-grade ciphers (40-bit encryption)
- DES/3DES ciphers (deprecated block ciphers)
- RC4 stream ciphers (known vulnerabilities)
- Anonymous Diffie-Hellman (no authentication)

**Basic Usage:**
```bash
nmap -p 443 --script ssl-weak-ciphers example.com
```

**Verbose Analysis:**
```bash
nmap -p 443 --script ssl-weak-ciphers -v example.com
```

**Sample Output:**
```
| ssl-weak-ciphers:
|   Weak cipher groups ACCEPTED by server:
|     - RC4 ciphers -> server negotiated TLS_RSA_WITH_RC4_128_SHA
|     - DES / 3DES ciphers -> server negotiated TLS_RSA_WITH_3DES_EDE_CBC_SHA
|   Weak cipher groups rejected:
|     - NULL ciphers (no encryption)
|     - Export-grade ciphers
|     - Anonymous Diffie-Hellman ciphers
```

**Risk Level:** 🔴 **CRITICAL** - Weak ciphers allow cryptographic attacks

---

### 2. **ssl-protocol-versions** - TLS Version Support

Audits supported TLS/SSL protocol versions and identifies deprecated implementations.

**Versions Checked:**
- SSLv3 (deprecated, security issues)
- TLSv1.0 (weak, deprecated)
- TLSv1.1 (weak, deprecated)
- TLSv1.2 (secure, baseline)
- TLSv1.3 (recommended, latest security)

**Usage:**
```bash
nmap -p 443 --script ssl-protocol-versions example.com
```

**Sample Output:**
```
| ssl-protocol-versions:
|   Supported Versions:
|     - TLSv1.0 (WEAK - DEPRECATED)
|     - TLSv1.1 (WEAK - DEPRECATED)
|     - TLSv1.2 (SECURE)
|     - TLSv1.3 (SECURE - RECOMMENDED)
|   Recommendation: Disable TLSv1.0 and TLSv1.1
```

---

### 3. **ssl-cert-info** - Certificate Information Extraction

Extracts and displays detailed SSL/TLS certificate information.

```bash
nmap -p 443 --script ssl-cert-info example.com
```

**Information Extracted:**
- Subject/Issuer details
- Public key information
- Validity dates
- Alternative names (SANs)
- Key usage extensions
- Certificate chain

---

### 4. **ssl-cert-expiry** - Certificate Expiry Validation

Monitors SSL certificate expiration dates and provides renewal alerts.

```bash
nmap -p 443 --script ssl-cert-expiry example.com
```

**Output Example:**
```
| ssl-cert-expiry:
|   Subject: CN=example.com
|   Issuer: CN=Let's Encrypt Authority X3
|   Expires: 2024-08-15
|   Days until expiry: 45
|   Status: WARNING - Certificate expires within 60 days
```

---

### 5. **ssl-cert-hostname-mismatch** - Hostname Verification

Validates certificate hostname matches the target domain.

```bash
nmap -p 443 --script ssl-cert-hostname-mismatch example.com
```

**Risk Level:** 🔴 **CRITICAL** - Mismatches enable MITM attacks

---

### 6. **ssl-cert-weak-signature** - Weak Signature Algorithm Detection

Identifies certificates signed with weak or deprecated algorithms.

```bash
nmap -p 443 --script ssl-cert-weak-signature example.com
```

**Weak Algorithms Detected:**
- MD5 (cryptographically broken)
- SHA-1 (collision attacks possible)
- SHA-256 with small key sizes

---

### 7. **ssl-compression-check** - TLS Compression Vulnerability

Detects TLS compression enablement (CRIME vulnerability risk).

```bash
nmap -p 443 --script ssl-compression-check example.com
```

**Risk:** 🔴 Compression combined with HTTPS can leak sensitive data

---

### 8. **ssl-ocsp-stapling** - OCSP Stapling Configuration

Validates OCSP stapling implementation for certificate status verification.

```bash
nmap -p 443 --script ssl-ocsp-stapling example.com
```

---

### 9. **ssl-secure-renegotiation** - TLS Renegotiation Security

Verifies secure renegotiation support (prevents CVE-2009-3555).

```bash
nmap -p 443 --script ssl-secure-renegotiation example.com
```

---

## 🎯 Comprehensive Scanning Scenarios

### Scenario 1: Full Web Server Security Audit

```bash
nmap -p 80,443 \
  --script http-security-headers,http-cookie-flags,http-cors-config,\
http-methods-enum,http-server-fingerprint,http-error-disclosure,\
ssl-weak-ciphers,ssl-protocol-versions,ssl-cert-info,ssl-cert-expiry \
  -sV -v \
  -oX security-audit.xml \
  -oN security-audit.txt \
  example.com
```

### Scenario 2: Quick Security Assessment

```bash
nmap -p 80,443 \
  --script http-security-headers,ssl-weak-ciphers,ssl-protocol-versions \
  example.com
```

### Scenario 3: Network-Wide HTTP Audit

```bash
nmap -p 80,443 \
  --script 'http-*' \
  192.168.1.0/24
```

### Scenario 4: SSL/TLS Comprehensive Check

```bash
nmap -p 443 \
  --script 'ssl-*' \
  -v \
  -oA tls-audit \
  example.com
```

### Scenario 5: Batch Processing Multiple Targets

```bash
# Create targets.txt with one target per line
cat > targets.txt << EOF
example.com
site1.com
site2.com
EOF

# Run audit on all targets
nmap -p 80,443 \
  --script http-security-headers,ssl-weak-ciphers \
  -iL targets.txt \
  -oX batch-results.xml
```

---

## 🔍 Output Interpretation Guide

### Severity Levels

#### 🔴 **CRITICAL** - Immediate Action Required
- Weak ciphers accepted by server
- Missing HSTS header
- Self-signed certificates in production
- HTTP TRACE method enabled
- Hostname certificate mismatch
- Compression vulnerability active

#### 🟠 **HIGH** - High Priority
- Incomplete CSP configuration
- Missing HttpOnly/Secure cookie flags
- Deprecated TLS versions enabled
- Weak signature algorithms
- Anonymous ciphers

#### 🟡 **MEDIUM** - Medium Priority
- Weak CSP directives
- Broad cookie domain scope
- Persistent session cookies
- Missing X-Frame-Options

#### 🟢 **LOW** - Informational
- Server version disclosure
- Directory listing discovery
- CORS configuration details

### Output Formats

**XML Output (Recommended for parsing):**
```bash
nmap -p 80,443 --script http-security-headers -oX results.xml example.com
```

**Normal Text Output:**
```bash
nmap -p 80,443 --script http-security-headers -oN results.txt example.com
```

**Grepable Format (for grep/awk):**
```bash
nmap -p 80,443 --script http-security-headers -oG results.grep example.com
```

**All Formats:**
```bash
nmap -p 80,443 --script http-security-headers -oA results example.com
# Generates: results.nmap, results.xml, results.gnmap
```

---

## 📊 Script Reference Table

### HTTP Scripts

| Script Name | Port | Category | Threat Level | Description |
|-------------|------|----------|--------------|-------------|
| http-security-headers | 80/443 | Defensive | MEDIUM | Audits HTTP security headers |
| http-cookie-flags | 80/443 | Defensive | MEDIUM | Analyzes cookie protection flags |
| http-cors-config | 80/443 | Discovery | MEDIUM | CORS policy analysis |
| http-cache-audit | 80/443 | Defensive | LOW | HTTP caching analysis |
| http-error-disclosure | 80/443 | Discovery | MEDIUM | Error-based info leakage |
| http-methods-enum | 80/443 | Discovery | MEDIUM | Dangerous HTTP methods |
| http-server-fingerprint | 80/443 | Discovery | LOW | Web server detection |
| http-dir-listing | 80/443 | Discovery | MEDIUM | Directory listing detection |
| http-robots-sitemap | 80/443 | Discovery | LOW | robots.txt analysis |
| http-trace-method | 80/443 | Vulnerability | HIGH | HTTP TRACE vulnerability |

### SSL/TLS Scripts

| Script Name | Port | Category | Threat Level | Description |
|-------------|------|----------|--------------|-------------|
| ssl-weak-ciphers | 443 | Vulnerability | CRITICAL | Weak cipher detection |
| ssl-protocol-versions | 443 | Discovery | HIGH | TLS version audit |
| ssl-cert-info | 443 | Discovery | LOW | Certificate details |
| ssl-cert-expiry | 443 | Defensive | MEDIUM | Expiry validation |
| ssl-cert-hostname-mismatch | 443 | Vulnerability | CRITICAL | Hostname verification |
| ssl-cert-weak-signature | 443 | Vulnerability | HIGH | Signature algorithm check |
| ssl-compression-check | 443 | Vulnerability | HIGH | CRIME vulnerability check |
| ssl-ocsp-stapling | 443 | Defensive | LOW | OCSP stapling validation |
| ssl-secure-renegotiation | 443 | Defensive | MEDIUM | Renegotiation security |

---

## 🛠️ Advanced Configuration

### Custom Script Arguments

```bash
# Increase HTTP timeout
nmap -p 80,443 --script http-security-headers \
  --script-args http.timeout=30000 \
  example.com

# Specify custom paths for HTTP scripts
nmap -p 80,443 --script http-cookie-flags \
  --script-args http.paths="{\"/admin\",\"/api/v1\",\"/login\"}" \
  example.com

# SSL timeout configuration
nmap -p 443 --script ssl-weak-ciphers \
  --script-args ssl.timeout=10000 \
  example.com
```

### Performance Tuning

```bash
# Parallel script execution
nmap -p 80,443 \
  --script http-security-headers,ssl-weak-ciphers \
  --max-parallelism 10 \
  example.com

# Fast/aggressive scans
nmap -p 80,443 \
  --script http-security-headers \
  -T4 \
  example.com
```

---

## 🐛 Troubleshooting

### Issue: Scripts Not Found

**Solution:**
```bash
# Update NSE database
nmap --script-updatedb

# Verify script path
nmap --script-help http-security-headers

# Check directory contents
ls -la ~/.nmap/scripts/ | grep http

# Windows verification
dir "C:\Program Files\Nmap\scripts" | findstr http
```

### Issue: Connection Timeouts

**Solution:**
```bash
# Increase timeout values
nmap -p 80,443 \
  --script http-security-headers \
  --script-args http.timeout=30000 \
  --host-timeout 1h \
  example.com
```

### Issue: Permission Denied

**Solution (Linux/macOS):**
```bash
# Fix script permissions
chmod +x ~/.nmap/scripts/*.nse
chmod 755 ~/.nmap/scripts/

# Re-update database
sudo nmap --script-updatedb
```

**Solution (Windows):**
```powershell
# Run PowerShell as Administrator
# Or use Command Prompt (cmd) as Administrator
```

### Issue: No Output from Scripts

**Debug:**
```bash
# Run with debugging
nmap -p 80,443 \
  --script http-security-headers \
  -d \
  -vv \
  example.com

# Check connectivity
nmap -p 80,443 \
  -sV \
  example.com
```

---

## 📚 Real-World Examples

### Example 1: Security Baseline Report

```bash
#!/bin/bash
# security-baseline.sh

TARGET="$1"
REPORT_DIR="./security-audit-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "[*] Running comprehensive security audit on $TARGET"
echo "[*] Results: $REPORT_DIR"

# Run all scripts
nmap -p 80,443 \
  --script 'http-*,ssl-*' \
  -sV -A \
  -oX "$REPORT_DIR/nmap-audit.xml" \
  -oN "$REPORT_DIR/nmap-audit.txt" \
  -oG "$REPORT_DIR/nmap-audit.gnmap" \
  "$TARGET"

echo "[+] Audit complete!"
echo "[+] Open $REPORT_DIR/nmap-audit.txt for results"
```

**Usage:**
```bash
chmod +x security-baseline.sh
./security-baseline.sh example.com
```

### Example 2: Continuous Monitoring Script

```bash
#!/bin/bash
# monitor-certs.sh

TARGETS="prod1.example.com prod2.example.com"
REPORT_DIR="./cert-monitoring"
mkdir -p "$REPORT_DIR"

for target in $TARGETS; do
  echo "[*] Checking $target..."
  nmap -p 443 \
    --script ssl-cert-expiry,ssl-cert-info \
    -oX "$REPORT_DIR/$target-$(date +%Y%m%d).xml" \
    "$target"
done

echo "[+] Monitoring complete"
```

### Example 3: Multi-Target Batch Scan

```bash
#!/bin/bash
# batch-scan.sh

# Create target list
cat > targets.txt << 'EOF'
example.com:80
api.example.com:443
cdn.example.com:443
EOF

# Process each target
while IFS=: read -r host port; do
  echo "[*] Scanning $host:$port"
  nmap -p "$port" \
    --script http-security-headers,ssl-weak-ciphers \
    -v \
    -oX "results-$host.xml" \
    "$host"
done < targets.txt

echo "[+] Batch scan complete"
```

---

## 🔄 Maintenance & Updates

### Keeping Scripts Current

```bash
# Update your clone
cd Nmap-NSE-Script-Collection
git pull origin main

# Reinstall scripts
cp -r HTTP/* ~/.nmap/scripts/
cp -r SSL-TLS/* ~/.nmap/scripts/

# Update NSE database
nmap --script-updatedb
```

### Checking Nmap Updates

```bash
# Check current version
nmap --version

# Update Nmap (depends on your package manager)
# macOS
brew upgrade nmap

# Ubuntu/Debian
sudo apt-get update && sudo apt-get upgrade nmap

# CentOS/RHEL
sudo yum update nmap
```

---

## 📋 Scripts Summary

### HTTP Headers Checked (http-security-headers)

| Header | Purpose | Recommended Value |
|--------|---------|-------------------|
| Strict-Transport-Security | Force HTTPS | max-age=31536000; includeSubDomains; preload |
| Content-Security-Policy | Prevent XSS | script-src 'self'; default-src 'none' |
| X-Frame-Options | Prevent clickjacking | DENY or SAMEORIGIN |
| X-Content-Type-Options | MIME sniffing | nosniff |
| Referrer-Policy | Referrer leakage | strict-origin-when-cross-origin |
| Permissions-Policy | Feature restrictions | Various |

### Cookie Attributes Checked (http-cookie-flags)

| Attribute | Purpose | Importance |
|-----------|---------|-----------|
| Secure | HTTPS-only transmission | CRITICAL |
| HttpOnly | XSS protection | CRITICAL |
| SameSite | CSRF protection | HIGH |
| Domain | Scope limitation | MEDIUM |
| Path | Path limitation | MEDIUM |
| Expiry | Session duration | MEDIUM |

### TLS Cipher Categories (ssl-weak-ciphers)

| Category | Strength | Detection |
|----------|----------|-----------|
| NULL Ciphers | None | Detected and flagged |
| Export-Grade | 40-bit | Detected and flagged |
| DES/3DES | Weak | Detected and flagged |
| RC4 | Broken | Detected and flagged |
| Anonymous DH | No auth | Detected and flagged |

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-script`)
3. Commit your changes (`git commit -am 'Add new security check'`)
4. Push to the branch (`git push origin feature/new-script`)
5. Open a Pull Request

### Script Development Guidelines

- Use Lua NSE framework conventions
- Include comprehensive descriptions
- Add meaningful audit categories
- Provide clear output formatting
- Test against multiple targets

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** These scripts are intended for:
- ✅ **Authorized security testing** on systems you own or have permission to test
- ✅ **Defensive security audits** of your own infrastructure
- ✅ **Educational purposes** in controlled environments
- ✅ **Compliance verification** with your organization's security policies

**PROHIBITED USES:**
- ❌ Scanning systems **without explicit authorization**
- ❌ **Malicious** or **unethical** purposes
- ❌ Violation of **applicable laws** and regulations
- ❌ Unauthorized **network testing**

**Disclaimer:** The author assumes no liability for misuse or damage caused by these scripts. Users are solely responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.

---

## 📞 Support & Documentation

- **GitHub Issues:** Report bugs and request features
- **GitHub Discussions:** Share ideas and best practices
- **Nmap Documentation:** https://nmap.org/book/
- **NSE Development Guide:** https://nmap.org/book/nse-usage.html

---

## 📄 License

These scripts are licensed under the **same terms as Nmap**.
See [Nmap Legal](https://nmap.org/book/man-legal.html) for details.

---

## 🎓 Educational Resources

### Learning NSE Development
- Nmap Official NSE Tutorial: https://nmap.org/book/nse-tutorial.html
- NSE API Reference: https://nmap.org/nsedoc/

### Security Best Practices
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CIS Benchmarks: https://www.cisecurity.org/benchmarks/

### SSL/TLS Security
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
- OWASP Transport Layer Protection: https://cheatsheetseries.owasp.org/

---

## 📈 Project Statistics

- **Total Scripts:** 20
- **HTTP Audits:** 10
- **SSL/TLS Audits:** 9
- **Lines of Code:** ~1,500+ Lua
- **Security Checks:** 50+
- **Supported Nmap Versions:** 7.40+

---

## 🔗 Related Projects

- **Nmap Project:** https://nmap.org/
- **NSE Script Collection:** https://nmap.org/nsedoc/
- **Security Research:** https://github.com/topics/nmap-scripts

---

**Last Updated:** July 3, 2026

**All scripts are production-ready and immediately deployable for professional security assessments.**

---

## Quick Start Reference

```bash
# Install
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cp -r Nmap-NSE-Script-Collection/{HTTP,SSL-TLS}/* ~/.nmap/scripts/
nmap --script-updatedb

# Use
nmap -p 80,443 --script http-security-headers example.com
nmap -p 443 --script ssl-weak-ciphers example.com

# Advanced
nmap -p 80,443 --script 'http-*,ssl-*' -sV -oX results.xml example.com
```

**Ready to secure your infrastructure? Start scanning today!**
