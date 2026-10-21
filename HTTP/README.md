# 🌐 HTTP Security Audits

**16 Nmap NSE scripts** for auditing web services over HTTP/HTTPS. Every script performs real request/response analysis (header policy checks, content parsing, soft-404 baselining, WAF/CDN interstitial detection, request-budget throttling).

**Port:** 80/443 | **Protocol:** HTTP/HTTPS | **Total lines of Lua:** 32,910

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [http-env-file-exposure](#1-http-env-file-exposure---http-env-file-exposure) | 🔴 CRITICAL | vuln, safe | 1920 |
| 2 | [http-git-config-exposure](#2-http-git-config-exposure---http-git-config-exposure) | 🔴 CRITICAL | vuln, safe | 1587 |
| 3 | [http-crossdomain-xml-audit](#3-http-crossdomain-xml-audit---http-crossdomain-xml-audit) | 🟠 HIGH | vuln, defensive, safe | 1934 |
| 4 | [http-phpinfo-exposure](#4-http-phpinfo-exposure---http-phpinfo-exposure) | 🟠 HIGH | vuln, discovery, safe | 2270 |
| 5 | [http-cache-audit](#5-http-cache-audit---http-cache-audit) | 🟡 MEDIUM | safe, discovery, vuln | 1707 |
| 6 | [http-cookie-flags](#6-http-cookie-flags---http-cookie-flags) | 🟡 MEDIUM | safe, discovery, vuln | 1999 |
| 7 | [http-cors-config](#7-http-cors-config---http-cors-config) | 🟡 MEDIUM | safe, discovery, vuln | 1693 |
| 8 | [http-dir-listing](#8-http-dir-listing---http-dir-listing) | 🟡 MEDIUM | safe, discovery, vuln | 2181 |
| 9 | [http-error-disclosure](#9-http-error-disclosure---http-error-disclosure) | 🟡 MEDIUM | safe, discovery, vuln | 2363 |
| 10 | [http-methods-enum](#10-http-methods-enum---http-methods-enum) | 🟡 MEDIUM | safe, discovery, vuln | 1618 |
| 11 | [http-robots-sitemap](#11-http-robots-sitemap---http-robots-sitemap) | 🟡 MEDIUM | safe, discovery | 2053 |
| 12 | [http-security-headers](#12-http-security-headers---http-security-headers) | 🟡 MEDIUM | safe, discovery, vuln | 2960 |
| 13 | [http-server-fingerprint](#13-http-server-fingerprint---http-server-fingerprint) | 🟡 MEDIUM | discovery, safe | 2295 |
| 14 | [http-swagger-ui-exposure](#14-http-swagger-ui-exposure---http-swagger-ui-exposure) | 🟡 MEDIUM | vuln, discovery, safe | 2647 |
| 15 | [http-trace-method](#15-http-trace-method---http-trace-method) | 🟡 MEDIUM | safe, discovery, vuln | 1694 |
| 16 | [http-waf-detect](#16-http-waf-detect---http-waf-detect) | 🟢 LOW | discovery, safe | 1989 |

---

## ⚙️ Common Script Arguments

Most scripts in this folder share the following `--script-args` (script-specific extras are listed per script):

| Argument | Default | Purpose |
|----------|---------|---------|
| `maxpaths` | per script | Maximum candidate paths to test |
| `maxrequests` | per script | Hard request budget for the run |
| `retries` | 1 | Retries per request on 5xx |
| `timeout` | 10000 | Per-request timeout (ms) |
| `delay` | 0.05 | Polite delay between requests (s) |
| `soft404` | true | Build a soft-404 baseline to suppress catch-all pages |
| `useragent` | built-in | Override the User-Agent sent by the script |
| `maxbodysize` | 1048576 | Ignore bodies larger than N bytes |

---

## 📜 Script Details

### 1. **http-env-file-exposure** - Http Env File Exposure
**Description:** Probes for world-readable environment and configuration files (.env, .env.production, .env.bak, wp-config.php, docker-compose.yml, config.json and 40+ variants). When content is returned it classifies every key/value line into secret-shaped credentials (DB URLs, cloud keys, JWT/API tokens, signing keys), infrastructure disclosure and benign config, masks the secrets in the report, and scores each exposure by credential type.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Raw `.env` / `.env.*` files and their backup variants
- WordPress `wp-config.php` (DB credentials, auth salts)
- `docker-compose.yml` / `Dockerfile` environment sections
- `config.json`, `application.properties`, `settings.py` style files
- Key classification: strong secret shapes (AKIA..., sk_live_, base64 JWT, 40+ char tokens) vs placeholders ("changeme", "your_key_here")

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-env-file-exposure example.com

# Mask secrets in output (default on)
nmap -p 80 --script http-env-file-exposure --script-args mask=true example.com
```

**Sample Output:**
```
| http-env-file-exposure:
|   Status: VULNERABLE - a live .env file with production credentials is readable.
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP/HTTPS
|   Files found: 1
|   /.env (HTTP 200, 812 bytes):
|     [CRITICAL] DATABASE_URL = my************************op (52 chars)
|     [CRITICAL] AWS_SECRET_ACCESS_KEY = wJ************************EY (40 chars)
|     [CRITICAL] JWT_SECRET = ch********me (10 chars, placeholder - lower confidence)
|     [MEDIUM] REDIS_HOST = cache.internal.acme (infrastructure)
```

---

### 2. **http-git-config-exposure** - Http Git Config Exposure
**Description:** Probes for exposed Git repository metadata (/.git/HEAD, /.git/config, /.git/index, /.git/packed-refs, .gitmodules and per-branch refs). Parses the returned Git text files for remotes (including credentials embedded in the URL), branch topology, hooks paths and submodules, and reports the repository name/origin as an attack-surface disclosure.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- `/.git/HEAD` (current branch, repo existence)
- `/.git/config` (remotes with embedded `user:token@` credentials)
- `/.git/index`, `/.git/packed-refs`, `refs/heads/*` (history/refs)
- `.gitmodules` (submodule origins)
- Credential extraction from remote URLs (masked in output)

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-git-config-exposure example.com

# Standard verbose run
nmap -p 80 --script http-git-config-exposure -v example.com
```

**Sample Output:**
```
| http-git-config-exposure:
|   Status: VULNERABLE - the Git repository metadata is publicly readable.
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP/HTTPS
|   Repo files found: 4
|   /.git/HEAD -> branch: master
|   /.git/config:
|     [CRITICAL] remote "origin" URL contains embedded credentials (deploy:****)
|     [MEDIUM] repository origin: git.example.com/internal/app.git
```

---

### 3. **http-crossdomain-xml-audit** - Http Crossdomain Xml Audit
**Description:** Audits Flash / Silverlight cross-domain policy files (/crossdomain.xml, /clientaccesspolicy.xml) for overly permissive wildcard configurations (`<allow-access-from domain="*" />`) which permit cross-origin data access and cross-origin request forgery from any site. Parses the full policy (allow-access-from, site-control, allow-http-request-headers-from, Silverlight grant-to), scores severity per directive, detects DTD/XEE, comments and embedded metadata, and compares the policy served over http vs https.

**Risk Level:** 🟠 HIGH | **Category:** vuln, defensive, safe

**What it checks:**
- Wildcard `domain="*"` grants and `to-ports` wildcards
- `site-control permissive=1` and `allow-navigation` grants
- `allow-http-request-headers-from` with `headers="*"`
- Silverlight `<grant-to domain="*" />` and `include-subpaths="true"`
- DTD declarations / external entities, XML comments leaking dev metadata
- Scheme channel divergence (different policy over http vs https)

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-crossdomain-xml-audit example.com

# Include cache-busting variant
nmap -p 80 --script http-crossdomain-xml-audit --script-args cachebust=true example.com
```

**Sample Output:**
```
| http-crossdomain-xml-audit:
|   Status: VULNERABLE - permissive cross-domain policy published.
|   Risk Level: 🟠 HIGH
|   Protocol: HTTP/HTTPS
|   Policies found: 2
|   Findings:
|     [CRITICAL] /crossdomain.xml grants access to all origins (domain="*") for all ports
|     [MEDIUM] /clientaccesspolicy.xml grant-to domain="*" include-subpaths="true"
|     [MEDIUM] scheme channel comparison: https variant grants an additional origin
```

---

### 4. **http-phpinfo-exposure** - Http Phpinfo Exposure
**Description:** Finds publicly reachable `phpinfo()` pages and extracts the security-relevant configuration from them. A `phpinfo()` page is a single-file disclosure of the whole PHP runtime: exact version and build date, the loaded configuration file, every ini directive with its local and master value, the complete server environment, the HTTP headers of the request that produced the page, the loaded extension list, and often database defaults and include paths.

**Risk Level:** 🟠 HIGH | **Category:** vuln, discovery, safe

**What it checks:**
- 90 candidate phpinfo paths (plus `.php` suffix variants), confirmed by a weighted 20-marker test
- Identity block: version, Zend Engine, SAPI, build date, php.ini path, DOCUMENT_ROOT, streams
- ~55 directives scored against a secure-default policy (allow_url_include, enable_dl, register_globals, xdebug.remote_connect_back, mysql default password, cgi.fix_pathinfo, session cookie flags, open_basedir, disable_functions)
- Environment section: secret-shaped credentials (masked), infrastructure disclosure
- Reflected HTTP request headers (credential vs topology weighting)
- 37 risky/loaded extensions (xdebug, ionCube, imagick, phar), PHP EOL scoring, SSRF wrapper reachability

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-phpinfo-exposure example.com

# Mask secrets (default on) and probe .php suffixes
nmap -p 80 --script http-phpinfo-exposure --script-args mask=true,probe_suffix=true example.com
```

**Sample Output:**
```
| http-phpinfo-exposure:
|   Status: VULNERABLE - a public phpinfo() page prints secrets or enables remote debugging.
|   Risk Level: 🟠 HIGH
|   Protocol: HTTP/HTTPS
|   Candidates tested: 90
|   Confirmed pages: 1
|   Page /phpinfo.php:
|     [CRITICAL] allow_url_include: local=On master=Off
|     [CRITICAL] xdebug.remote_connect_back: local=On master=On
|     [SECRET] DATABASE_URL = my************************op (52 chars)
|   Severity counts: CRITICAL=22 HIGH=19 MEDIUM=44 LOW=14 INFO=8
```

---

### 5. **http-cache-audit** - Http Cache Audit
**Description:** Requests a set of paths that typically return authenticated, personal or otherwise sensitive content and inspects Cache-Control, Pragma, Expires, ETag and Vary headers to flag responses that are cacheable, stale-while-revalidate, shared-cache eligible or missing anti-caching directives. Checks for `Vary: Cookie`/`Authorization` gaps, ETag/Last-Modified leakage on personal data, `Surrogate-Control` and CDN-specific cache hints, and compares private vs public directives per path.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- Public/Shared cacheability of responses that look personal (session ids, account wording, user markers)
- Cache-Control directive policy: no-store/no-cache/private/immutable/stale-while-revalidate/max-age
- Missing or wrong `Vary` header when the response differs per user or auth state
- ETag/Last-Modified/Expires leakage on sensitive pages
- CDN/ISP cache hints (Surrogate-Control, X-Cache, Age)

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-cache-audit example.com

# Wider path set and bigger budget
nmap -p 443 --script http-cache-audit --script-args maxpaths=40,maxrequests=120 example.com
```

**Sample Output:**
```
| http-cache-audit:
|   Status: VULNERABLE - sensitive-looking responses are publicly cacheable.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Findings:
|     [HIGH] /account/dashboard is cacheable by shared caches (Cache-Control: public, max-age=3600)
|     [MEDIUM] /profile is missing Vary: Cookie while the body contains session markers
|     [LOW] /checkout exposes ETag and Last-Modified on personalized content
|   Requests issued: 26 of 120
```

---

### 6. **http-cookie-flags** - Http Cookie Flags
**Description:** Audits Set-Cookie headers returned across a set of common application paths and evaluates each cookie against Secure, HttpOnly, SameSite, Domain, Path and expiry attributes. Flags cookies whose names look like session, auth, CSRF, token or remember-me credentials when they lack the corresponding protection flag, and reports overly broad Domain or long Max-Age values.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- Missing `Secure` on session/auth/CSRF/token cookies over HTTPS
- Missing `HttpOnly` on non-CSRF cookies (script-readable sessions)
- Missing or lax `SameSite` (Lax/None accepted with the right risk model)
- Overly broad `Domain`, missing `Path`, and long-lived `Max-Age`/`Expires`
- Credential-shaped cookie names (session, sid, token, csrf, remember, auth...)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script http-cookie-flags example.com

# More paths and requests
nmap -p 443 --script http-cookie-flags --script-args maxpaths=30,maxrequests=90 example.com
```

**Sample Output:**
```
| http-cookie-flags:
|   Status: VULNERABLE - session cookies are missing protective flags.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Cookies analyzed: 9
|   Findings:
|     [HIGH] PHPSESSID set without Secure over HTTPS
|     [HIGH] PHPSESSID set without HttpOnly (script-readable session)
|     [MEDIUM] remember_me missing SameSite (CSRF-prone cross-site send)
|     [LOW] analytics_id Max-Age of 31536000s (365 days)
```

---

### 7. **http-cors-config** - Http Cors Config
**Description:** Probes HTTP(S) endpoints with a set of crafted Origin headers to detect common CORS misconfigurations: reflected arbitrary origins, wildcard origin combined with credentials, null-origin acceptance, and subdomain-suffix origin reflection. Validates Access-Control-Allow-Credentials, Access-Control-Allow-Headers reflection and preflight (OPTIONS) behaviour, and distinguishes real CORS responses from WAF interstitials.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- Arbitrary Origin reflection in Access-Control-Allow-Origin
- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` (flagged as invalid-but-telling)
- Null origin (`null`) acceptance and subdomain suffix matching
- Preflight handling: allowed methods/headers reflected without restriction
- Exposed headers (Access-Control-Expose-Headers) leaking internal data

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script http-cors-config example.com

# Include preflight + sibling-origin checks
nmap -p 443 --script http-cors-config --script-args preflight=true,sibling=true example.com
```

**Sample Output:**
```
| http-cors-config:
|   Status: VULNERABLE - arbitrary origins are reflected with credentials.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Tested origins: 14
|   Findings:
|     [CRITICAL] /api reflects Origin https://evil.example with Access-Control-Allow-Credentials: true
|     [HIGH] / returns Access-Control-Allow-Origin: * and echoes Access-Control-Request-Headers
|     [MEDIUM] /api accepts the null origin
```

---

### 8. **http-dir-listing** - Http Dir-Listing
**Description:** Enumerates common directory paths and, when directory indexes are enabled, parses the HTML/autoindex listing to inventory files and subdirectories, flags sensitive file names (backups, dumps, logs, .git, .env, SQL files, archives) and optionally recurses into subdirectories with a depth and entry budget. Distinguishes real indexes from soft-404 catch-all pages via a baseline.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- Apache autoindex, nginx autoindex, IIS detailed directory listings
- Sensitive entries: *.sql, *.bak, *.log, *.zip, dump, backup, .env, .git, config
- Subdirectory recursion with per-depth entry caps (budgeted)
- WEBDAV (OPTIONS PROPFIND/MKCOL support detection when enabled)
- Soft-404 suppression so "Index of" catch-all pages are not over-reported

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-dir-listing example.com

# Recurse up to 3 levels with WEBDAV probing
nmap -p 80 --script http-dir-listing --script-args recurse=true,webdav=true,maxdepth=3,maxentries=500 example.com
```

**Sample Output:**
```
| http-dir-listing:
|   Status: VULNERABLE - directory indexes expose sensitive files.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Indexes found: 4
|   /backup/:
|     [CRITICAL] db_dump.sql (database dump)
|     [HIGH] site_backup.tar.gz (archive)
|   /logs/:
|     [MEDIUM] access.log (application log)
|   Requests issued: 61 of 140
```

---

### 9. **http-error-disclosure** - Http Error Disclosure
**Description:** Sends a curated set of trigger requests (malformed queries, invalid method/path combinations, oversized input, bad JSON, non-existent include paths) to elicit error pages, then classifies each response for stack traces, source code snippets, file paths, framework signatures, SQL errors, PHP/ASP/.NET/JEE disclosure and verbose 5xx pages. Builds a soft-404 baseline so generic error pages are not over-reported.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- Stack traces (Java, .NET, Python, PHP, Ruby, Node)
- Absolute file paths and source snippets in error bodies
- Database error disclosure (MySQL, PostgreSQL, MSSQL, Oracle strings)
- Framework/app-signature banners in error pages (Laravel, Spring, ASP.NET, JEE)
- Verbose 5xx vs generic 500, debug-mode banners, exception IDs

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-error-disclosure example.com

# Include raw trigger requests and more triggers
nmap -p 80 --script http-error-disclosure --script-args raw=true,triggers=12 example.com
```

**Sample Output:**
```
| http-error-disclosure:
|   Status: VULNERABLE - stack traces and file paths are disclosed.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Triggers sent: 9
|   Findings:
|     [HIGH] Java stack trace with 14 frames at /api/nonexistent?x=%00
|     [HIGH] absolute file path /var/www/app/src/main/.../UserRepo.java disclosed
|     [MEDIUM] MySQL syntax error quoted in response body
|     [LOW] ASP.NET detailed error page (customErrors off)
```

---

### 10. **http-methods-enum** - Http Methods Enum
**Description:** Enumerates which HTTP methods a target accepts (55 methods from GET to CONNECT/PROPFIND/MKCOL/COPY/MOVE/LOCK/UNLOCK/VERSION-CONTROL) using OPTIONS and per-method probes, detects Allow/MS-Allowed-METHODS headers, and optionally probes write methods (PUT/DELETE), TRACE and tunneling (CONNECT) behaviour to map the method attack surface.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- OPTIONS `Allow` and `MS-Allowed-METHODS` header parsing
- Per-method status mapping (200/201 accepted vs 405 rejected)
- Write methods: PUT (file write candidate), DELETE, PATCH
- TRACE and the tunneling-capable CONNECT method
- Method-not-allowed consistency (405 without Allow header)

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-methods-enum example.com

# Include write/trace/tunnel probes
nmap -p 80 --script http-methods-enum --script-args writeprobe=true,traceprobe=true,tunnelprobe=true example.com
```

**Sample Output:**
```
| http-methods-enum:
|   Status: AUDITED - unusual methods accepted on target paths.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Methods accepted on /: GET, HEAD, POST, OPTIONS
|   Findings:
|     [MEDIUM] PUT accepted on / (file write candidate)
|     [LOW] TRACE accepted (XST/reflective probe surface)
|     [INFO] 405 responses consistently include an Allow header
```

---

### 11. **http-robots-sitemap** - Http Robots Sitemap
**Description:** Fetches and parses robots.txt (per-agent Disallow/Allow rules, wildcard and regex-style patterns, Crawl-delay, Noindex, bogus fields) and every referenced Sitemap (XML urlset/sitemapindex, lastmod validation, priority/changefreq, image/video extensions, chained sitemaps). Extracts credential-shaped URLs, flags discouraged-but-sensitive paths and validates date/URI hygiene.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- robots.txt rule parsing with per-agent scopes and wildcard matching
- Disallowed paths that reveal admin/backup/internal areas
- Sitemap discovery (multiple Sitemap: lines, chained sitemapindex)
- Sitemap URL hygiene: bad lastmod dates, missing loc, image/video entries
- Credential-shaped URLs (session/token/apikey query params) in sitemaps

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-robots-sitemap example.com

# Follow up to 5 chained sitemaps
nmap -p 80 --script http-robots-sitemap --script-args follow=true,maxfollow=5 example.com
```

**Sample Output:**
```
| http-robots-sitemap:
|   Status: AUDITED - robots.txt discloses sensitive paths; sitemap parsed.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   robots.txt: 8 Disallow rules for User-agent *
|   Disclosed sensitive paths: /admin/, /backup/db_dump.sql, /internal/config.php
|   Sitemaps: 2 (1 urlset with 47 urls, 1 sitemapindex with 3 children)
|   [MEDIUM] sitemap URL contains a sessionid query parameter
|   [LOW] lastmod 2031-13-45 is not a valid date
```

---

### 12. **http-security-headers** - Http Security Headers
**Description:** The deepest header-policy auditor in the folder. Evaluates the full modern browser-protection header set — Content-Security-Policy (with directive-level parsing and weak-directive detection), Strict-Transport-Security (max-age, includeSubDomains, preload), X-Content-Type-Options, Referrer-Policy, Permissions-Policy/Feature-Policy, Cross-Origin-*Policies, X-Frame-Options, X-XSS-Protection, Public-Key-Pins and Cache-Control — across multiple paths, scoring each finding with concrete remediation text.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- CSP: presence, `default-src`, `script-src` (unsafe-inline/unsafe-eval), `object-src none`, `frame-ancestors`, `base-uri`, `form-action`, report-uri/report-to, nonce/strict-dynamic
- HSTS: max-age thresholds, includeSubDomains, preload
- Clickjacking (X-Frame-Options, frame-ancestors), MIME sniffing (nosniff)
- Referrer-Policy strictness, Permissions-Policy camera/microphone/geolocation
- COOP/COEP/COEP-require-corp for site-isolation, deprecated header handling

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script http-security-headers example.com

# Larger budget
nmap -p 443 --script http-security-headers --script-args maxrequests=60 example.com
```

**Sample Output:**
```
| http-security-headers:
|   Status: VULNERABLE - multiple missing or weak browser-protection headers.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Findings:
|     [HIGH] Content-Security-Policy allows 'unsafe-inline' in script-src
|     [HIGH] Strict-Transport-Security max-age=300 is far below 63072000
|     [MEDIUM] missing X-Content-Type-Options: nosniff
|     [MEDIUM] Referrer-Policy unsafe-url
|     [LOW] X-XSS-Protection present (deprecated)
```

---

### 13. **http-server-fingerprint** - Http Server Fingerprint
**Description:** Fingerprinting suite that identifies the web server, language/framework, and software versions. Combines Server/X-Powered-By/X-AspNet-Version/X-Generator headers, response-to-error-page analysis, favicon hash matching (md5 of /favicon.ico against a known hash table), and version strings in banners/bodies to build a composite fingerprint with confidence scoring.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Server, X-Powered-By, X-AspNet-Version, X-Generator, X-Technology headers
- Error-page fingerprinting (IIS vs Apache vs nginx vs Jetty vs gunicorn banners)
- Favicon MD5 hash against a known icon hash table
- Framework/version strings in HTML bodies (meta generator, cookie names)
- Composite confidence: header+body+favicon agreement

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-server-fingerprint example.com

# Include favicon + raw error-page probes
nmap -p 80 --script http-server-fingerprint --script-args favicon=true,errorpage=true example.com
```

**Sample Output:**
```
| http-server-fingerprint:
|   Status: AUDITED - server fingerprint established.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Fingerprint:
|     Server: Apache/2.4.49 (Ubuntu)
|     Language: PHP/7.4.3 (X-Powered-By)
|     CMS: WordPress 5.9 (X-Generator)
|     Favicon: md5 20e78a4433f82e4a12a3e0a1191626a3 (WordPress)
|   Confidence: high (header + favicon agreement)
```

---

### 14. **http-swagger-ui-exposure** - Http Swagger UI Exposure
**Description:** Finds publicly reachable Swagger / OpenAPI API specifications and the interactive documentation UIs (Swagger UI, ReDoc, Scalar, Stoplight Elements, GraphiQL) that render them, then parses what the document actually contains. Carries its own compact JSON parser and a YAML subset parser (Nmap has no JSON library) to turn a confirmed spec into an attack-surface inventory: every path, method, the authentication model, sensitive endpoints, internal server URLs and documented data-model fields.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- 80+ candidate paths: Swagger UI entry points, Spring api-docs (v2/v3 + grouped), OpenAPI json/yaml, api/docs, ReDoc, Scalar, Stoplight, GraphiQL, drf-yasg/spectacular, WCF doc.json, swagger-resources registry
- Spec confirmation by document markers + successful JSON/YAML parse (catch-all pages cannot masquerade)
- Sensitive endpoint policy: admin, internal, debug, backup/restore, execute/eval, export/import, upload/download, password, token, payment/wallet, config, keys, git, lifecycle
- Security model: declared schemes (http basic/bearer, apiKey, oauth2 flows), global requirement, unsecured operation count
- Internal topology: declared servers + every embedded URL classified (loopback, RFC1918, link-local/metadata, .internal, .corp, 172.16/12, staging/dev names)
- UI spec-URL extraction + follow, group-registry follow, group-name enumeration, content-hash dedup

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-swagger-ui-exposure example.com

# Wider path set and bigger request budget
nmap -p 443 --script http-swagger-ui-exposure --script-args maxpaths=90,maxrequests=160 example.com
```

**Sample Output:**
```
| http-swagger-ui-exposure:
|   Status: VULNERABLE - the exposed API specification lists administrative or internal endpoints.
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   Specification documents found: 5
|   Interactive documentation UIs found: 3
|   Total documented operations: 36
|   Sensitive API surface:
|     [CRITICAL] /api/v1/admin/backup/create - backup endpoint (methods: post)
|     [CRITICAL] /api/v1/internal/health - internal-only endpoint (methods: get)
|     [HIGH] /api/v1/payments/transfer - financial endpoint (methods: post)
|   Infrastructure disclosure:
|     [MEDIUM] http://10.0.0.5:8080 - private 10/8 address (in /v3/api-docs)
|     [LOW] https://staging.api.acme-corp.com - non-production environment (in /v3/api-docs)
|   Requests issued: 92 of 160
```

---

### 15. **http-trace-method** - Http Trace Method
**Description:** Tests whether the TRACE method (and its proxies) is accepted and whether it reflects request headers in the response body, which enables Cross-Site Tracing (XST) to steal credentials and cookies sent with the request. Sends TRACE directly and via common alias/header workarounds, classifies the response by content type and marker content, and reports which request headers (Authorization, Cookie, X-Forwarded-For) would be reflected.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- TRACE acceptance (HTTP 200 with reflected headers)
- Header reflection: Authorization, Cookie, custom headers echoed in the 200 body
- Alias and variant workarounds (X-HTTP-Method-Override, proxy-rewritten TRACE)
- Content-Type of the TRACE response (message/http vs text/html)
- Distinguishes real TRACE reflection from WAF/proxy generic 200s

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-trace-method example.com

# Include alias + variant probes
nmap -p 80 --script http-trace-method --script-args variants=true,aliases=true example.com
```

**Sample Output:**
```
| http-trace-method:
|   Status: VULNERABLE - TRACE reflects request headers (XST surface).
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
|   TRACE accepted on: /, /api
|   Findings:
|     [HIGH] / reflects Authorization and Cookie headers in the TRACE body
|     [MEDIUM] X-HTTP-Method-Override: TRACE honoured on /api
```

---

### 16. **http-waf-detect** - Http Waf Detect
**Description:** Detects the presence and vendor of a Web Application Firewall or CDN in front of the target. Uses passive signature matching on headers and error bodies (Cloudflare, Akamai, Imperva/Incapsula, Sucuri, AWS WAF, ModSecurity, FortiWeb, SafeLine) plus optional behavioural probing (baseline vs challenge comparison across crafted but non-malicious inputs) to confirm an active WAF layer and identify which vendor is answering.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Passive header signatures (cf-ray, x-iinfo, akamai, server banners)
- Passive body signatures on error/interstitial pages
- Optional behavioural confirmation: baseline vs probed response diffing
- Distinguishes CDN edge vs WAF vs origin (response header composition)
- Reports vendor + confidence, never attempts bypass

**How to Execute:**
```bash
# Basic scan (passive signatures only)
nmap -p 80 --script http-waf-detect example.com

# Add behavioural confirmation probes
nmap -p 80 --script http-waf-detect --script-args behaviour=true example.com
```

**Sample Output:**
```
| http-waf-detect:
|   Status: AUDITED - a WAF/CDN layer is present in front of the target.
|   Risk Level: 🟢 LOW
|   Protocol: HTTP/HTTPS
|   Detected: Cloudflare (header signature: cf-ray)
|   Confidence: high (header + body agreement)
|   Note: origin server is shielded; further probes may be filtered.
```

## 🧪 Testing These Scripts

The HTTP folder ships with a Lua-sandbox smoke harness and test fixtures:

```bash
python3 tools/smoke_nse.py HTTP                      # all 16 scripts, plain scenario
python3 tools/smoke_nse.py --scenario=phpinfo HTTP   # a specific synthetic posture
python3 tools/lint_nse.py HTTP                       # quality gate (compile + line minimums)
```

Synthetic scenarios available: `plain`, `hardened`, `waf`, `empty`, `error`, `redirect`, `json`, `git`, `env`, `listing`, `methods`, `crawler`, `policy`, `phpinfo`, `swagger`.

---

## 📌 Notes

- All scripts are **passive and non-destructive**: GET (plus read-only OPTIONS/TRACE where the audit requires it), bounded by `maxrequests`, and they never attempt authentication bypass, payload injection beyond trigger strings, or DoS.
- Secrets that are discovered (DB URLs, cloud keys, git credentials) are **masked** in the report by default (`mask=true`); the report states the key name and length so you can rotate without the value being copied into scan logs.
- Soft-404 baselining prevents catch-all "not found" pages from being misreported as exposures.
