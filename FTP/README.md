# 📁 FTP Security Audits

**16 Nmap NSE scripts** for auditing FTP servers:

**Covers:**

- Anonymous access and what it exposes
- Daemon banner fingerprinting (including the vsftpd 2.3.4 backdoor signature)
- FTP bounce and FXP third-party transfer surface
- Brute-force rate limiting and lockout
- Chroot jail escape preconditions
- Cleartext-vs-FTPS login enforcement
- Full command-surface enumeration
- Directory listing with sensitive-entry classification
- ProFTPD mod_copy (CPFR/CPTO) exposure
- Passive-mode data-channel correctness
- Explicit FTPS support and a full FTPS TLS cipher/protocol audit
- Self-cleaning writable-directory tests

Every script speaks the FTP control (and data) protocol directly - real banners, real command exchanges, real data-connection attempts - and reports evidence-based verdicts.

**Port:** 21/tcp (any `ftp`-matched port) | **Protocol:** FTP (RFC 959) + extensions (EPSV, MLST, AUTH, FX, mod_copy) + explicit FTPS (RFC 4217) | **Total lines of Lua:** 30,421

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [ftp-proftpd-mod-copy](#1-ftp-proftpd-mod-copy---proftpd-mod_copy-cpfrcpto) | 🔴 CRITICAL | vuln, safe | 1707 |
| 2 | [ftp-vsftpd-backdoor-fingerprint](#2-ftp-vsftpd-backdoor-fingerprint---vsftpd-2.3.4-backdoor-cve-2011-2523) | 🔴 CRITICAL | vuln, safe | 1651 |
| 3 | [ftp-chroot-escape-precondition](#3-ftp-chroot-escape-precondition---chroot-jail-escape-precondition) | 🟠 HIGH | vuln, safe | 1756 |
| 4 | [ftp-fxp-cross-server](#4-ftp-fxp-cross-server---fxp-third-party-transfer) | 🟠 HIGH | vuln, safe | 1718 |
| 5 | [ftp-anonymous-login](#5-ftp-anonymous-login---anonymous-login-access) | 🟡 MEDIUM | safe, discovery, vuln | 1720 |
| 6 | [ftp-banner-grab](#6-ftp-banner-grab---banner-and-daemon-fingerprint) | 🟡 MEDIUM | safe, discovery, version | 1687 |
| 7 | [ftp-bounce-check](#7-ftp-bounce-check---ftp-bounce-port-exposure) | 🟡 MEDIUM | safe, discovery, vuln | 1735 |
| 8 | [ftp-brute-rate-limit](#8-ftp-brute-rate-limit---login-rate-limiting-and-lockout) | 🟡 MEDIUM | defensive, safe | 1734 |
| 9 | [ftp-cleartext-enforcement](#9-ftp-cleartext-enforcement---cleartext-login-enforcement) | 🟡 MEDIUM | safe, discovery, vuln | 1723 |
| 10 | [ftp-command-enum](#10-ftp-command-enum---command-surface-enumeration) | 🟡 MEDIUM | safe, discovery, vuln | 1741 |
| 11 | [ftp-directory-listing](#11-ftp-directory-listing---directory-listing-and-sensitive-entries) | 🟡 MEDIUM | safe, discovery | 1783 |
| 12 | [ftp-passive-mode-check](#12-ftp-passive-mode-check---passive-mode-data-channel) | 🟡 MEDIUM | safe, discovery | 1671 |
| 13 | [ftp-tls-cipher-audit](#13-ftp-tls-cipher-audit---ftps-tls-cipher-audit) | 🟡 MEDIUM | defensive, safe | 3150 |
| 14 | [ftp-tls-support](#14-ftp-tls-support---explicit-ftps-support) | 🟡 MEDIUM | safe, discovery | 3175 |
| 15 | [ftp-writable-dirs](#15-ftp-writable-dirs---writable-directory-test) | 🟡 MEDIUM | safe, discovery, vuln | 1786 |
| 16 | [ftp-syst-fingerprint](#16-ftp-syst-fingerprint---syst-and-feat-fingerprint) | 🟢 LOW | discovery, safe | 1684 |

---

### 1. **ftp-proftpd-mod-copy** - ProFTPD mod_copy (CPFR/CPTO)
**Description:** Probes ProFTPD mod_copy (CPFR / CPTO) for the unauthenticated file-copying exposure (CVE-2015-3306 class) without performing any copy by default.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- HELP/FEAT cross-check for mod_copy command signatures
- bare CPFR against a read-only source file
- 250/350 acceptance -> CRITICAL (mod_copy live without authentication)
- CPTO chain executed only with confirmcopy=true, into a volatile /tmp path
- 502/500 -> INFO (module absent); 530 -> INFO (auth-gated)

**How to Execute:**
```bash
# Basic scan (stops at CPFR; no copy is performed)
nmap -p 21 --script ftp-proftpd-mod-copy target.example.com

# Confirm the full CPFR/CPTO chain into a volatile path
nmap -p 21 --script ftp-proftpd-mod-copy --script-args ftp-proftpd-mod-copy.confirmcopy=true target.example.com
```

**Sample Output:**
```
| ftp-proftpd-mod-copy:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - ProFTPD mod_copy (CPFR/CPTO) exposure tested.
|   Findings:
|     [CRITICAL] unauthenticated CPFR was accepted for /etc/passwd; mod_copy is
|            live without authentication and, combined with CPTO, copies any readable
|            file to any writable location (CVE-2015-3306 class exposure on ProFTPD
|            mod_copy) (modcopy-cpfr-accepted) [evidence: CPFR /etc/passwd accepted.]
|     [MEDIUM] HELP explicitly lists the mod_copy commands (CPFR/CPTO); the module
|            is loaded on this daemon (modcopy-in-help) [evidence: 214-Commands
|            supported:
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 14
|   Requests issued: 4
|   banner: 227 Welcome to the vsftpd FTP daemon
|   cpfr_code: 250
|   cpfr_response: CPFR /etc/passwd accepted.
|   daemon_family: vsftpd
|   probe_notes:
|     1: daemon family: vsftpd
|     2: CPFR /etc/passwd answered 250
|     3: stopping at CPFR by default; set confirmcopy=true to exercise the CPTO chain into a volatile path
|   probe_source: /etc/passwd
```

---

### 2. **ftp-vsftpd-backdoor-fingerprint** - vsftpd 2.3.4 Backdoor (CVE-2011-2523)
**Description:** Checks for the vsftpd 2.3.4 smiley-face backdoor banner signature and the affected 2.3.4 version window.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- banner reply code + daemon identity parsing (16 daemon grammars)
- 227-code welcome carrying a vsftpd identity -> CRITICAL (backdoor build; listens on TCP 6200)
- vsftpd 2.3.4 on a normal 220 banner -> HIGH (affected version window)
- optional STAT corroboration of the version string

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-vsftpd-backdoor-fingerprint target.example.com
```

**Sample Output:**
```
| ftp-vsftpd-backdoor-fingerprint:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - vsftpd backdoor signature (CVE-2011-2523) checked.
|   Findings:
|     [CRITICAL] the banner matches the vsftpd 2.3.4 backdoor signature: a 227
|            welcome code with a vsftpd identity. Builds with this signature ship a
|            hardcoded backdoor that opens a TCP listener on port 6200 (CVE-2011-2523);
|            treat the host as compromised or intentionally backdoored and take it
|            offline for forensic review (vsftpd-backdoor-banner) [evidence: 227 Welcome
|            to the vsftpd FTP daemon]
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 11
|   Requests issued: 2
|   banner: 227 Welcome to the vsftpd FTP daemon
|   banner_code: 227
|   daemon_family: vsftpd
|   probe_notes:
|     1: banner code 227, family vsftpd
|     2: STAT corroboration: 211
|   stat: 211-Status:
```

---

### 3. **ftp-chroot-escape-precondition** - Chroot Jail Escape Precondition
**Description:** Tests directory traversal and chroot containment across the FTP root tree with CWD, CDUP and MLST probes - the historical escape vectors of vsftpd, ProFTPD, wu-ftp and busybox ftpd.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- 8 traversal probes: double-dot from root, single dot-dot, bare dot-dot, absolute /etc, /etc/passwd, /root, chained ....//etc/passwd, filter-evasion ....//....//etc/passwd
- CDUP from the landing root (parent-of-root resolution)
- MLST on absolute system paths (metadata read without a listing)
- per-probe classification: escaped (250) -> HIGH, contained (550), normalized (501), no-response

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-chroot-escape-precondition target.example.com
```

**Sample Output:**
```
| ftp-chroot-escape-precondition:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - FTP chroot containment probed.
|   Findings:
|     [HIGH] 8 of 8 CWD traversal probes were accepted with 250; the FTP root is
|            not confined to a jail (first: CWD /../../) (chroot-escape-possible)
|            [evidence: CWD /../../ -> 250]
|     [HIGH] CDUP from the landing directory succeeded; the daemon has a parent
|            directory above the configured root, which is a containment defect
|            (cdup-from-root) [evidence: CDUP command successful.]
|     [HIGH] MLST returned valid metadata for the system path /etc; the daemon can
|            stat files outside the jail even when CWD refuses traversal
|            (mlst-system-path) [evidence: /etc:
|            type=dir;size=4096;modify=20110101000000;]
|   Severity counts: CRITICAL=0 HIGH=3 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 21
|   Requests issued: 14
|   banner: 227 Welcome to the vsftpd FTP daemon
|   cdup_code: 250
|   landing_dir: "/pub/ftp" is the current directory.
|   probe_notes:
|     1: session established as anonymous
|     2: CWD ....//....//etc/passwd -> 250 (escaped)
|     3: CDUP -> 250
|     4: MLST /etc -> 250
|     5: landing directory: "/pub/ftp" is the current directory.
|     6: CWD /../../ -> 250 (escaped)
|     7: CWD /../ -> 250 (escaped)
|     8: CWD /.. -> 250 (escaped)
|     9: CWD /etc -> 250 (escaped)
|     10: CWD /etc/passwd -> 250 (escaped)
|     11: CWD /root -> 250 (escaped)
|     12: CWD /../../etc -> 250 (escaped)
|   traversal_results:
|     1: 
|   traversal_summary: escaped=8 contained=0 normalized=0 other=0
```

---

### 4. **ftp-fxp-cross-server** - FXP Third-Party Transfer
**Description:** Tests whether the server allows File Exchange Protocol (FXP) third-party transfers, where the server itself opens a connection to an attacker-chosen host.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- SITE FXPT probe to a safe private-range destination (destip/destport args)
- 200/250 acceptance -> HIGH (server acts as the data mover between two endpoints)
- 502/unknown-command -> INFO (FXP not loaded)
- no file is ever transferred; the probe stops at the control-channel reply

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-fxp-cross-server target.example.com

# Custom destination
nmap -p 21 --script ftp-fxp-cross-server --script-args 'ftp-fxp-cross-server.destip=198.18.0.1 ftp-fxp-cross-server.destport=21' target.example.com
```

**Sample Output:**
```
| ftp-fxp-cross-server:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - FTP FXP third-party transfer tested.
|   Findings:
|     [HIGH] the server accepted SITE FXPT for an external destination
|            (198.18.0.1:53); FXP third-party transfers are enabled and the server will
|            initiate outbound FTP sessions to attacker-chosen hosts (fxp-enabled)
|            [evidence: Third-party transfer initiated.]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 7
|   Requests issued: 4
|   banner: 227 Welcome to the vsftpd FTP daemon
|   fxpt_response: Third-party transfer initiated.
|   port_response: PORT command successful.
|   probe_notes:
|     1: FXP destination is 198.18.0.1:53 (RFC 2544 benchmarking range)
|     2: login attempt: success
|     3: PORT 198,18,0,1,0,53 answered 200
|     4: SITE FXPT answered 250
```

---

### 5. **ftp-anonymous-login** - Anonymous Login Access
**Description:** Attempts anonymous FTP login with the standard anonymous credential pairs on a single control connection and, when accepted, captures what the unauthenticated account can actually read.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- anonymous/anonymous and common anonymous credential pairs (USER/PASS in one session)
- login classification: accepted (230), pending-then-rejected (331/530), refused, TLS-required (534)
- on success: PWD landing directory, SYST system type, FEAT extension map, first NLST entry scan
- what the anonymous jail exposes: directory/file counts and notable entry names

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-anonymous-login target.example.com

# Custom anonymous credentials and request budget
nmap -p 21 --script ftp-anonymous-login --script-args 'ftp-anonymous-login.user=anonymous ftp-anonymous-login.pass=me@example.com' target.example.com
```

**Sample Output:**
```
| ftp-anonymous-login:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP anonymous login tested.
|   Findings:
|     [HIGH] anonymous FTP login succeeded with anonymous / anonymous@example.com;
|            the FTP jail is reachable without credentials (anonymous-login-permitted)
|            [evidence: Login successful. Restrictions apply.]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 7
|   Requests issued: 3
|   banner: 227 Welcome to the vsftpd FTP daemon
|   credential_attempts:
|     1: anonymous / anonymous@example.com -> SUCCESS
|   features:
|     1: 211
|     2: AUTH
|     3: EPSV
|     4: MDTM
|     5: MLST
|     6: PASV
|     7: SITE
|     8: SIZE
|     9: UTF8
|   landing_dir: "/pub/ftp" is the current directory.
|   landing_entries: 4 directories, 5 files
|   os_class: UNIX (Unix)
|   probe_notes:
|     1: anonymous session established with anonymous / anonymous@example.com
|     2: landing directory contains 3 sensitive-looking entry(ies)
|   welcome: Login successful. Restrictions apply.
```

---

### 6. **ftp-banner-grab** - Banner and Daemon Fingerprint
**Description:** Captures the raw FTP welcome banner and fingerprints the server daemon family and version from it, including the distinctive 227-code vsftpd backdoor signature.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, version

**What it checks:**
- raw banner text and reply code (220 / 221 / 227)
- daemon family + version from 16 known daemon banner grammars (vsftpd, ProFTPD, IIS, FileZilla, Pure-FTPd, wu-ftp, busybox, Serv-U, ...)
- 227-code welcome on a vsftpd identity (CVE-2011-2523 backdoor marker) -> MEDIUM + cross-reference
- known-bug / end-of-life notes for the identified version

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-banner-grab target.example.com
```

**Sample Output:**
```
| ftp-banner-grab:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP banner captured and daemon fingerprinted.
|   Findings:
|     [MEDIUM] banner uses the 227 welcome code with a vsftpd identity - this is
|            the signature of the vsftpd 2.3.4 backdoor build (CVE-2011-2523); see
|            ftp-vsftpd-backdoor-fingerprint for the dedicated CRITICAL report
|            (backdoor-banner) [evidence: 227 Welcome to the vsftpd FTP daemon]
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 4
|   Requests issued: 2
|   banner: 227 Welcome to the vsftpd FTP daemon
|   banner_class: backdoor
|   banner_code: 227
|   daemon_family: vsftpd
|   probe_notes:
|     1: banner captured from the spontaneous greeting
|     2: non-standard welcome code 227
|     3: STAT answered 211
|   stat: 211-Status:
|   vendor: vsftpd project
```

---

### 7. **ftp-bounce-check** - FTP Bounce (PORT) Exposure
**Description:** Checks whether the server accepts a PORT command pointing at an address the scanner chose - the first step of the classic FTP bounce / third-party transfer attack - using only safe probe destinations.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- PORT to a private-range destination (default 198.18.0.1:53, override with destip/destport)
- routable and loopback destinations are refused by the script itself (SAFE_PROBE_RANGES)
- 200 + a 150/125 data-connection reply -> HIGH (bounce-capable: internal port scans, file relaying)
- 501/500/530 refusals -> INFO (bounce disabled or unauthenticated)
- no data transfer is ever performed

**How to Execute:**
```bash
# Basic scan (safe private-range destination)
nmap -p 21 --script ftp-bounce-check target.example.com

# Custom probe destination
nmap -p 21 --script ftp-bounce-check --script-args 'ftp-bounce-check.destip=198.18.0.1 ftp-bounce-check.destport=53' target.example.com
```

**Sample Output:**
```
| ftp-bounce-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP bounce (third-party PORT) capability tested.
|   Findings:
|     [HIGH] after the external PORT was accepted the server opened the data
|            transfer sequence (150/125) - a full FTP bounce is executable from this host
|            (bounce-executable) [evidence: Opening data channel for transfer.]
|     [MEDIUM] the server accepted PORT with an external address
|            (198,18,0,1,0,53); it will attempt outbound data connections to
|            attacker-chosen hosts (port-external-accepted) [evidence: PORT command
|            successful.]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 11
|   Requests issued: 4
|   banner: 227 Welcome to the vsftpd FTP daemon
|   bounce_transfer_response: Opening data channel for transfer.
|   port_response: PORT command successful.
|   probe_notes:
|     1: bounce destination is 198.18.0.1:53 (RFC 2544 benchmarking range)
|     2: login attempt: success
|     3: PORT 198,18,0,1,0,53 answered 200
|     4: NLST after external PORT answered 150
|     5: final transfer code 226
```

---

### 8. **ftp-brute-rate-limit** - Login Rate Limiting and Lockout
**Description:** Tests whether the daemon throttles, hints at, or enforces a lockout after consecutive failed logins - the property that decides how fast a password brute-force can run.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- N consecutive failed logins as a probe user (default 8, maxattempts capped at 50)
- lockout signals: connection drop, 421 service-unavailable, 'too many' / 'account locked' text markers (LOCKOUT_TEXT_MARKERS)
- latency progression via clock_ms to detect progressive throttling
- 230-accept guard: the probe stops immediately if the password ever succeeds
- no lockout and no throttling -> MEDIUM (unthrottled brute-force surface)

**How to Execute:**
```bash
# Basic scan (8 probe attempts)
nmap -p 21 --script ftp-brute-rate-limit target.example.com

# Stricter probe (more attempts, longer per-request timeout)
nmap -p 21 --script ftp-brute-rate-limit --script-args 'ftp-brute-rate-limit.maxattempts=20 ftp-brute-rate-limit.timeout=3000' target.example.com
```

**Sample Output:**
```
| ftp-brute-rate-limit:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP brute-force rate limiting tested.
|   Findings:
|     [MEDIUM] 8 consecutive failed logins completed with no lockout, no 421 close
|            and no lockout hint; the daemon does not rate-limit failed attempts
|            (no-rate-limiting) [evidence: codes 530,530,530,530,530,530,530,530]
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 4
|   Requests issued: 9
|   attempts_completed: 8
|   avg_latency_ms: 0
|   banner: 227 Welcome to the vsftpd FTP daemon
|   probe_notes:
|     1: attempt 1: USER 331 PASS 530
|     2: attempt 2: USER 331 PASS 530
|     3: attempt 3: USER 331 PASS 530
|     4: attempt 4: USER 331 PASS 530
|     5: attempt 5: USER 331 PASS 530
|     6: attempt 6: USER 331 PASS 530
|     7: attempt 7: USER 331 PASS 530
|     8: attempt 8: USER 331 PASS 530
|   reply_codes:
|     1: 530
|     2: 530
|     3: 530
|     4: 530
|     5: 530
|     6: 530
|     7: 530
|     8: 530
```

---

### 9. **ftp-cleartext-enforcement** - Cleartext Login Enforcement
**Description:** Determines whether the server accepts plaintext USER/PASS sessions without first negotiating TLS, and whether FTPS is offered as the protected alternative.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- FEAT AUTH advertisement on the first connection
- AUTH TLS / AUTH SSL acceptance on dedicated connections (234 vs 504/530)
- plaintext USER/PASS on a fresh connection (anonymous by default, user/password args supported)
- matrix verdicts: plaintext accepted while TLS is offered -> MEDIUM (no enforcement); plaintext refused with 534 -> INFO (TLS enforced); no AUTH at all -> MEDIUM (cleartext-only endpoint)

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-cleartext-enforcement target.example.com

# Test a specific account
nmap -p 21 --script ftp-cleartext-enforcement --script-args 'ftp-cleartext-enforcement.user=ftpuser ftp-cleartext-enforcement.password=secret' target.example.com
```

**Sample Output:**
```
| ftp-cleartext-enforcement:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP cleartext login enforcement tested.
|   Findings:
|     [MEDIUM] plaintext login with anonymous succeeded although the server
|            advertises AUTH; credentials are accepted unencrypted because TLS is not
|            enforced (cleartext-accepted-no-enforcement) [evidence: Login successful.
|            Restrictions apply.]
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 4
|   Requests issued: 5
|   auth_ssl_code: 504
|   auth_ssl_offered: false
|   auth_tls_code: 234
|   auth_tls_offered: true
|   banner: 227 Welcome to the vsftpd FTP daemon
|   plaintext_login_class: success
|   plaintext_login_codes: USER 331, PASS 230
|   probe_notes:
|     1: FEAT answered 211
|     2: AUTH TLS answered 234
|     3: AUTH SSL answered 504
```

---

### 10. **ftp-command-enum** - Command Surface Enumeration
**Description:** Enumerates the FTP command surface - what the RFC 959 core supports, which extensions are present, and which of the implemented commands carry known risk.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- SYST, FEAT and HELP declarations (advertised feature set)
- 38 bare commands probed (core + extensions; QUIT kept for last and the session ends cleanly)
- per-command classification: implemented / unimplemented / no-response
- historically risky implementations flagged individually (MEDIUM each): SITE, CPFR, CPTO, RNFR, RNTO, REST, SMNT, STAT

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-command-enum target.example.com
```

**Sample Output:**
```
| ftp-command-enum:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP command surface enumerated.
|   Findings:
|     [MEDIUM] CPFR is implemented: CPFR (mod_copy copy-from) is present; with
|            CPTO it enables unauthenticated file copying on ProFTPD builds
|            (CVE-2015-3306 class) (risky-command-CPFR)
|     [MEDIUM] CPTO is implemented: CPTO (mod_copy copy-to) is present; see CPFR
|            for the mod_copy risk (risky-command-CPTO)
|     [MEDIUM] REST is implemented: REST (restart position) is implemented;
|            restart semantics can be abused for partial-upload races on writable servers
|            (risky-command-REST)
|     [MEDIUM] RNFR is implemented: RNFR (rename-from) is implemented; with a
|            writable jail it enables overwriting existing objects (risky-command-RNFR)
|     [MEDIUM] RNTO is implemented: RNTO (rename-to) is implemented; part of the
|            rename chain used to overwrite objects (risky-command-RNTO)
|     [MEDIUM] SITE is implemented: SITE exposes host-specific commands; on
|            several daemons this is the entry point to command execution and file
|            manipulation (risky-command-SITE)
|     [MEDIUM] SMNT is implemented: SMNT (second mount point) is implemented; can
|            expose alternate filesystem roots (risky-command-SMNT)
|     [MEDIUM] STAT is implemented: STAT is implemented; can disclose session
|            state and configuration details (risky-command-STAT)
|     [LOW] command surface: 38 implemented, 0 unimplemented, 0 unresponsive out
|            of 39 probed (command-surface)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=8 LOW=1 INFO=1
|   Weighted score: 35
|   Requests issued: 42
|   banner: 227 Welcome to the vsftpd FTP daemon
|   declared_features:
|     1: 211 (FEAT)
|     2: EPSV (HELP)
|     3: LIST (HELP)
|     4: MDTM (HELP)
|     5: MKD (HELP)
|     6: MLST (HELP)
|     7: NLST (HELP)
|     8: NOOP (HELP)
|     9: PASS (HELP)
|     10: PASV (HELP)
|     11: PBSZ (HELP)
|     12: AUTH (HELP)
|     13: PORT (HELP)
|     14: PROT (HELP)
|     15: PWD (HELP)
|     16: QUIT (HELP)
|     17: RENAM (HELP)
|     18: RETR (HELP)
|     19: RMD (HELP)
|     20: SITE (HELP)
|     21: SIZE (HELP)
|     22: STOR (HELP)
|     23: CDUP (HELP)
|     24: USER (HELP)
|     25: UTF8 (FEAT)
|     26: CPFR (HELP)
|     27: CPTO (HELP)
|     28: CWD (HELP)
|     29: DELE (HELP)
|     30: END (HELP)
|     31: EPRT (HELP)
|   implemented_commands:
|     1: NOOP
|     2: NLST
|     3: LIST
|     4: RETR
|     5: STOR
|     6: APPE
|     7: DELE
|     8: RNFR
|     9: RNTO
|     10: REST
|     11: SIZE
|     12: USER
|     13: MDTM
|     14: MLST
|     15: MLSD
|     16: PASV
|     17: EPSV
|     18: PORT
|     19: EPRT
|     20: ACCN
|     21: ABOR
|     22: STAT
|     23: PWD
|     24: HELP
|     25: SITE
|     26: CLNT
|     27: HOST
|     28: LANG
|     29: SMNT
|     30: CPFR
|     31: CPTO
|     32: AUTH
|     33: CWD
|     34: CDUP
|     35: MKD
|     36: RMD
|     37: TYPE
|     38: MODE
|   os_class: UNIX (Unix)
|   probe_notes:
|     1: FEAT advertises 9 feature line(s)
|     2: TYPE -> 200 (implemented)
|     3: MODE -> 200 (implemented)
|     4: NLST -> 150 (implemented)
|     5: LIST -> 226 (implemented)
|     6: RETR -> 200 (implemented)
|     7: STOR -> 226 (implemented)
|     8: APPE -> 200 (implemented)
|     9: DELE -> 250 (implemented)
|     10: RNFR -> 200 (implemented)
|     11: RNTO -> 200 (implemented)
|     12: HELP lists 29 command tokens
|     13: REST -> 200 (implemented)
|     14: SIZE -> 213 (implemented)
|     15: MDTM -> 213 (implemented)
|     16: MLST -> 550 (implemented)
|     17: MLSD -> 200 (implemented)
|     18: PASV -> 227 (implemented)
|     19: EPSV -> 229 (implemented)
|     20: PORT -> 200 (implemented)
|     21: EPRT -> 200 (implemented)
|     22: ACCN -> 200 (implemented)
|     23: NOOP -> 200 (implemented)
|     24: ABOR -> 200 (implemented)
|     25: STAT -> 211 (implemented)
|     26: HELP -> 214 (implemented)
|     27: SITE -> 200 (implemented)
|     28: CLNT -> 200 (implemented)
|     29: HOST -> 200 (implemented)
|     30: LANG -> 200 (implemented)
|     31: SMNT -> 200 (implemented)
|     32: CPFR -> 250 (implemented)
|     33: CPTO -> 250 (implemented)
|     34: USER -> 331 (implemented)
|     35: AUTH -> 504 (implemented)
|     36: PWD -> 257 (implemented)
|     37: CWD -> 250 (implemented)
|     38: CDUP -> 250 (implemented)
|     39: MKD -> 257 (implemented)
|     40: RMD -> 250 (implemented)
|   unimplemented_commands: {}
```

---

### 11. **ftp-directory-listing** - Directory Listing and Sensitive Entries
**Description:** Logs in (anonymously by default) and lists the landing directory plus common subdirectories, classifying what an unauthenticated or low-privilege visitor can see.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- root NLST + LIST plus 6 common subdirectories (uploads, www, public_html, incoming, outgoing, tmp)
- sensitive-name rules: backup archives, database dumps, dotfiles, version-control metadata, editor temp files -> MEDIUM or HIGH by class
- world-writable listing entries -> MEDIUM (unauthenticated upload surface)
- findings deduped per entry name with all observed paths collected

**How to Execute:**
```bash
# Basic scan (anonymous listing)
nmap -p 21 --script ftp-directory-listing target.example.com

# List as a specific account
nmap -p 21 --script ftp-directory-listing --script-args 'ftp-directory-listing.user=ftpuser ftp-directory-listing.password=secret' target.example.com
```

**Sample Output:**
```
| ftp-directory-listing:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP directory listing captured.
|   Findings:
|     [MEDIUM] sensitive entry //.htaccess is visible in the listing: Apache
|            configuration or password file (sensitive-entry-.htaccess) [paths:
|            //.htaccess]
|     [MEDIUM] sensitive entry //backup.tar.gz is visible in the listing: backup
|            artifact (sensitive-entry-backup.tar.gz) [paths: //backup.tar.gz]
|     [MEDIUM] sensitive entry //database.sql is visible in the listing: backup or
|            editor temp file (sensitive-entry-database.sql) [paths: //database.sql]
|     [MEDIUM] world-writable entry //public_html is visible; unauthenticated or
|            low-privilege upload may be possible there
|            (world-writable-entry-public_html) [paths: //public_html]
|     [MEDIUM] world-writable entry //readme.txt is visible; unauthenticated or
|            low-privilege upload may be possible there (world-writable-entry-readme.txt)
|            [paths: //readme.txt]
|     [LOW] directory listing is permitted for anonymous: 63 entries visible
|            across 7 directory(ies) (listing-permitted)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=5 LOW=1 INFO=0
|   Weighted score: 22
|   Requests issued: 10
|   banner: 227 Welcome to the vsftpd FTP daemon
|   landing_dir: "/pub/ftp" is the current directory.
|   listed_directories:
|     1: /
|     2: uploads
|     3: www
|     4: public_html
|     5: incoming
|     6: outgoing
|     7: tmp
|   probe_notes:
|     1: session established as anonymous
|     2: root LIST returned 9 entries
|     3: subdirectory uploads returned 9 entries
|     4: subdirectory www returned 9 entries
|     5: subdirectory public_html returned 9 entries
|     6: subdirectory incoming returned 9 entries
|     7: subdirectory outgoing returned 9 entries
|     8: subdirectory tmp returned 9 entries
|   totals: 63 entries in 7 listed directories (28 directories, 35 files)
```

---

### 12. **ftp-passive-mode-check** - Passive Mode Data Channel
**Description:** Sends PASV and EPSV, inspects the advertised data-channel address and port, and verifies the data connection actually completes.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- PASV (227) and EPSV (229) address:port parsing
- advertised-address classification: 0.0.0.0 -> MEDIUM (client picks the address), loopback, RFC1918 from a public server, unroutable
- active data-connection attempt against the advertised endpoint (timeout/refusal reported)
- PORT/EPRT availability cross-check

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-passive-mode-check target.example.com
```

**Sample Output:**
```
| ftp-passive-mode-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP passive data-channel modes checked.
|   Findings:
|     [MEDIUM] PASV data-channel problem: server advertises 0.0.0.0 as the
|            data-channel address; external clients cannot connect to the data channel
|            (pasv-non-routable)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 5
|   Requests issued: 3
|   banner: 227 Welcome to the vsftpd FTP daemon
|   epsv_address: (control host):50001
|   epsv_classification: ephemeral-range
|   epsv_connect: completed
|   pasv_address: 0.0.0.0:50048
|   pasv_classification: non-routable
|   pasv_connect: completed
|   probe_notes:
|     1: pasv advertised 0.0.0.0:50048 -> non-routable
|     2: PASV data connection to 0.0.0.0:50048 completed
|     3: epsv advertised (control host):50001 -> ephemeral-range
|     4: EPSV data connection to port 50001 completed
```

---

### 13. **ftp-tls-cipher-audit** - FTPS TLS Cipher Audit
**Description:** Audits the TLS protocol versions and cipher suites the FTP server will actually negotiate over explicit FTPS (AUTH TLS), each probe on a fresh connection.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- gate: AUTH TLS must be accepted (else INFO ft-ps-unavailable and stop)
- baseline handshake: negotiated version + cipher, DHE parameter size -> HIGH if 1024-bit or less (Logjam class)
- TLS 1.3 availability probe (supported_versions + GREASE-free cipher set)
- legacy protocol probes: SSLv3 -> HIGH (POODLE), TLS 1.0 / 1.1 -> MEDIUM (RFC 8996 deprecation)
- cipher-family probes on a TLS 1.2 hello: NULL -> HIGH, DES/export -> HIGH, RC4 -> MEDIUM, 3DES -> MEDIUM (Sweet32)

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-tls-cipher-audit target.example.com
```

**Sample Output:**
```
| ftp-tls-cipher-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTPS (AUTH TLS) protocol and cipher audit.
|   Findings:
|     [HIGH] DES is negotiable over FTPS (server picked TLS_RSA_WITH_RC4_40_MD5):
|            single-DES and 40-bit export DES are trivially breakable (weak-cipher-des)
|            [evidence: TLS_RSA_WITH_RC4_40_MD5]
|     [HIGH] NULL encryption is negotiable over FTPS (server picked
|            TLS_RSA_WITH_NULL_MD5): NULL ciphers provide no confidentiality at all
|            (weak-cipher-null-encryption) [evidence: TLS_RSA_WITH_NULL_MD5]
|     [HIGH] SSLv3 is negotiable over FTPS: SSLv3 is broken by design (POODLE,
|            CVE-2014-3566) and must not be negotiable (legacy-protocol-sslv3) [evidence:
|            SSLv3/TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
|     [HIGH] the default FTPS negotiation uses 1024-bit Diffie-Hellman; 1024-bit
|            DH is within reach of sophisticated attackers (Logjam class) (weak-dh)
|            [evidence: DH 1024 bits]
|     [MEDIUM] 3DES is negotiable over FTPS (server picked
|            TLS_RSA_WITH_3DES_EDE_CBC_SHA): 3DES is vulnerable to the Sweet32 birthday
|            attack (CVE-2016-2183) (weak-cipher-3des) [evidence:
|            TLS_RSA_WITH_3DES_EDE_CBC_SHA]
|     [MEDIUM] RC4 is negotiable over FTPS (server picked
|            TLS_RSA_WITH_3DES_EDE_CBC_SHA): RC4 is broken (biases, RFC 7465 deprecation)
|            and must not be negotiable (weak-cipher-rc4) [evidence:
|            TLS_RSA_WITH_3DES_EDE_CBC_SHA]
|     [MEDIUM] TLS 1.0 is negotiable over FTPS: TLS 1.0 is deprecated by RFC 8996
|            and should not be negotiable (legacy-protocol-tls-1.0) [evidence: TLS
|            1.0/TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
|     [MEDIUM] TLS 1.1 is negotiable over FTPS: TLS 1.1 is deprecated by RFC 8996
|            and should not be negotiable (legacy-protocol-tls-1.1) [evidence: TLS
|            1.1/TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
|   Severity counts: CRITICAL=0 HIGH=4 MEDIUM=4 LOW=0 INFO=0
|   Weighted score: 44
|   Requests issued: 1
|   auth_tls_code: 234
|   banner: 227 Welcome to the vsftpd FTP daemon
|   baseline_cipher: TLS_DHE_RSA_WITH_AES_256_CBC_SHA
|   baseline_dh_bits: 1024
|   baseline_protocol: TLS 1.2
|   probe_notes:
|     1: AUTH TLS accepted; starting the probe set
|     2: 3DES: accepted (TLS 1.2/TLS_RSA_WITH_3DES_EDE_CBC_SHA)
|     3: baseline: accepted (TLS 1.2/TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
|     4: TLS 1.3: rejected (alert fatal:no_application_protocol)
|     5: SSLv3: accepted (SSLv3/TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
|     6: TLS 1.0: accepted (TLS 1.0/TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
|     7: TLS 1.1: accepted (TLS 1.1/TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
|     8: NULL encryption: accepted (TLS 1.2/TLS_RSA_WITH_NULL_MD5)
|     9: RC4: accepted (TLS 1.2/TLS_RSA_WITH_3DES_EDE_CBC_SHA)
|     10: DES: accepted (TLS 1.2/TLS_RSA_WITH_RC4_40_MD5)
|   tls13: not offered
```

---

### 14. **ftp-tls-support** - Explicit FTPS Support
**Description:** Checks whether the server supports explicit FTPS (AUTH TLS / AUTH SSL) and, when it does, confirms the TLS handshake completes and reports the negotiated protocol and certificate.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- FEAT AUTH advertisement
- AUTH TLS handshake: negotiated protocol version + cipher suite
- certificate summary: subject CN, issuer, validity window, signature-algorithm class (weak signature -> MEDIUM)
- AUTH SSL probe on a dedicated connection
- state classification: healthy (INFO), handshake alert / broken (MEDIUM), TLS refused (LOW), plaintext-only (MEDIUM)

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-tls-support target.example.com
```

**Sample Output:**
```
| ftp-tls-support:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP explicit TLS (FTPS) support checked.
|   Findings:
|     [MEDIUM] the FTPS certificate is signed with a weak algorithm (MD5); clients
|            with modern policy will reject the session (ftps-weak-signature)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 5
|   Requests issued: 5
|   auth_advertised: true
|   auth_ssl_code: 504
|   auth_tls_code: 234
|   banner: 227 Welcome to the vsftpd FTP daemon
|   certificate: validity=365d
|   certificate_signature_class: weak
|   probe_notes:
|     1: FEAT answered 211
|     2: AUTH TLS answered 234
|     3: AUTH SSL answered 504
|   tls_cipher: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
|   tls_verification: handshake
|   tls_version: TLS 1.2
```

---

### 15. **ftp-writable-dirs** - Writable Directory Test
**Description:** Tests which FTP directories are writable by the logged-in account using small marker files and marker directories that are deleted immediately after each test.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- login as anonymous by default (user/password args supported)
- up to maxdirs directories (default 3) from: /, uploads, www, public_html, incoming, tmp
- per directory: CWD -> MKD probe dir -> STOR marker file -> DELE -> RMD (full in-run cleanup)
- writable -> MEDIUM per directory; web-root names (www, public_html, htdocs, web) -> HIGH
- cleanup gaps -> MEDIUM with the exact manual-removal path

**How to Execute:**
```bash
# Basic scan (self-cleaning markers)
nmap -p 21 --script ftp-writable-dirs target.example.com

# Test more directories as a specific account
nmap -p 21 --script ftp-writable-dirs --script-args 'ftp-writable-dirs.user=ftpuser ftp-writable-dirs.password=secret ftp-writable-dirs.maxdirs=6' target.example.com
```

**Sample Output:**
```
| ftp-writable-dirs:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - FTP writable directories tested with self-cleaning markers.
|   Findings:
|     [MEDIUM] / is writable by anonymous; files can be staged there without
|            authentication beyond the FTP login (writable-directory/) [evidence:
|            directory is accessible; STOR accepted (226); marker deleted (250); marker
|            directory removed (250)]
|     [MEDIUM] /uploads is writable by anonymous; files can be staged there
|            without authentication beyond the FTP login (writable-directory/uploads)
|            [evidence: directory is accessible; STOR accepted (226); marker deleted
|            (250); marker directory removed (250)]
|     [MEDIUM] /www is writable by anonymous; files can be staged there without
|            authentication beyond the FTP login (writable-directory/www) [evidence:
|            directory is accessible; STOR accepted (226); marker deleted (250); marker
|            directory removed (250)]
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=3 LOW=0 INFO=0
|   Weighted score: 12
|   Requests issued: 6
|   banner: 227 Welcome to the vsftpd FTP daemon
|   directory_results:
|     1: 
|   landing_dir: "/pub/ftp" is the current directory.
|   probe_notes:
|     1: session established as anonymous
|     2: /: writable
|     3: /uploads: writable
|     4: /www: writable
|     5: maxdirs limit reached (3); remaining directories skipped
|   write_summary: 3 writable, 0 read-only, 0 inaccessible of 3 tested
```

---

### 16. **ftp-syst-fingerprint** - SYST and FEAT Fingerprint
**Description:** Fingerprints the FTP daemon and operating-system class from SYST, FEAT and the banner, and summarizes the RFC extension surface.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- SYST system type + OS hint (UNIX Type: L8, Windows_NT, DOS, VM...)
- FEAT extension map with per-feature risk notes (EPSV, MLST, AUTH, MDTM, UTF8, SITE, ...)
- banner cross-check against the declared feature set
- LOW fingerprint summary + INFO notes for notable extensions

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-syst-fingerprint target.example.com
```

**Sample Output:**
```
| ftp-syst-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - FTP daemon and OS fingerprinted.
|   Findings:
|     [LOW] daemon fingerprint: vsftpd on Unix (9 FEAT extensions) (fingerprint)
|            [evidence: 227 Welcome to the vsftpd FTP daemon]
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=1 INFO=2
|   Weighted score: 4
|   Requests issued: 4
|   backdoor_banner: yes (227 + vsftpd)
|   banner: 227 Welcome to the vsftpd FTP daemon
|   benign_features:
|     1: 211
|     2: AUTH
|     3: EPSV
|     4: MLST
|     5: PASV
|     6: SIZE
|     7: UTF8
|   daemon_family: vsftpd
|   notable_features:
|     1: 
|   os_class: Unix
|   probe_notes:
|     1: banner family: vsftpd
|     2: SYST: UNIX Type: L8
|     3: FEAT returned 9 feature line(s)
|     4: STAT answered 211
|   stat: 211-Status:
|   syst_type: UNIX
|   vendor: vsftpd project
```

## 🧪 Typical Scan

```bash
# Full FTP audit of an endpoint
nmap -p 21 --script ftp-* target.example.com

# Include the alternate FTP port and a known account
nmap -p 21,2121 --script ftp-* --script-args 'ftp-directory-listing.user=ftpuser ftp-directory-listing.password=secret' target.example.com
```
