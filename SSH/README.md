# 🔑 SSH Security Audits

**16 Nmap NSE scripts** for auditing SSH-2 servers (RFC 4251-4253, RFC 4256):

**Covers:**

- The regreSSHion pre-auth RCE (CVE-2024-6387)
- The libssh publickey authentication bypass (CVE-2018-10933)
- Terrapin prefix-truncation exposure (CVE-2023-48795)
- Weak cipher/key-exchange/MAC negotiation
- Root login exposure
- Password authentication availability
- MaxAuthTries tolerance measurement
- SSH agent forwarding permission
- Host key size and fingerprint auditing
- Authentication method enumeration
- Keyboard-interactive disclosure
- Legacy compression support
- Unauthenticated banner grabbing with a built-in CVE table

Every script speaks real SSH-2 bytes over TCP - identification exchange, KEXINIT algorithm negotiation, host key capture, USERAUTH requests and channel/channel-request exchanges - and turns the observed protocol facts into evidence-based findings.

All probes are bounded (request budgets, timeouts, bounded attempt loops), send no valid credentials by default, and never modify server state.

**Ports:** 22 or matched `ssh` service | **Protocol:** SSH-2 (RFC 4251 transport layer / RFC 4252 user authentication) over plain TCP | **Total lines of Lua:** 29,319

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [ssh-libssh-bypass-check](#1-ssh-libssh-bypass-check---cve-2018-10933-publickey-bypass) | 🔴 CRITICAL | vuln, safe | 1839 |
| 2 | [ssh-regresshion-cve-check](#2-ssh-regresshion-cve-check---cve-2024-6387-pre-auth-rce) | 🔴 CRITICAL | vuln, safe | 1831 |
| 3 | [ssh-terrapin-vulnerability](#3-ssh-terrapin-vulnerability---cve-2023-48795-prefix-truncation) | 🔴 CRITICAL | vuln, safe | 1868 |
| 4 | [ssh-weak-ciphers](#4-ssh-weak-ciphers---legacy-and-broken-cipher-negotiation) | 🔴 CRITICAL | vuln, safe | 1817 |
| 5 | [ssh-root-login-allowed](#5-ssh-root-login-allowed---permitrootlogin-exposure) | 🟠 HIGH | vuln, safe | 1833 |
| 6 | [ssh-weak-kex-algorithms](#6-ssh-weak-kex-algorithms---logjam-and-sha-1-key-exchange) | 🟠 HIGH | vuln, safe | 1816 |
| 7 | [ssh-weak-macs](#7-ssh-weak-macs---broken-and-pre-etm-mac-negotiation) | 🟠 HIGH | vuln, safe | 1837 |
| 8 | [ssh-agent-forwarding-probe](#8-ssh-agent-forwarding-probe---agent-forwarding-permission) | 🟡 MEDIUM | discovery, safe | 1826 |
| 9 | [ssh-auth-methods-enum](#9-ssh-auth-methods-enum---authentication-method-inventory) | 🟡 MEDIUM | discovery, safe | 1854 |
| 10 | [ssh-hostkey-size-audit](#10-ssh-hostkey-size-audit---small-or-deprecated-host-keys) | 🟡 MEDIUM | defensive, safe | 1848 |
| 11 | [ssh-max-auth-tries](#11-ssh-max-auth-tries---maxauthtries-tolerance-measurement) | 🟡 MEDIUM | defensive, safe | 1847 |
| 12 | [ssh-password-auth-allowed](#12-ssh-password-auth-allowed---brute-force-surface-exposure) | 🟡 MEDIUM | defensive, safe | 1839 |
| 13 | [ssh-compression-support](#13-ssh-compression-support---legacy-zlib-exposure) | 🟢 LOW | discovery, safe | 1810 |
| 14 | [ssh-hostkey-fingerprint](#14-ssh-hostkey-fingerprint---key-rotation-monitoring) | 🟢 LOW | discovery, safe | 1788 |
| 15 | [ssh-keyboard-interactive-info](#15-ssh-keyboard-interactive-info---challenge-method-disclosure) | 🟢 LOW | discovery, safe | 1842 |
| 16 | [ssh-unauth-banner-grab](#16-ssh-unauth-banner-grab---banner-capture-with-cve-table) | 🟢 LOW | discovery, safe | 1824 |

---

### 1. **ssh-libssh-bypass-check** - CVE-2018-10933 Publickey Bypass
**Description:** Detects embedded libssh builds in the CVE-2018-10933 vulnerable range (0.0.1 through 0.8.2, fixed in 0.8.3), where an attacker can bypass publickey authentication by submitting an empty publickey challenge and then completing authentication as any user with an empty password.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Identification string parse for `libssh-<version>` vendor signatures
- Version comparison against the 0.0.1-0.8.2 affected window (fixed in 0.8.3)
- Vendor disambiguation so OpenSSH/Dropbear servers report "not applicable" with evidence
- CVSS 9.8 verdict when a vulnerable libssh build is identified

**How to Execute:**
```bash
nmap -p 22 --script ssh-libssh-bypass-check target.example.com

# Probe with a specific account name in the userauth phase
nmap -p 22 --script ssh-libssh-bypass-check --script-args ssh-libssh-bypass-check.test_user=audit target.example.com
```

**Sample Output:**
```
| ssh-libssh-bypass-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - CVE-2018-10933 libssh 0.8.2 publickey authentication bypass
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] libssh version is in the CVE-2018-10933 vulnerable range (libssh 0.8.2)
|   libssh Bypass Evidence:
|     Affected range: 0.0.1 through 0.8.2
|     Fixed in: 0.8.3
|     Identification string: SSH-2.0-libssh-0.8.2
|     Vendor: libssh
|     Verdict: vulnerable
|     Version: 0.8.2
```

---

### 2. **ssh-regresshion-cve-check** - CVE-2024-6387 Pre-Auth RCE
**Description:** Parses the SSH identification string and checks the OpenSSH version against the regreSSHion vulnerable range (8.5 through 9.7, fixed in 9.8), a pre-authentication signal-handler race that yields remote code execution as root without credentials.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Identification string vendor/version parse (OpenSSH, libssh, Dropbear, etc.)
- Version comparison against the affected range 8.5-9.7 with patch-level (`pN`) handling
- KEXINIT context dump (negotiated ciphers/kex/MACs) for the report
- CVSS 8.5 verdict, evidence line, and per-finding rationale

**How to Execute:**
```bash
nmap -p 22 --script ssh-regresshion-cve-check target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-regresshion-cve-check --script-args 'ssh-regresshion-cve-check.maxrequests=8,ssh-regresshion-cve-check.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-regresshion-cve-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - CVE-2024-6387 regreSSHion: OpenSSH 8.9p1 in pre-auth RCE range
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] OpenSSH version is in the regreSSHion (CVE-2024-6387) vulnerable range (OpenSSH 8.9p1)
|   regreSSHion Evidence:
|     Affected range: 8.5 through 9.7
|     Fixed in: 9.8
|     Identification string: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
|     Vendor: OpenSSH
|     Verdict: vulnerable
|     Version: 8.9p1
```

---

### 3. **ssh-terrapin-vulnerability** - CVE-2023-48795 Prefix Truncation
**Description:** Checks the server's KEXINIT lists for Terrapin exposure: the `chacha20-poly1305@openssh.com` cipher is offered while non-Encrypt-then-MAC MACs remain negotiable, the exact policy combination the prefix-truncation attack exploits.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Presence of `chacha20-poly1305@openssh.com` in both cipher directions
- EtM MAC inventory (`-etm@openssh.com` variants) versus non-EtM MACs per direction
- Server identity (vendor/version) for context
- Exposure verdict: gated cipher + non-EtM MACs offered = exposed; cipher absent or EtM-only = secure

**How to Execute:**
```bash
nmap -p 22 --script ssh-terrapin-vulnerability target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-terrapin-vulnerability --script-args 'ssh-terrapin-vulnerability.maxrequests=8,ssh-terrapin-vulnerability.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-terrapin-vulnerability:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Terrapin (CVE-2023-48795): chacha20-poly1305 offered without enforced Encrypt-then-MAC
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] Server offers the Terrapin-gated cipher without an EtM-only MAC policy (chacha20-poly1305@openssh.com)
|   Terrapin Exposure Analysis:
|     chacha20-poly1305 offered (client-to-server): yes
|     chacha20-poly1305 offered (server-to-client): yes
|     Non-EtM MACs offered (client-to-server): hmac-md5, hmac-sha1, hmac-sha2-256
|     EtM MACs offered (client-to-server): hmac-sha2-256-etm@openssh.com
```

---

### 4. **ssh-weak-ciphers** - Legacy and Broken Cipher Negotiation
**Description:** Audits the server-offered cipher suites in both KEXINIT directions against a classification table of broken, weak and modern ciphers (3DES, RC4/ARCFOUR, CBC-mode AES, GCM/AEAD and CTR modern sets), reporting every weak instance with its reason.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Full cipher list extraction from KEXINIT (client-to-server and server-to-client)
- Per-algorithm classification: broken (3des-cbc, arcfour*), weak (CBC modes), modern (GCM/CTR/chacha20)
- Unknown-algorithm tracking for non-standard or new cipher names
- Per-instance HIGH findings plus an aggregate CRITICAL when any weak cipher is offered

**How to Execute:**
```bash
nmap -p 22 --script ssh-weak-ciphers target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-weak-ciphers --script-args 'ssh-weak-ciphers.maxrequests=8,ssh-weak-ciphers.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-weak-ciphers:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - SSH server offers 8 weak cipher instance(s)
|   Severity counts: CRITICAL=1 HIGH=8 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] Server offers weak or deprecated ciphers in its KEXINIT list (cipher suite)
|     [HIGH] Weak cipher offered: c2s: 3des-cbc [broken key size, CBC mode]
|     [HIGH] Weak cipher offered: c2s: arcfour128 [broken stream cipher]
|     [HIGH] Weak cipher offered: s2c: aes256-cbc [CBC mode (ETM recommended)]
|   Cipher Audit (client-to-server):
|     Weak / deprecated offered: 3des-cbc [broken key size, CBC mode]; arcfour128 [broken stream cipher]; aes128-cbc [CBC mode (ETM recommended)]; aes256-cbc [CBC mode (ETM recommended)]
|     Modern offered: aes128-ctr, aes256-ctr, chacha20-poly1305@openssh.com
```

---

### 5. **ssh-root-login-allowed** - PermitRootLogin Exposure
**Description:** Determines whether the `root` account is accepted into the SSH authentication phase by comparing a USERAUTH `none` probe for `root` against one for a guaranteed-nonexistent user; a server that answers root with a method list while dropping the other exposes root to credential attacks.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Session A: USERAUTH (method `none`) for the configured root user
- Session B: control probe with a random 16-character nonexistent username
- Differential classification: root survived + control dropped = root reachable
- Methods offered to root (password offered => additional MEDIUM finding)

**How to Execute:**
```bash
nmap -p 22 --script ssh-root-login-allowed target.example.com

# Override the root account name
nmap -p 22 --script ssh-root-login-allowed --script-args ssh-root-login-allowed.root_user=root target.example.com
```

**Sample Output:**
```
| ssh-root-login-allowed:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - SSH server allows user 'root' into the authentication phase
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [HIGH] root (or the configured root_user) is accepted into SSH authentication (user root)
|     [MEDIUM] root authentication offers password-based methods (root authentication methods)
|   Session A: probe user 'root':
|     Detail: server responded with a method list (authentication phase accepted)
|     Offered methods: publickey,password
|     Outcome: survived
|   Session B: probe user 'nmap-yp9bmecevlgr':
|     Detail: server closed the connection during authentication
|     Outcome: dropped
```

---

### 6. **ssh-weak-kex-algorithms** - Logjam and SHA-1 Key Exchange
**Description:** Audits the server-offered key-exchange algorithms for weak or broken groups - DH group 1 (1024-bit MODP, Logjam), DH group 14 with SHA-1 and other pre-2014 groups - and flags when a weak group is listed first in the server preference order.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Full KEX list extraction from KEXINIT
- Classification: broken (group1-sha1), weak (group14-sha1), modern (curve25519, ECDSA, group16/18, GEX-sha256/512)
- Negotiation-order risk: weak group first = default pick for permissive clients
- Unknown-algorithm tracking

**How to Execute:**
```bash
nmap -p 22 --script ssh-weak-kex-algorithms target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-weak-kex-algorithms --script-args 'ssh-weak-kex-algorithms.maxrequests=8,ssh-weak-kex-algorithms.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-weak-kex-algorithms:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - SSH server offers 2 weak key-exchange algorithm(s)
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [HIGH] Server offers weak or deprecated key-exchange groups (key exchange)
|     [MEDIUM] Weak kex group is first in the server preference order (diffie-hellman-group1-sha1)
|   Key Exchange Audit:
|     Offered list: diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,curve25519-sha256
|     Weak / deprecated offered: diffie-hellman-group1-sha1 [1024-bit DH, SHA-1 (Logjam)]; diffie-hellman-group14-sha1 [SHA-1 (upgrade to -sha256)]
|     Negotiation order risk: WEAK group listed first: diffie-hellman-group1-sha1 (default pick for permissive clients)
```

---

### 7. **ssh-weak-macs** - Broken and Pre-EtM MAC Negotiation
**Description:** Audits the server-offered MAC algorithms in both KEXINIT directions against a classification table (MD5-based, SHA-1-based, SHA-2, and Encrypt-then-MAC variants) and assesses the server's overall Encrypt-then-MAC posture.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Full MAC list extraction from KEXINIT (client-to-server and server-to-client)
- Per-MAC classification: broken (hmac-md5*), weak (hmac-sha1), modern (hmac-sha2-*, umac-128)
- EtM posture: whether `-etm@openssh.com` variants are offered and whether non-EtM MACs remain negotiable
- Per-instance findings plus aggregate exposure verdict

**How to Execute:**
```bash
nmap -p 22 --script ssh-weak-macs target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-weak-macs --script-args 'ssh-weak-macs.maxrequests=8,ssh-weak-macs.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-weak-macs:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - SSH server offers 4 weak MAC instance(s)
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [HIGH] Server offers weak or deprecated MACs in its KEXINIT list (MAC suite)
|     [MEDIUM] Server allows non-EtM MAC negotiation (Encrypt-then-MAC policy)
|   MAC Audit (client-to-server):
|     Offered list: hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha2-256-etm@openssh.com
|     Weak / deprecated offered: hmac-md5 [MD5-based]; hmac-sha1 [SHA-1 (upgrade to sha2)]
|     Modern offered: hmac-sha2-256, hmac-sha2-256-etm@openssh.com
```

---

### 8. **ssh-agent-forwarding-probe** - Agent Forwarding Permission
**Description:** Authenticates with documented test credentials, opens a session channel and issues the `agent-foreground-openssh` channel request to determine whether the server permits SSH agent forwarding - which would let a compromised server use the user's private keys.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Full userauth exchange (password method with the documented audit account)
- CHANNEL_OPEN for a session channel + confirmation
- `agent-foreground-openssh` channel request: CHANNEL_SUCCESS (permitted) vs. CHANNEL_FAILURE (denied)
- Session teardown and posture verdict

**How to Execute:**
```bash
nmap -p 22 --script ssh-agent-forwarding-probe target.example.com

# Specify the audit account and password
nmap -p 22 --script ssh-agent-forwarding-probe --script-args 'ssh-agent-forwarding-probe.test_user=audit,ssh-agent-forwarding-probe.test_password=your-audit-password' target.example.com
```

**Sample Output:**
```
| ssh-agent-forwarding-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - SSH server permits agent forwarding (agent-foreground-openssh)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Agent forwarding is permitted on the server (agent-foreground-openssh)
|   Agent Forwarding Probe:
|     Session channel open: confirmed (remote channel id 0)
|     agent-foreground-openssh request: CHANNEL_SUCCESS - agent forwarding PERMITTED
|   Authentication Step:
|     Method list for audit: publickey,password
|     Password authentication: accepted (documented test credentials)
```

---

### 9. **ssh-auth-methods-enum** - Authentication Method Inventory
**Description:** Requests the server's offered authentication methods for the audit account and produces a full inventory with per-method risk notes (password brute-force surface, key-based rotation needs, Kerberos delegation, host-based trust).

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- USERAUTH `none` probe for the configured audit user
- Method list parse and per-method annotation table
- Password-method presence (MEDIUM finding when offered)
- Method count and raw list for the report

**How to Execute:**
```bash
nmap -p 22 --script ssh-auth-methods-enum target.example.com

# Specify the audit account
nmap -p 22 --script ssh-auth-methods-enum --script-args ssh-auth-methods-enum.test_user=audit target.example.com
```

**Sample Output:**
```
| ssh-auth-methods-enum:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - SSH server offers password authentication
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Server offers password-based authentication (method list)
|   Authentication Method Inventory:
|     Offered method list: publickey,password
|     Method count: 2
|     Inventory: publickey - key-based authentication; rotate and audit authorized_keys; password - enables password brute-force / credential stuffing
```

---

### 10. **ssh-hostkey-size-audit** - Small or Deprecated Host Keys
**Description:** Captures the host key presented by the server (SSH_MSG_KEXDH_REPLY or the equivalent in the exchange) and audits the key type and bit length against current minimums (RSA < 2048 = below minimum, RSA 2048-3071 = target, DSA/1024-bit RSA = deprecated).

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Host key wire parse (key type string + key blob, RSA modulus bit length)
- Size classification: weak (below minimum) / acceptable / target / deprecated
- Per-type deprecation notes (e.g. ssh-rsa acceptable only at >= 2048 bits)
- Fingerprint context and remediation guidance

**How to Execute:**
```bash
nmap -p 22 --script ssh-hostkey-size-audit target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-hostkey-size-audit --script-args 'ssh-hostkey-size-audit.maxrequests=8,ssh-hostkey-size-audit.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-hostkey-size-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - SSH host key is below the minimum size (ssh-rsa, 1024 bits)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Server presents a small or deprecated host key (ssh-rsa)
|   Host Key Audit:
|     Key type: ssh-rsa
|     Key strength: 1024 bits
|     Classification: weak
|     Deprecation note: acceptable only with RSA >= 2048 bits
```

---

### 11. **ssh-max-auth-tries** - MaxAuthTries Tolerance Measurement
**Description:** Measures how many consecutive failed password authentications the server tolerates before closing the connection, using a bounded sequence (default 8, hard cap 8) of deliberately wrong passwords for the audit account, then classifies the observed tolerance.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Method-list probe (USERAUTH `none`) to confirm the account reaches the auth phase
- Bounded failed-password loop (default 8 attempts, documented wrong password only)
- Per-attempt trace: USERAUTH_FAILURE vs. connection-closed-by-server
- Tolerance classification: <= 3 hardened, 4-6 OpenSSH default, 7-8 (or still open) loose

**How to Execute:**
```bash
nmap -p 22 --script ssh-max-auth-tries target.example.com

# Specify the audit account and the attempt budget
nmap -p 22 --script ssh-max-auth-tries --script-args 'ssh-max-auth-tries.test_user=audit,ssh-max-auth-tries.maxtries=8' target.example.com
```

**Sample Output:**
```
| ssh-max-auth-tries:
|   Risk Level: 🟡 MEDIUM
|   Status: CAUTION - SSH server closed after 6 failed attempts (OpenSSH default range)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [INFO] Authentication tolerance is at the OpenSSH default
|   Attempt Trace:
|     method none probe: methods offered: publickey,password
|     attempt 1: USERAUTH_FAILURE (still connected)
|     attempt 6: USERAUTH_FAILURE (still connected)
|     attempt 7: connection closed by server
```

---

### 12. **ssh-password-auth-allowed** - Brute-Force Surface Exposure
**Description:** Requests the authentication method list for the audit account and reports whether password-based methods (password / keyboard-interactive) are offered, i.e. whether the server exposes an online brute-force and credential-stuffing surface.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- USERAUTH `none` probe for the configured audit user
- Method list parse (publickey, password, keyboard-interactive, gssapi-with-mic, hostbased)
- Password-method presence classification (password or kbd-interactive password flows)
- Method context and hardening guidance

**How to Execute:**
```bash
nmap -p 22 --script ssh-password-auth-allowed target.example.com

# Specify the audit account
nmap -p 22 --script ssh-password-auth-allowed --script-args ssh-password-auth-allowed.test_user=audit target.example.com
```

**Sample Output:**
```
| ssh-password-auth-allowed:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - SSH server offers password authentication
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Password-based authentication is available on this server (method password)
|   Method List Analysis:
|     Probe user: audit
|     Offered method list: publickey,password
|     Password method offered: yes (password)
```

---

### 13. **ssh-compression-support** - Legacy zlib Exposure
**Description:** Inspects the server-offered compression algorithms in both KEXINIT directions and flags the legacy bare `zlib` variant (pre-MAC compression, CVE-2006-5051 context) versus the safe `zlib@openssh.com` (compression after MAC) and `none`.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Compression list extraction from KEXINIT (both directions)
- Variant classification: `none` (safe), `zlib` (legacy), `zlib@openssh.com` (safe)
- Legacy-presence verdict with per-direction detail
- Unknown-variant tracking

**How to Execute:**
```bash
nmap -p 22 --script ssh-compression-support target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-compression-support --script-args 'ssh-compression-support.maxrequests=8,ssh-compression-support.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-compression-support:
|   Risk Level: 🟢 LOW
|   Status: CAUTION - SSH server offers legacy zlib compression (CVE-2006-5051 context)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Legacy 'zlib' compression variant offered by the server (zlib)
|   Compression (client-to-server):
|     Offered list: none,zlib,zlib@openssh.com
|     Legacy zlib present: yes
|     Entries: none [no compression - always safe]; zlib [LEGACY variant - pre-MAC compression]; zlib@openssh.com [OpenSSH-safe variant (compression after MAC)]
```

---

### 14. **ssh-hostkey-fingerprint** - Key Rotation Monitoring
**Description:** Captures the server's host key from the key-exchange reply and computes both the legacy MD5 and modern SHA256 fingerprints (plus key type and bit length) for asset inventorying, known_hosts baselining and rotation-change alerting.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Host key wire parse (key type + key blob)
- MD5 and SHA256 fingerprint computation over the key blob
- Key strength (bit length) for context
- Rotation-monitoring guidance (schedule re-runs, alert on change)

**How to Execute:**
```bash
nmap -p 22 --script ssh-hostkey-fingerprint target.example.com

# Custom budget/timeout
nmap -p 22 --script ssh-hostkey-fingerprint --script-args 'ssh-hostkey-fingerprint.maxrequests=8,ssh-hostkey-fingerprint.timeout=10' target.example.com
```

**Sample Output:**
```
| ssh-hostkey-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - host key fingerprint captured (ssh-rsa)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [INFO] no weaknesses detected by this audit
|   Host Key Fingerprint:
|     Key type: ssh-rsa
|     Key strength: 1024 bits
|     MD5 fingerprint: 74:5a:ba:4a:32:bb:14:87:57:86:15:46:50:fd:46:06
|     SHA256 fingerprint: SHA256:gBJcYtUY+sb4tIfh94TB8SpqzF1gfVVPLjzM9TQt0po=
```

---

### 15. **ssh-keyboard-interactive-info** - Challenge Method Disclosure
**Description:** Checks whether the server offers the `keyboard-interactive` authentication method for the audit account and reports the full method list, useful for identifying PAM-based challenge flows that may disclose custom prompts or second-factor behavior.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- USERAUTH `none` probe for the configured audit user
- Method list parse with keyboard-interactive presence flag
- Full offered-method context for the report
- Minimal-surface guidance when the method is not needed

**How to Execute:**
```bash
nmap -p 22 --script ssh-keyboard-interactive-info target.example.com

# Specify the audit account
nmap -p 22 --script ssh-keyboard-interactive-info --script-args ssh-keyboard-interactive-info.test_user=audit target.example.com
```

**Sample Output:**
```
| ssh-keyboard-interactive-info:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - keyboard-interactive is not offered by this server
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [INFO] no weaknesses detected by this audit
|   Method List Analysis:
|     Probe user: audit
|     Offered method list: publickey,password
|     keyboard-interactive offered: no
```

---

### 16. **ssh-unauth-banner-grab** - Banner Capture with CVE Table
**Description:** Reads the SSH identification string without completing the exchange and evaluates the disclosed vendor/version against a built-in CVE table (regreSSHion CVE-2024-6387, Terrapin CVE-2023-48795 gating, libssh bypass CVE-2018-10933) to flag unpatched versions from a single pre-auth packet.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Raw identification string capture (protocol field, software vendor, version)
- Vendor/version parse with patch-level handling
- CVE table evaluation per entry (applicable / vulnerable / not exposed)
- Version-disclosure hardening guidance

**How to Execute:**
```bash
nmap -p 22 --script ssh-unauth-banner-grab target.example.com

# Custom timeout
nmap -p 22 --script ssh-unauth-banner-grab --script-args ssh-unauth-banner-grab.timeout=10 target.example.com
```

**Sample Output:**
```
| ssh-unauth-banner-grab:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Banner retrieved; 1 CVE table entry in vulnerable range
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Banner version matches 1 known-vulnerable table entries (OpenSSH 8.9p1)
|   Identification Analysis:
|     Raw identification string: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
|     Protocol field: 2.0
|     Software vendor: OpenSSH
|     Software version: 8.9p1
|   CVE Table Evaluation:
|     CVE-2024-6387: regreSSHion (pre-auth signal handler race) - vulnerable
|     CVE-2023-48795: not exposed (chacha20-poly1305 not offered)
|     CVE-2018-10933: not applicable
```

## 🛡️ Safety & Scope

- All scripts are **non-destructive**: they read server state (identification, KEXINIT lists, method lists, host key, channel-request responses) and never modify configuration, accounts, or keys.
- Probes are **bounded**: request budgets (`maxrequests`), timeouts, retries and inter-request delays are configurable per script; authentication probes use only the documented audit account and deliberately wrong or explicitly supplied test credentials.
- No valid production credentials are required or stored; scripts that need an authenticated session (agent forwarding) fail informatively when the test account is unavailable.
