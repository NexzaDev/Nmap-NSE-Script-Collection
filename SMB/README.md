# 🔐 SMB Security Audits

**16 Nmap NSE scripts** for auditing SMB file services:

**Covers:**

- Protocol dialects and downgrade exposure
- Anonymous/guest/null session access
- IPC$ and administrative share reachability
- NTLM authentication downgrade
- Message signing enforcement
- DFS topology leakage and service fingerprinting

Every script speaks the SMB wire protocol directly (SMB 1.0 and SMB 2/3 negotiate, NTLM/NTLMv2 session setup, tree connect, echo), parses the binary responses, and reports evidence-based verdicts.

**Port:** 139/tcp + 445/tcp (80/443 for the WebDAV script) | **Protocol:** SMB (SMBv1 / SMB2 / SMB3) | **Total lines of Lua:** 25,131

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [smb-eternalblue-precondition](#1-smb-eternalblue-precondition---smb-eternalblue-precondition) | 🔴 CRITICAL | vuln, safe | 1624 |
| 2 | [smb-smbghost-precondition](#2-smb-smbghost-precondition---smb-smbghost-precondition) | 🔴 CRITICAL | vuln, safe | 1546 |
| 3 | [smb-anonymous-ipc-pipe](#3-smb-anonymous-ipc-pipe---smb-anonymous-ipc-pipe) | 🟠 HIGH | vuln, safe | 1577 |
| 4 | [smb-extended-security](#4-smb-extended-security---smb-extended-security) | 🟠 HIGH | safe, discovery, vuln | 1569 |
| 5 | [smb-guest-access-check](#5-smb-guest-access-check---smb-guest-access-check) | 🟠 HIGH | safe, discovery, vuln | 1547 |
| 6 | [smb-ntlm-version-downgrade](#6-smb-ntlm-version-downgrade---smb-ntlm-version-downgrade) | 🟠 HIGH | vuln, safe | 1529 |
| 7 | [smb-null-session-check](#7-smb-null-session-check---smb-null-session-check) | 🟠 HIGH | safe, discovery, vuln | 1566 |
| 8 | [smb-share-accessibility](#8-smb-share-accessibility---smb-share-accessibility) | 🟠 HIGH | safe, discovery, vuln | 1556 |
| 9 | [smb-signing-config](#9-smb-signing-config---smb-signing-config) | 🟠 HIGH | safe, discovery, vuln | 1541 |
| 10 | [smb-dfs-referral-leak](#10-smb-dfs-referral-leak---smb-dfs-referral-leak) | 🟡 MEDIUM | discovery, safe | 1536 |
| 11 | [smb-protocol-dialects](#11-smb-protocol-dialects---smb-protocol-dialects) | 🟡 MEDIUM | safe, discovery, vuln | 1597 |
| 12 | [smb-webdav-exposure](#12-smb-webdav-exposure---smb-webdav-exposure) | 🟡 MEDIUM | discovery, safe | 1609 |
| 13 | [smb-buffer-limits](#13-smb-buffer-limits---smb-buffer-limits) | 🟢 LOW | safe, discovery | 1578 |
| 14 | [smb-capabilities](#14-smb-capabilities---smb-capabilities) | 🟢 LOW | safe, discovery | 1596 |
| 15 | [smb-security-level](#15-smb-security-level---smb-security-level) | 🟢 LOW | safe, discovery | 1572 |
| 16 | [smb-version-fingerprint](#16-smb-version-fingerprint---smb-version-fingerprint) | 🟢 LOW | discovery, safe | 1588 |

---

## ⚙️ Common Script Arguments

All 16 scripts share the following `--script-args` (script-specific extras are listed per script):

| Argument | Default | Purpose |
|----------|---------|---------|
| `maxrequests` | per script | Hard request budget for the run |
| `timeout` | 10 | Per-exchange timeout (seconds) |

---

## 📜 Script Details

### 1. **smb-eternalblue-precondition** - Smb Eternalblue Precondition
**Description:** Checks whether the SMB service accepts SMBv1 (NT LM 0.12) dialect negotiation, which is the mandatory precondition for MS17-010 (EternalBlue, CVE-2017-0144) exploitation. A host that refuses SMBv1 dialect negotiation is not exploitable through MS17-010 regardless of patch level; a host that negotiates and services NT LM 0.12 carries the RCE/DoS surface plus legacy LM/NTLMv1 downgrade and relay paths.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- full-dialect negotiate (NT LM 0.12 + SMB 2.002 + SMB 3.1.1 offered)
- SMBv1-only negotiate on a second session (0x0005 rejection = SMBv1 disabled)
- NTLM session completion on the SMBv1 path (negotiated-but-unauthed vs serviceable)
- signing requirement on the modern dialect (relay-friendliness)

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-eternalblue-precondition target.example.com

# Both legacy ports
nmap -p 139,445 --script smb-eternalblue-precondition target.example.com
```

**Sample Output:**
```
| smb-eternalblue-precondition:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - SMBv1 (MS17-010 precondition) negotiation checked.
|   Findings:
|     [CRITICAL] server negotiates and services SMBv1 (NT LM 0.12): the
|                MS17-010 / EternalBlue attack surface (CVE-2017-0144 RCE,
|                CVE-2017-0143 DoS) is present on this host regardless of
|                patch level (smbv1-ms17-010-precondition)
|                [evidence: dialect=NT LM 0.12 ipc$=open]
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 10
```

---

### 2. **smb-smbghost-precondition** - Smb Smbghost Precondition
**Description:** Checks whether the SMB service exposes the SMB 3.1.1 compression/transform code path that CVE-2020-0796 (SMBGhost) requires. SMBGhost is a use-after-free in affected Samba builds (4.13.x/4.14.x/4.15.x) exploitable for unauthenticated RCE; a host that does not select the SMB 3.1.1 dialect cannot be reached through it.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- full-dialect negotiate: selected dialect, SMB2 capability flags, security flags, server GUID
- SMB 3.1.1 selection (the code path where the bug exists)
- transform-framework activity (CAP ENCRYPTION) for elevated confidence
- max transfer sizes and decoded capabilities

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-smbghost-precondition target.example.com
```

**Sample Output:**
```
| smb-smbghost-precondition:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - SMB 3.1.1 compression (SMBGhost precondition) checked.
|   Findings:
|     [CRITICAL] server negotiates SMB 3.1.1: the SMBGhost (CVE-2020-0796)
|                use-after-free in the SMB 3.1.1 compression/transform path
|                is present in affected Samba builds (4.13.0-4.13.13,
|                4.14.0-4.14.5, 4.15.0-4.15.2) - unauthenticated RCE until
|                patched (smbghost-precondition-met)
|   cve_details:
|     CVE-2020-0796: use-after-free in SMB 2/3 compression handling in Samba
|     Exploitation: unauthenticated RCE; public proof-of-concept available since June 2020
|     Affected: Samba 4.13.0-4.13.13, 4.14.0-4.14.5, 4.15.0-4.15.2
```

---

### 3. **smb-anonymous-ipc-pipe** - Smb Anonymous Ipc Pipe
**Description:** Checks whether the anonymous (null) and guest SMB sessions can open the IPC$ share, which exposes the remote procedure call pipes used for domain account enumeration and RPC-based lateral movement. An open IPC$ from an anonymous session is the entry point for SAMR/LSARPC enumeration, NetShareEnum discovery and RPC-based lateral movement; guest access to IPC$ is a weaker variant of the same surface.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- null session (no credentials) establishment + IPC$ tree connect
- guest session establishment + IPC$ tree connect
- service type and access-mask decoding of the granted IPC$ context
- enumerated SAMR/LSARPC surface listing when IPC$ is open

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-anonymous-ipc-pipe target.example.com

# With budget control
nmap -p 445 --script smb-anonymous-ipc-pipe --script-args maxrequests=12 target.example.com
```

**Sample Output:**
```
| smb-anonymous-ipc-pipe:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - anonymous/guest IPC$ reachability checked.
|   Findings:
|     [HIGH] anonymous (null) session can open IPC$: SAMR/LSARPC
|            enumeration and RPC-based lateral movement surface is
|            exposed without credentials (anonymous-ipc-open)
|            [evidence: service=0x80 (IPC (anonymous)) access=GENERIC_READ]
|     [MEDIUM] guest session can open IPC$: same RPC enumeration surface
|            reachable under a constrained account (guest-ipc-open)
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 11
```

---

### 4. **smb-extended-security** - Smb Extended Security
**Description:** Determines whether the SMB server enforces the extended security model (NTLMv2-only authentication via SPNEGO) on the legacy SMBv1 path - the last code path where it can still be negotiated away. SMB2/3 always enforce extended security by construction, so the SMBv1 negotiate capability word (bit 0x80000000) is what matters.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- full-dialect negotiate: modern dialect selection + security flags
- SMBv1-only negotiate: capability word parsing, EXTENDED_SECURITY bit test
- full decode of the SMBv1 capability word (10 bits)
- combined classification (SMBv1 + no extended security = HIGH)

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-extended-security target.example.com
```

**Sample Output:**
```
| smb-extended-security:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - SMB extended security (SMBv1 SPNEGO/NTLMv2 enforcement) checked.
|   Findings:
|     [HIGH] SMBv1 negotiate response does not advertise the EXTENDED_SECURITY
|            capability (0x80000000): legacy SMBv1 sessions may authenticate
|            with NTLMv1 or the plaintext password mode instead of NTLMv2-only
|            SPNEGO (smbv1-no-extended-security)
|            [evidence: smb1_caps=0x00028813]
|   probe_notes:
|     full-dialect probe: SMB 3.1.1 (sec_flags=1 caps=3)
|     SMBv1 probe: negotiated (caps=0x00028813 extended_security=false
|                  max_buf=0 max_mpx=50)
```

---

### 5. **smb-guest-access-check** - Smb Guest Access Check
**Description:** Determines whether the SMB service maps anonymous logins to a guest account and which shares that guest context can open. Guest access is a standing, credential-free foothold: every share the guest can open is readable (or writable) by anyone who can reach port 445/139.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- guest login (user `guest`) with session-setup action-code recording
- share probing under the guest context (IPC$, public, print$, NETLOGON, admin$, c$)
- open/refused status + access mask per share
- grading: open shares = HIGH, session-only = MEDIUM, rejected = INFO

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-guest-access-check target.example.com
```

**Sample Output:**
```
| smb-guest-access-check:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - guest account SMB access checked.
|   Findings:
|     [HIGH] guest account can open 3 of 6 probed shares:
|            credential-free read/write foothold on this host (guest-shares-open)
|            [evidence: ipc$: OPEN (service=0x80 access=GENERIC_READ)
|             | public: OPEN (service=0x01 access=GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE)]
|   share_probes:
|     ipc$: OPEN (service=0x80 access=GENERIC_READ)
|     public: OPEN (service=0x01 access=GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE)
|     print$: OPEN (service=0x03 access=GENERIC_READ|GENERIC_EXECUTE)
```

---

### 6. **smb-ntlm-version-downgrade** - Smb Ntlm Version Downgrade
**Description:** Determines whether the SMB server accepts legacy NTLMv1 authentication in addition to NTLMv2, which enables credential hash downgrade attacks. NTLMv1 (DES-crypt of the LM hash triple) is practically crackable offline; a server that accepts both mechanisms lets the attacker choose the weaker one.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- NTLMv2-forced guest session (baseline)
- NTLMv1-forced guest session on a separate connection
- server acceptance/refusal per mechanism + action codes
- challenge flags cross-check and target name

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-ntlm-version-downgrade target.example.com
```

**Sample Output:**
```
| smb-ntlm-version-downgrade:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - NTLMv1 downgrade exposure checked.
|   Findings:
|     [HIGH] server accepts both NTLMv1 and NTLMv2 authentication: credential
|            hash downgrade to the broken NTLMv1 construction is possible,
|            weakening every SMB login on this host (ntlmv1-accepted)
|            [evidence: ntlm action=success ntlmv2 action=success]
|   ntlm_facts:
|     NTLMv1: DES-crypt of the 7-byte LM hash triple, HMAC-MD5 keyed by the
|             MD4 hash - offline cracking is practical
|     NTLMv2: MD4(NT hash) then HMAC-MD5 keyed by NTOWFv2 - cracking cost
|             increases substantially
```

---

### 7. **smb-null-session-check** - Smb Null Session Check
**Description:** Checks whether the SMB service accepts anonymous (null, no-credential) logins and what share access that context provides. A null session that reaches IPC$ is the classic entry point for domain reconnaissance (SAMR SID enumeration, NetShareEnum, RPC pipe probing); a null session that opens data shares is a direct confidentiality exposure.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- null session (empty username, NTLMv2) establishment
- share probing: IPC$, public, print$, dfs (referral capture)
- access-mask decoding per open share
- grading: IPC$ open = HIGH, data shares only = MEDIUM, refused = INFO

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-null-session-check target.example.com
```

**Sample Output:**
```
| smb-null-session-check:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - anonymous null session access checked.
|   Findings:
|     [HIGH] anonymous (null) session can open IPC$: SAMR/LSARPC enumeration
|            and RPC-based lateral movement surface is exposed without
|            credentials (null-ipc-open)
|     [LOW] anonymous session receives a DFS root referral: internal DFS
|            topology (server names, share paths) is disclosed without
|            authentication (null-dfs-referral)
|   share_probes:
|     ipc$: OPEN (service=0x80 access=GENERIC_READ)
|     public: OPEN (service=0x01 access=GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE)
|     print$: refused (STATUS_ACCESS_DENIED)
|     dfs: REFERRAL (STATUS_MORE_PROCESSING_REQUIRED; 2 entries)
```

---

### 8. **smb-share-accessibility** - Smb Share Accessibility
**Description:** Maps which SMB shares an anonymous or guest session can open, including administrative and drive shares, and flags the high-impact ones. Administrative shares reachable by an anonymous context are effectively open for lateral movement; print$/IPC$ enable RPC-based movement chains; public/data shares are direct confidentiality exposures.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- best available anonymous context (null first, then guest)
- share list probing: IPC$, public, print$, NETLOGON, admin$, C$-F$, USER$, SYSTEM$
- open/refused + service type + access mask per share
- impact grading: admin/drive = CRITICAL, IPC$/print$ = HIGH, data = MEDIUM

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-share-accessibility target.example.com

# Larger budget for the full share list
nmap -p 445 --script smb-share-accessibility --script-args maxrequests=28 target.example.com
```

**Sample Output:**
```
| smb-share-accessibility:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - anonymous share accessibility mapped.
|   Findings:
|     [HIGH] share \\target.example.com\ipc$ is open to the null anonymous
|            context (share-open-ipc$)
|     [MEDIUM] share \\target.example.com\public is open to the null
|              anonymous context (share-open-public)
|   share_table:
|     ipc$: OPEN (service=0x80 access=GENERIC_READ)
|     public: OPEN (service=0x01 access=GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE)
|     print$: OPEN (service=0x03 access=GENERIC_READ|GENERIC_EXECUTE)
|     NETLOGON: refused (STATUS_OBJECT_PATH_NOT_FOUND)
|     admin$: refused (STATUS_ACCESS_DENIED)
```

---

### 9. **smb-signing-config** - Smb Signing Config
**Description:** Determines whether the SMB server enforces message signing (and encryption) on the modern dialects, which is the primary control against SMB relay attacks. The SMB2/3 negotiate SecurityFlags (bit 0 = SIGNING_REQUIRED, bit 1 = ENCRYPTION_REQUIRED) state the server-side policy; a server that leaves signing optional is a relay target.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- SecurityFlags from the SMB2/3 negotiate response (classified)
- SMBv1-only negotiate: legacy fallback availability
- combined exposure (modern dialects unsigned + SMBv1 fallback)
- flag reference table and GPO/Samba remediation

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-signing-config target.example.com
```

**Sample Output:**
```
| smb-signing-config:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - SMB message signing/encryption enforcement checked.
|   Findings:
|     [MEDIUM] SMBv1 (NT LM 0.12) is still negotiable: the legacy path cannot
|              express the modern signing policy and is commonly left unsigned,
|              leaving a relay-friendly fallback (smbv1-unsigned-fallback)
|   flag_classification: signing required
|   probe_notes:
|     full-dialect probe: SMB 3.1.1, security flags: signing required
|     SMBv1 probe: NT LM 0.12 still negotiates (legacy path lacks modern signing flags)
```

---

### 10. **smb-dfs-referral-leak** - Smb Dfs Referral Leak
**Description:** Captures DFS (Distributed File System) root referral responses returned by the SMB server and reports the internal topology they leak: storage cluster hostnames, departmental file-server names and share paths, often mirroring AD site structure.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- best available anonymous context (null, then guest)
- tree connect of the `dfs` root and the 0x0016 referral response
- per-entry parsing: target server name, content path, entry index
- referral disclosure graded by session context (null > guest)

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-dfs-referral-leak target.example.com
```

**Sample Output:**
```
| smb-dfs-referral-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - DFS root referral disclosure checked.
|   Findings:
|     [MEDIUM] DFS root discloses 2 internal server target(s) to a null
|              session: internal hostnames and share paths are leaked
|              without authentication (dfs-anonymous-referral)
|              [evidence: [0] server=file01.corp.example.com content=\dfsroot
|               | [1] server=file02.corp.example.com content=\dfsroot]
|   referral_table:
|     [0] server=file01.corp.example.com content=\dfsroot
|     [1] server=file02.corp.example.com content=\dfsroot
```

---

### 11. **smb-protocol-dialects** - Smb Protocol Dialects
**Description:** Enumerates which SMB protocol dialects the server negotiates and reports the resulting protocol baseline, including whether deprecated SMBv1 is still on the table. The negotiated dialect determines the entire security baseline - a host that offers NT LM 0.12 alongside modern dialects is a downgrade target.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- full-dialect negotiate: selected dialect, security flags, capabilities, GUID
- SMBv1-only negotiate: offered vs refused, capability word + limits
- per-dialect status table and effective baseline
- SMBv1 capability bit decoding

**How to Execute:**
```bash
# Basic scan
nmap -p 139,445 --script smb-protocol-dialects target.example.com
```

**Sample Output:**
```
| smb-protocol-dialects:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - SMB dialect negotiation baseline enumerated.
|   Findings:
|     [MEDIUM] server offers SMBv1 (NT LM 0.12) alongside SMB2/3: sessions can
|              be pinned to the deprecated dialect with its weaker security
|              baseline (smbv1-downgrade-offered)
|              [evidence: smb1 offered; modern selected=SMB 3.1.1]
|   dialect_status:
|     NT LM 0.12: offered
|     SMB 2.002/3.x: offered (selected: SMB 3.1.1)
|   smb1_capabilities:
|     LEVEL_2_OPLOCKS
|     NT_SMBS
|     MPX
|     RAW
```

---

### 12. **smb-webdav-exposure** - Smb Webdav Exposure
**Description:** Checks whether WebDAV content is exposed through the host's file services: SMB shares that look like web content roots (wwwroot, web, webdav, ...) and HTTP front ends that answer DAV negotiation. An anonymous write path to a web root is the classic defacement / webshell foothold.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- on 445/139: anonymous context + web-content share probing (wwwroot, web, webdav, http, www, inetpub) with write-mask detection
- on 80/443: single OPTIONS + DAV header inspection over a raw socket
- grading: web share open = MEDIUM (HIGH when GENERIC_WRITE), DAV front end = LOW

**How to Execute:**
```bash
# Basic scan (SMB side)
nmap -p 445 --script smb-webdav-exposure target.example.com

# HTTP side
nmap -p 80,443 --script smb-webdav-exposure target.example.com
```

**Sample Output:**
```
| smb-webdav-exposure:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - WebDAV / web-content share exposure checked.
|   Findings:
|     [HIGH] web-content share \\target.example.com\web is open to the null
|            context WITH write access: anonymous web defacement / webshell
|            foothold (web-share-write-web)
|            [evidence: access=GENERIC_READ|GENERIC_WRITE]
|   web_share_probes:
|     wwwroot: refused (STATUS_OBJECT_PATH_NOT_FOUND)
|     web: OPEN (service=0x01 access=GENERIC_READ|GENERIC_WRITE)
|     webdav: refused (STATUS_OBJECT_PATH_NOT_FOUND)
```

---

### 13. **smb-buffer-limits** - Smb Buffer Limits
**Description:** Reports the maximum transfer sizes the SMB server advertises in its negotiate responses, for both the legacy SMBv1 (MaxBuffer / MaxMpxCount) and modern SMB2/3 (MaxTransact / MaxRead / MaxWrite) dialects, and flags deviations from the common Windows defaults.

**Risk Level:** 🟢 LOW | **Category:** safe, discovery

**What it checks:**
- MaxTransact / MaxRead / MaxWrite from the SMB2/3 negotiate response
- MaxBuffer / MaxMpxCount from the SMBv1 negotiate response parameters
- deviation from common defaults (16 MB / 1 MB / 1 MB, 64 KB / 50)
- unusually restrictive (proxy-like) or non-standard large values

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-buffer-limits target.example.com
```

**Sample Output:**
```
| smb-buffer-limits:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - SMB advertised transfer limits reported.
|   Findings:
|     [LOW] SMB2/3 advertised transfer limits: transact=16777216 bytes
|           (16.0 MB) read=1048576 bytes (1.0 MB) write=1048576 bytes (1.0 MB)
|     [LOW] SMBv1 advertised limits: MaxBuffer=65536 bytes (64.0 KB)
|           MaxMpxCount=50
```

---

### 14. **smb-capabilities** - Smb Capabilities
**Description:** Decodes the capability flags the SMB server advertises on both dialect paths: the SMBv1 capability word (extended security, large writes, oplocks, RPC support, ...) and the SMB2/3 capability flags (durable handles, leases, multichannel, large MTU, encryption, ...).

**Risk Level:** 🟢 LOW | **Category:** safe, discovery

**What it checks:**
- SMB2 capability flags + security flags from the modern negotiate response
- SMBv1 capability word from the legacy negotiate response parameters
- bit-by-bit decoding of every advertised capability
- notes on absent flags that are commonly expected (ENCRYPTION, EXTENDED_SECURITY, DURABLE_HANDLES)

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-capabilities target.example.com
```

**Sample Output:**
```
| smb-capabilities:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - SMB capability flags decoded.
|   Findings:
|     [LOW] SMB2/3 capabilities advertised on SMB 3.1.1
|           (caps=0x00000003, sec_flags=1)
|     [LOW] SMBv1 capability word advertised (0x00028813)
|   capabilities:
|     SMB2/3 path (SMB 3.1.1) caps=0x00000003
|       DURABLE_HANDLES
|       LEASES
|     SMBv1 path (NT LM 0.12) caps=0x00028813
|       0x00008000 LEVEL_2_OPLOCKS
|       0x00000010 NT_SMBS (32-bit SMB fields)
```

---

### 15. **smb-security-level** - Smb Security Level
**Description:** Reports the effective SMB authentication security level: user-level NTLMv2/SPNEGO on modern dialects versus the legacy SMBv1 authentication modes (NTLMv1, plaintext password) that remain negotiable when EXTENDED_SECURITY is not advertised.

**Risk Level:** 🟢 LOW | **Category:** safe, discovery

**What it checks:**
- full-dialect negotiate: modern path classification (always user-level NTLMv2/SPNEGO) + signing/encryption flags
- SMBv1-only negotiate: EXTENDED_SECURITY bit test
- per-path classification + combined effective security level

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-security-level target.example.com
```

**Sample Output:**
```
| smb-security-level:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - SMB authentication security level classified.
|   Findings:
|     [LOW] SMBv1 path allows legacy authentication modes (no
|           EXTENDED_SECURITY capability): the effective security level of a
|           pinned SMBv1 session drops to NTLMv1/plaintext territory
|     [LOW] modern dialect security level: user-level NTLMv2/SPNEGO
|           (signing required, mechanism=ntlmv2)
|   security_levels:
|     SMB2/3 path (SMB 3.1.1): user-level NTLMv2/SPNEGO
|     SMBv1 path (NT LM 0.12): legacy modes reachable (no EXTENDED_SECURITY)
|     effective security level: legacy authentication modes reachable via
|                               SMBv1 (downgrade risk)
```

---

### 16. **smb-version-fingerprint** - Smb Version Fingerprint
**Description:** Builds a protocol fingerprint of the SMB service from negotiate and session setup responses: dialect, server info strings, NTLM target name, NetBIOS name, server GUID and capability flags, with an OS guess derived from the version strings.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- full-dialect negotiate + guest session: dialect, GUID, capabilities, NTLM target, challenge flags
- SMBv1-only negotiate: capability word, max buffer/multiplex, server info strings
- OS pattern matching (Windows Server 20xx / Windows 10/11 / Samba)
- NetBIOS name reference (port 139 session header)

**How to Execute:**
```bash
# Basic scan
nmap -p 445 --script smb-version-fingerprint target.example.com

# Via NetBIOS
nmap -p 139 --script smb-version-fingerprint target.example.com
```

**Sample Output:**
```
| smb-version-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - SMB service fingerprint assembled.
|   fingerprint:
|     host=target.example.com
|     ip=192.0.2.10
|     port=445
|     dialect=SMB 3.1.1
|     os_guess=Windows Server 2019
|     server_info=Windows Server 2019 17763 / Windows Server / NTFS
|     target_name=CORP
|     netbios_name=CORP
|     capabilities=0x00000003
|     smb1_caps=0x00028813
|     smb1_cap_names=LEVEL_2_OPLOCKS,NT_SMBS,MPX,RAW
```

## 🛡️ Safety Notes

- All 16 scripts are **defensive and non-destructive**: they send standard SMB negotiate / session setup / tree connect / echo exchanges at a polite rate, never send exploit payloads, never write or modify any data, and never flood.
- No credentials are used unless the operator supplies them via `--script-args` (the default probes use empty / `guest` user names only); no NTLM hashes are ever transmitted in cleartext - the NTLM challenge-response is computed locally.
- Every script enforces a `maxrequests` budget; a hostile or rate-limiting server simply stops answering and the audit degrades to evidence-gathering of the refusals.
- The MS17-010 and SMBGhost scripts test **preconditions only** (dialect negotiation and capability advertisement). They are safe to run unpatched-host-adjacent, but the follow-up actions they report (patch state, SMBv1 disablement) are operator responsibilities.
