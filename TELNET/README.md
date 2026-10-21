# 📟 Telnet Security Audits

**16 Nmap NSE scripts** for auditing Telnet/NVT services directly on the wire:

**Covers:**

- A full IAC command-stream codec (WILL/WONT/DO/DONT exchange with escaped 0xFF handling, SB subnegotiations for TTYPE/NAWS/NEW-ENVIRON/AUTHENTICATION/ENCRYPT decoded against the IANA option registry incl. the Microsoft PRAGMA/SSPI-LOGON vendor options)
- RFC 2941 authentication-type and RFC 2946 encryption-type tables
- Staged login-flow probes (login/password/shell/menu/lockout outcome classification with prompt-shape recognition)
- Device and BusyBox signature tables with advisory correlation
- A safe IAC parser-robustness probe (protocol-legal frames only)
- Bounded default-credential auditing (4 pairs by default, hard cap 8)
- A connection-capacity probe (max 8 short-lived sessions)
- Root-login surface detection that never sends a password

**Every probe is a bounded, read-exchange-only session:**

- No crash-inducing frames
- No lockout-triggering loops
- Sessions close as soon as they are classified.

**Ports:** 23/tcp | **Protocol:** Telnet NVT (RFC 854/855), options RFC 856-2946 + vendor 138/139, RFC 1572 NEW-ENVIRON, RFC 2941 AUTHENTICATION | **Total lines of Lua:** 23,869

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [telnet-auth-option-bypass](#1-telnet-auth-option-bypass---authentication-option-bypass-check-rfc-2941) | 🔴 CRITICAL | vuln, safe | 1510 |
| 2 | [telnet-cleartext-warning](#2-telnet-cleartext-warning---cleartext-credential-path-warning) | 🔴 CRITICAL | defensive, safe | 1509 |
| 3 | [telnet-default-credentials](#3-telnet-default-credentials---default-credential-audit) | 🔴 CRITICAL | vuln, safe | 1511 |
| 4 | [telnet-iac-buffer-overflow](#4-telnet-iac-buffer-overflow---iac-parser-robustness-surface) | 🔴 CRITICAL | vuln, safe | 1504 |
| 5 | [telnet-env-var-disclosure](#5-telnet-env-var-disclosure---new-environ-variable-disclosure) | 🟠 HIGH | vuln, safe | 1501 |
| 6 | [telnet-root-login-allowed](#6-telnet-root-login-allowed---root-login-surface-check) | 🟠 HIGH | vuln, safe | 1500 |
| 7 | [telnet-busybox-fingerprint](#7-telnet-busybox-fingerprint---busybox-embedded-telnetd-fingerprint) | 🟡 MEDIUM | discovery, safe | 1495 |
| 8 | [telnet-cisco-login-prompt](#8-telnet-cisco-login-prompt---cisco-style-login-prompt-detection) | 🟡 MEDIUM | discovery, safe | 1491 |
| 9 | [telnet-encrypt-option-audit](#9-telnet-encrypt-option-audit---rfc-2946-encryption-option-audit) | 🟡 MEDIUM | defensive, safe | 1478 |
| 10 | [telnet-max-connections-dos](#10-telnet-max-connections-dos---connection-capacity-behaviour) | 🟡 MEDIUM | defensive, safe | 1468 |
| 11 | [telnet-terminal-type-dos](#11-telnet-terminal-type-dos---terminal-type-handling-robustness) | 🟡 MEDIUM | defensive, safe | 1479 |
| 12 | [telnet-windows-auth-ntlm](#12-telnet-windows-auth-ntlm---windows-telnet--ntlm-sspi-fingerprint) | 🟡 MEDIUM | discovery, safe | 1485 |
| 13 | [telnet-banner-grab](#13-telnet-banner-grab---login-banner-capture) | 🟢 LOW | discovery, safe | 1491 |
| 14 | [telnet-escape-character-enum](#14-telnet-escape-character-enum---escape-character--nvt-control-enum) | 🟢 LOW | discovery, safe | 1471 |
| 15 | [telnet-option-negotiation](#15-telnet-option-negotiation---full-option-negotiation-map) | 🟢 LOW | discovery, safe | 1482 |
| 16 | [telnet-subnegotiation-leak](#16-telnet-subnegotiation-leak---subnegotiation-disclosure-map) | 🟢 LOW | discovery, safe | 1494 |

---

### 1. **telnet-auth-option-bypass** - AUTHENTICATION Option Bypass Check (RFC 2941)
**Description:** Probes the RFC 2941 AUTHENTICATION option (option 37) and the login flow

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Scans whether the server negotiates option 37 (DO/WILL) and decodes any AUTHENTICATION subnegotiation (requested types).
- Performs one bounded login-flow probe to observe whether password prompts appear without any authentication option.
- Grades the bypass conditions against the auth type table.
- Why it matters: Telnet without the AUTHENTICATION option transmits credentials in cleartext and accepts any caller: the login screen itself is the bypass. When option 37 is offered, weak types (NULL, NTLM, SRA) re-open the door the option was supposed to close.
- Safety: option negotiation plus one rejected login attempt with a non-existent audit user; no real credentials are used.

**How to Execute:**
```bash
nmap -p 23 --script telnet-auth-option-bypass switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-auth-option-bypass --script-args 'telnet-auth-option-bypass.timeout=8,telnet-auth-option-bypass.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-auth-option-bypass:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - no RFC 2941 authentication negotiated and the login flow accepts cleartext credentials
```

---

### 2. **telnet-cleartext-warning** - Cleartext Credential Path Warning
**Description:** Grades the cleartext exposure of the telnet service end to end: option

**Risk Level:** 🔴 CRITICAL | **Category:** defensive, safe

**What it checks:**
- Reads the option flight and scans for authentication/encryption/ Start-TLS offers.
- Runs one rejected login attempt to prove the credential path is served in cleartext.
- Emits the exposure verdict with migration guidance.
- Why it matters: Telnet sends every keystroke - including passwords - unencrypted; a single on-path observer captures full credentials. Options 37/38/46 exist exactly to close this gap; their absence is the finding.
- Safety: negotiation plus one rejected audit login; no real credentials and no traffic interception beyond the auditor's own session.

**How to Execute:**
```bash
nmap -p 23 --script telnet-cleartext-warning switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-cleartext-warning --script-args 'telnet-cleartext-warning.timeout=8,telnet-cleartext-warning.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-cleartext-warning:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - full cleartext credential path: no authentication, encryption or Start-TLS negotiated
```

---

### 3. **telnet-default-credentials** - Default Credential Audit
**Description:** Tests a bounded list of factory-default telnet credential pairs and

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Confirms a login prompt exists.
- Attempts at most guesslimit well-known pairs with full prompt-flow detection (login, password, shell/menu outcomes).
- Stops at the first acceptance and records the evidence trail.
- Why it matters: Embedded devices, switches and appliance consoles ship with admin/admin, cisco/cisco and similar pairs that operators rarely change on telnet-exposed management interfaces. A single working default pair over telnet yields interactive device control in cleartext.
- Safety: four pairs maximum (hard cap 8), one connection per pair, no lockout-triggering loops, no further actions after a success.

**How to Execute:**
```bash
nmap -p 23 --script telnet-default-credentials switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-default-credentials --script-args 'telnet-default-credentials.timeout=8,telnet-default-credentials.maxrequests=64,telnet-default-credentials.guesslimit=4' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-default-credentials:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - default credential accepted: admin/admin
```

---

### 4. **telnet-iac-buffer-overflow** - IAC Parser Robustness Surface
**Description:** Probes the IAC/subnegotiation parsing surface with legal-but-stressful

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends an escaped-data probe and a bounded legal subnegotiation.
- Re-checks service health on a fresh connection.
- Correlates the banner family with the advisory table.
- Why it matters: Historic telnetd builds (BusyBox pre-1.30, netkit CVE-2020-10188 lineage) mishandle crafted IAC streams; the parser is pre-auth attack surface. The audit measures parser sanity without ever sending a crash-inducing payload.
- Safety: two small, protocol-legal probes (<= 70 bytes each) and a health re-check; no overflow payloads, no malformed lengths.

**How to Execute:**
```bash
nmap -p 23 --script telnet-iac-buffer-overflow switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-iac-buffer-overflow --script-args 'telnet-iac-buffer-overflow.timeout=8,telnet-iac-buffer-overflow.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-iac-buffer-overflow:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - telnetd family carries IAC-handling advisories (BusyBox pre-1.30 embedded telnetd)
```

---

### 5. **telnet-env-var-disclosure** - NEW-ENVIRON Variable Disclosure
**Description:** Requests the server environment via the NEW-ENVIRON option (RFC 1572,

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Completes the banner negotiation, then sends a NEW-ENVIRON SEND for the standard variable set.
- Decodes IS/INFO subnegotiations into name/value rows.
- Grades the disclosure.
- Why it matters: Environment values leak usernames, home directories and internal paths - exactly the data needed to aim credential attacks. Older stacks also echo OLD-ENVIRON (option 36) data, which predates the size fixes for the 1995-era env-disclosure bugs.
- Safety: one read-only environment request per session.

**How to Execute:**
```bash
nmap -p 23 --script telnet-env-var-disclosure switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-env-var-disclosure --script-args 'telnet-env-var-disclosure.timeout=8,telnet-env-var-disclosure.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-env-var-disclosure:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - server discloses environment data via NEW-ENVIRON (USER, admin, HOME, /root, PATH, /bin:/sbin, SHELL, /bin/sh)
```

---

### 6. **telnet-root-login-allowed** - Root Login Surface Check
**Description:** Checks whether the root account is reachable through the telnet login

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Opens the login flow and sends "root" (or a configured user) once.
- Records the next stage: password prompt (surface exists), immediate denial, or lockout.
- Never sends a password - the probe stops at the first stage.
- Why it matters: Direct root telnet couples the highest-privilege account with a cleartext transport and an online guessing surface. Many hardened stacks refuse root before the password stage; that distinction is exactly what this audit measures.
- Safety: one username submission, zero passwords, connection closed right after the observed stage.

**How to Execute:**
```bash
nmap -p 23 --script telnet-root-login-allowed switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-root-login-allowed --script-args 'telnet-root-login-allowed.timeout=8,telnet-root-login-allowed.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-root-login-allowed:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - root accepted at the login stage over telnet (password prompt shown)
```

---

### 7. **telnet-busybox-fingerprint** - BusyBox Embedded Telnetd Fingerprint
**Description:** Fingerprints BusyBox-based embedded telnetd from the banner (version

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Reads the banner and extracts the BusyBox version and build date.
- Correlates the version against the advisory family table.
- Reports the embedded-stack verdict.
- Why it matters: BusyBox telnetd ships on millions of IoT/ICS devices; pre-1.30 builds carry long-known telnet and shell advisories. Knowing the exact build anchors the device in time (EOL status, unpatched CVE exposure).
- Safety: banner read only.

**How to Execute:**
```bash
nmap -p 23 --script telnet-busybox-fingerprint switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-busybox-fingerprint --script-args 'telnet-busybox-fingerprint.timeout=8,telnet-busybox-fingerprint.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-busybox-fingerprint:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - embedded BusyBox telnetd 1.20.2 (pre-1.30 advisory family)
```

---

### 8. **telnet-cisco-login-prompt** - Cisco-Style Login Prompt Detection
**Description:** Detects Cisco-style login flows on telnet: the "User Access

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Reads the greeting and classifies the Cisco markers.
- Follows the prompt flow one step (a non-existent audit user) to see whether the service asks password-only.
- Reports the IOS-style exposure.
- Why it matters: Cisco IOS telnet (vty lines) is a classic management surface; its exposure history (default vty access, easy vty brute force) makes the fingerprint directly actionable. Password-only prompts indicate no local username enforcement.
- Safety: one connection and one rejected audit username; no password guessing.

**How to Execute:**
```bash
nmap -p 23 --script telnet-cisco-login-prompt switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-cisco-login-prompt --script-args 'telnet-cisco-login-prompt.timeout=8,telnet-cisco-login-prompt.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-cisco-login-prompt:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - no Cisco-style login markers on this telnet service
```

---

### 9. **telnet-encrypt-option-audit** - RFC 2946 Encryption Option Audit
**Description:** Audits RFC 2946 Telnet Encryption (option 38) support: whether the

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Scans for option 38 negotiation (DO/WILL).
- Decodes ENCRYPT SUPPORT subnegotiations into named cipher types.
- Pairs the encryption posture with the cleartext login state.
- Why it matters: The encryption option (DES/3DES/CAST era) is the only in-protocol transport protection telnet ever standardised; its types are cryptographically deprecated but still better than nothing. A server that offers encryption but also serves cleartext logins gives clients an unsafe default.
- Safety: option negotiation plus one rejected login attempt.

**How to Execute:**
```bash
nmap -p 23 --script telnet-encrypt-option-audit switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-encrypt-option-audit --script-args 'telnet-encrypt-option-audit.timeout=8,telnet-encrypt-option-audit.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-encrypt-option-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - no RFC 2946 encryption offered; credentials ride the stream in cleartext (login state failed-retry)
```

---

### 10. **telnet-max-connections-dos** - Connection Capacity Behaviour
**Description:** Measures connection capacity behaviour within strictly safe bounds:

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Opens up to probecount sequential connections (hard cap 8).
- Records banner service and closes each session at once.
- Classifies limiting behaviour (none, partial, strict).
- Why it matters: Unbounded telnet capacity is a classic exhaustion target (device consoles often cap at 1-4 sessions by design). Documented acceptance behaviour shows whether the daemon applies any session limiting before an attacker measures it differently.
- Safety: at most eight short-lived sessions, one at a time; no flooding, no held connections, never exhausting the service.

**How to Execute:**
```bash
nmap -p 23 --script telnet-max-connections-dos switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-max-connections-dos --script-args 'telnet-max-connections-dos.timeout=8,telnet-max-connections-dos.maxrequests=64,telnet-max-connections-dos.probecount=5' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-max-connections-dos:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - every probe session served (5/5); no limit within the safe bound
```

---

### 11. **telnet-terminal-type-dos** - Terminal-Type Handling Robustness
**Description:** Sends a protocol-legal, 60-character terminal-type value in the TTYPE

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Completes the banner negotiation.
- Sends one TTYPE IS with a 60-byte legal value.
- Records the daemon's response/behaviour and re-checks the banner family advisories.
- Why it matters: Several embedded telnetd builds mishandle long or unusual TTYPE values; the parser runs pre-authentication. The audit gauges parser robustness without ever sending a crash-inducing payload.
- Safety: one bounded legal subnegotiation (66 bytes total); no oversized or malformed frames are sent.

**How to Execute:**
```bash
nmap -p 23 --script telnet-terminal-type-dos switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-terminal-type-dos --script-args 'telnet-terminal-type-dos.timeout=8,telnet-terminal-type-dos.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-terminal-type-dos:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - long TTYPE accepted by a flagged telnetd family (BusyBox pre-1.30 embedded telnetd)
```

---

### 12. **telnet-windows-auth-ntlm** - Windows Telnet / NTLM-SSPI Fingerprint
**Description:** Fingerprints Microsoft telnet servers and their NTLM/SSPI authentication

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Reads the banner and classifies Microsoft markers.
- Scans for vendor logon options (138/139) and standard option 37 authentication.
- Reports the Windows authentication posture.
- Why it matters: Windows telnetd authenticates through NTLM/SSPI; the option presence identifies the platform and its credential handling. NTLM over telnet exposes challenge/response material and keeps the deprecated service alive in the estate.
- Safety: banner read plus option negotiation only; no NTLM exchange is initiated.

**How to Execute:**
```bash
nmap -p 23 --script telnet-windows-auth-ntlm switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-windows-auth-ntlm --script-args 'telnet-windows-auth-ntlm.timeout=8,telnet-windows-auth-ntlm.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-windows-auth-ntlm:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - not a Windows telnet server (no Microsoft markers or vendor logon options)
```

---

### 13. **telnet-banner-grab** - Login Banner Capture
**Description:** Captures the telnet login banner and the initial option negotiation,

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Opens a session and reads the greeting until the first prompt.
- Classifies the banner (vendors, BusyBox version, firmware, OS hint).
- Reports the option flight that accompanied the banner.
- Why it matters: Telnet banners are historically chatty: device models, firmware builds and internal hostnames leak to anyone connecting to 23/tcp. The same banner feeds every other fingerprint in this folder.
- Safety: one connection closed after the greeting; nothing is submitted.

**How to Execute:**
```bash
nmap -p 23 --script telnet-banner-grab switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-banner-grab --script-args 'telnet-banner-grab.timeout=8,telnet-banner-grab.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-banner-grab:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - banner captured with build identity (F3.2)
```

---

### 14. **telnet-escape-character-enum** - Escape Character / NVT Control Enum
**Description:** Enumerates the telnet control-plane behaviours available to a client:

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Reads the banner and searches for escape-character mentions.
- Sends one AYT and records the response (NOP/GA/text reply).
- Reports GA suppression and timing-mark behaviour.
- Why it matters: The control verbs (AYT, GA, IP/BRK) reveal how faithfully the daemon implements the NVT spec and shape out-of-band behaviour clients rely on. Escape-character banners (Cisco-style "escape character is '^]'") fingerprint the platform family.
- Safety: one AYT per session; control verbs never include IP/AO which would abort sessions on some stacks.

**How to Execute:**
```bash
nmap -p 23 --script telnet-escape-character-enum switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-escape-character-enum --script-args 'telnet-escape-character-enum.timeout=8,telnet-escape-character-enum.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-escape-character-enum:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - control plane responsive (AYT answered)
```

---

### 15. **telnet-option-negotiation** - Full Option Negotiation Map
**Description:** Maps the full telnet option negotiation: the server's initial WILL/DO

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Captures the initial option flight with the banner.
- Sends DO probes for the audit option set and records WILL/WONT answers plus subnegotiations.
- Renders the complete negotiation map.
- Why it matters: The option map is the protocol-level fingerprint of the daemon and the fastest way to spot unsafe capabilities (encryption offered but unused, vendor logon options, missing SGA). Every other telnet check in this folder keys off this map.
- Safety: option negotiation only; no login data sent.

**How to Execute:**
```bash
nmap -p 23 --script telnet-option-negotiation switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-option-negotiation --script-args 'telnet-option-negotiation.timeout=8,telnet-option-negotiation.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-option-negotiation:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - negotiation map captured (6 entries; auth=false, encrypt=false)
```

---

### 16. **telnet-subnegotiation-leak** - Subnegotiation Disclosure Map
**Description:** Enumerates the subnegotiations a telnet server initiates or echoes

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Captures server-initiated subnegotiations in the banner flight.
- Completes one TTYPE reply and observes whether the daemon echoes or re-queries.
- Classifies every observed subnegotiation into a disclosure class.
- Why it matters: Server-initiated TTYPE/NAWS/ENVIRON requests make clients broadcast their terminal identity, window size and environment before any auth. The subneg map shows which client-disclosure surfaces the daemon exercises by default.
- Safety: option/subnegotiation exchanges only; the TTYPE value is a generic audit string.

**How to Execute:**
```bash
nmap -p 23 --script telnet-subnegotiation-leak switch01.corp.example.com

# Tuned request budget
nmap -p 23 --script telnet-subnegotiation-leak --script-args 'telnet-subnegotiation-leak.timeout=8,telnet-subnegotiation-leak.maxrequests=32' switch01.corp.example.com
```

**Sample Output:**
```
| telnet-subnegotiation-leak:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - server queries client terminal identity (TTYPE=true, NAWS=true)
```

