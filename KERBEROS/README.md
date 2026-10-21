# 🎟️ Kerberos Security Audits

**16 Nmap NSE scripts** for auditing Kerberos key distribution centres directly on the wire:

**Covers:**

- A full ASN.1/DER codec (APPLICATION-class AS-REQ/AS-REP/TGS-REQ/KRB-ERROR messages, PA-DATA builders for ENC-TIMESTAMP, ETYPE-INFO2, FX-FAST, anonymous PKINIT, FOR-USER, PAC-REQUEST and REQ-ENC-PA-REP, the complete IANA error-code registry and an etype table with weak-crypto classification)
- A transport layer that speaks UDP/88 with retries and TCP/88 with RFC 4120 four-byte framing plus kpasswd (464) and the MS-KKDCP HTTPS proxy protocol

**The suite covers the whole attack surface used for offline cracking and escalation:**

- AS-REP roasting
- SPN Kerberoasting
- Username enumeration
- Weak DES/RC4 negotiation
- Missing pre-authentication
- Absent FAST armoring
- Anonymous PKINIT
- Delegation/PAC signals
- Clock skew
- Realm referrals and Zerologon precondition fingerprinting

**Every probe is bounded and non-destructive:**

- No tickets are decrypted
- No passwords are guessed and no KDC state is modified.

**Ports:** 88/udp+tcp (kerberos-sec) + 464 (kpasswd) + 443 (KKDCP proxy) | **Protocol:** Kerberos 5 RFC 4120, pre-authentication RFC 4120/6806, FAST RFC 6803, anonymous PKINIT RFC 8062, kpasswd RFC 3244, KKDCP MS-KKDCP | **Total lines of Lua:** 46,642

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [kerberos-asrep-roasting](#1-kerberos-asrep-roasting---as-rep-roasting-exposure-audit) | 🔴 CRITICAL | vuln, safe | 2925 |
| 2 | [kerberos-cve-2020-1472-prep](#2-kerberos-cve-2020-1472-prep---cve-2020-1472-zerologon-precondition-fingerprint) | 🔴 CRITICAL | vuln, safe | 2923 |
| 3 | [kerberos-weak-encryption](#3-kerberos-weak-encryption---weak-kerberos-encryption-audit-desrc4) | 🔴 CRITICAL | vuln, safe | 2930 |
| 4 | [kerberos-anonymous-pkinit](#4-kerberos-anonymous-pkinit---anonymous-pkinit-rfc-8062-exposure) | 🟠 HIGH | vuln, safe | 2905 |
| 5 | [kerberos-constrained-deleg](#5-kerberos-constrained-deleg---s4u2self--constrained-delegation-probe) | 🟠 HIGH | vuln, safe | 2906 |
| 6 | [kerberos-spn-probe](#6-kerberos-spn-probe---spn-kerberoastability-probe) | 🟠 HIGH | vuln, safe | 2916 |
| 7 | [kerberos-user-enum](#7-kerberos-user-enum---username-enumeration-oracle) | 🟠 HIGH | vuln, safe | 2924 |
| 8 | [kerberos-fast-negotiation](#8-kerberos-fast-negotiation---rfc-6803-fast-armoring-detection) | 🟡 MEDIUM | discovery, safe | 2924 |
| 9 | [kerberos-kdc-proxy-probe](#9-kerberos-kdc-proxy-probe---ms-kkdcp-proxy-protocol-audit) | 🟡 MEDIUM | discovery, safe | 2912 |
| 10 | [kerberos-kpasswd-service](#10-kerberos-kpasswd-service---kpasswd-rfc-3244-service-audit) | 🟡 MEDIUM | discovery, safe | 2911 |
| 11 | [kerberos-pac-validation](#11-kerberos-pac-validation---pac-request--enc-pa-rep-signal-audit) | 🟡 MEDIUM | discovery, safe | 2914 |
| 12 | [kerberos-preauth-required](#12-kerberos-preauth-required---pre-authentication-enforcement-check) | 🟡 MEDIUM | discovery, safe | 2914 |
| 13 | [kerberos-time-skew-audit](#13-kerberos-time-skew-audit---kdc-clock-skew-measurement) | 🟡 MEDIUM | discovery, safe | 2914 |
| 14 | [kerberos-etype-negotiation](#14-kerberos-etype-negotiation---encryption-type-negotiation-profile) | 🟢 LOW | discovery, safe | 2908 |
| 15 | [kerberos-realm-discovery](#15-kerberos-realm-discovery---kerberos-realm-discovery) | 🟢 LOW | discovery, safe | 2910 |
| 16 | [kerberos-tcp-udp-support](#16-kerberos-tcp-udp-support---kdc-transport-matrix-udptcp-88) | 🟢 LOW | discovery, safe | 2906 |

---

### 1. **kerberos-asrep-roasting** - AS-REP Roasting Exposure Audit
**Description:** Sends AS-REQ messages without pre-authentication for common service

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends one pre-auth-free AS-REQ per candidate service account.
- Classifies: AS-REP returned (roastable, records the etype), KDC_ERR_PREAUTH_REQUIRED (protected), unknown.
- Never attempts any decryption or password guessing.
- Why it matters: Accounts without pre-authentication hand offline-crackable material to anyone who asks - the fastest path from no access to a password. Service accounts with stale passwords are the classic victims.
- Safety: one request per candidate; the replies are only classified, never decrypted.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-asrep-roasting dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-asrep-roasting --script-args 'kerberos-asrep-roasting.timeout=8,kerberos-asrep-roasting.maxrequests=48,kerberos-asrep-roasting.recv_window=3,kerberos-asrep-roasting.realm=CORP.EXAMPLE.COM,kerberos-asrep-roasting.users=administrator' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-asrep-roasting:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - pre-authentication enforced on all 2 known accounts; no AS-REP material disclosed
```

---

### 2. **kerberos-cve-2020-1472-prep** - CVE-2020-1472 (Zerologon) Precondition Fingerprint
**Description:** Fingerprints the preconditions of CVE-2020-1472 (Zerologon): the

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Profiles the DC via its Kerberos answers (realm, etype posture, kpasswd availability).
- Correlates the posture with the CVE-2020-1472 patch-generation guidance.
- Produces a patch-verification priority score.
- Why it matters: Zerologon-totalled domains still exist unpatched; precondition fingerprinting flags hosts for patch verification. The Kerberos surface reveals DC role and Netlogon linkage.
- Safety: passive AS-REQ probes only; no Netlogon/NRPC frames.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-cve-2020-1472-prep dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-cve-2020-1472-prep --script-args 'kerberos-cve-2020-1472-prep.timeout=8,kerberos-cve-2020-1472-prep.maxrequests=48,kerberos-cve-2020-1472-prep.recv_window=3,kerberos-cve-2020-1472-prep.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-cve-2020-1472-prep:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - no CVE-2020-1472 precondition indicators from the Kerberos surface (score 0/100)
```

---

### 3. **kerberos-weak-encryption** - Weak Kerberos Encryption Audit (DES/RC4)
**Description:** Checks whether the KDC still negotiates deprecated cryptography:

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends AS-REQ offers restricted to DES etypes, then RC4-only, then modern AES.
- Reads the PA-ETYPE-INFO2 etype (or the ETYPE_NOTSUPP refusal).
- Grades the accepted cryptography.
- Why it matters: RC4 tickets fall to offline cracking at modern GPU speeds; DES is broken outright. A KDC that offers RC4/DES keeps every legacy-bound account on the weakest crypto in the forest.
- Safety: three AS-REQ exchanges; no tickets are decrypted or used.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-weak-encryption dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-weak-encryption --script-args 'kerberos-weak-encryption.timeout=8,kerberos-weak-encryption.maxrequests=48,kerberos-weak-encryption.recv_window=3,kerberos-weak-encryption.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-weak-encryption:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - weak etypes rejected; KDC selects aes256-cts-hmac-sha1-96 for AES-capable offers
```

---

### 4. **kerberos-anonymous-pkinit** - Anonymous PKINIT (RFC 8062) Exposure
**Description:** Tests anonymous PKINIT (RFC 8062): an AS-REQ for

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends one AS-REQ for cname WELLKNOWN/ANONYMOUS with PA-PK-AS-REQ.
- Classifies: AS-REP (anonymous tickets enabled), error 14 (disabled), other.
- Reports the anonymous posture.
- Why it matters: Anonymous Kerberos enables unauthenticated Kerberised access (and is a building block for relay chains). Answering anonymous PKINIT without the WELLKNOWN restriction is a configuration regression.
- Safety: one request; no certificate is presented.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-anonymous-pkinit dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-anonymous-pkinit --script-args 'kerberos-anonymous-pkinit.timeout=8,kerberos-anonymous-pkinit.maxrequests=48,kerberos-anonymous-pkinit.recv_window=3,kerberos-anonymous-pkinit.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-anonymous-pkinit:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - anonymous PKINIT answers with a full AS-REP; unauthenticated Kerberos tickets are available
```

---

### 5. **kerberos-constrained-deleg** - S4U2self / Constrained Delegation Probe
**Description:** Probes S4U2self protocol-transition exposure: an AS-REQ carrying

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends one AS-REQ with PA-FOR-USER naming a probe principal.
- Classifies the error code: honoured vs rejected.
- Reports the transition exposure.
- Why it matters: PA-FOR-USER handling without proper account verification lets any caller request tickets on behalf of others. The answer classifies how exposed the transition primitive is.
- Safety: a single probe with a non-existent target; no tickets are obtained or used.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-constrained-deleg dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-constrained-deleg --script-args 'kerberos-constrained-deleg.timeout=8,kerberos-constrained-deleg.maxrequests=48,kerberos-constrained-deleg.recv_window=3,kerberos-constrained-deleg.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-constrained-deleg:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - PA-FOR-USER probe answered 4; protocol transition follows the normal account checks
```

---

### 6. **kerberos-spn-probe** - SPN Kerberoastability Probe
**Description:** Sends TGS-REQ messages for common service SPNs and reads the ticket

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends one TGS-REQ per candidate SPN (MSSQLSvc, HTTP, CIFS, ...).
- Records the returned ticket enc-etype and its roastability.
- Grades the exposure by etype and account class.
- Why it matters: Kerberoasting is the standard escalation path from any domain account to service-account passwords. Weak etype tickets for privileged SPNs (MSSQL, backup) are the highest-value finding here.
- Safety: one request per SPN; tickets are not decrypted or saved.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-spn-probe dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-spn-probe --script-args 'kerberos-spn-probe.timeout=8,kerberos-spn-probe.maxrequests=48,kerberos-spn-probe.recv_window=3,kerberos-spn-probe.realm=CORP.EXAMPLE.COM,kerberos-spn-probe.users=administrator' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-spn-probe:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - probed SPNs issued no RC4 tickets
```

---

### 7. **kerberos-user-enum** - Username Enumeration Oracle
**Description:** Enumerates valid Active Directory usernames from KDC error codes: an

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends one pre-auth-free AS-REQ per configured username.
- Classifies answers (exists / unknown / revoked).
- Measures oracle strength from the answer distribution.
- Why it matters: A validated user list feeds password spraying and targeted phishing; the KDC answers these probes for any unauthenticated caller. Uniform answers close the oracle entirely.
- Safety: one request per configured name (six by default); no password guessing.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-user-enum dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-user-enum --script-args 'kerberos-user-enum.timeout=8,kerberos-user-enum.maxrequests=48,kerberos-user-enum.recv_window=3,kerberos-user-enum.realm=CORP.EXAMPLE.COM,kerberos-user-enum.users=administrator' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-user-enum:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - username oracle confirmed (4 valid vs 2 unknown answers)
```

---

### 8. **kerberos-fast-negotiation** - RFC 6803 FAST Armoring Detection
**Description:** Detects RFC 6803 FAST (Kerberos Armoring) support: a PA-FX-FAST

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends one AS-REQ carrying PA-FX-FAST stub armour.
- Classifies: cookie+preauth (FAST capable), error 14 (no FAST).
- Reports the armour posture.
- Why it matters: FAST shields the user's password-derived key from offline guessing (the classic AS-REP roasting path). A KDC without FAST leaves all password knowledge to the client side.
- Safety: one request; the armour is a stub with no real key material.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-fast-negotiation dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-fast-negotiation --script-args 'kerberos-fast-negotiation.timeout=8,kerberos-fast-negotiation.maxrequests=48,kerberos-fast-negotiation.recv_window=3,kerberos-fast-negotiation.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-fast-negotiation:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - FAST answered with PA-FX-COOKIE; armoring negotiation available
```

---

### 9. **kerberos-kdc-proxy-probe** - MS-KKDCP Proxy Protocol Audit
**Description:** Audits the MS-KKDCP Kerberos Key Distribution Center Proxy Protocol:

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Performs a TLS handshake and grades the negotiated version/cipher.
- POSTs a KDC-PROXY-MESSAGE blob to /KdcProxy.
- Records the HTTP status and body echo.
- Why it matters: KKDCP exposes Kerberos through the web tier: TLS misconfiguration and open proxies directly inherit the exposure. A 404 on /KdcProxy marks a half-migrated proxy deployment.
- Safety: one handshake + one small POST; the blob is a well-formed but inert KDC message.

**How to Execute:**
```bash
nmap -p 443 -sV --version-intensity 0 --script kerberos-kdc-proxy-probe dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 443 --script kerberos-kdc-proxy-probe --script-args 'kerberos-kdc-proxy-probe.timeout=8,kerberos-kdc-proxy-probe.maxrequests=48,kerberos-kdc-proxy-probe.recv_window=3,kerberos-kdc-proxy-probe.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-kdc-proxy-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - KKDCP endpoint alive: TLS negotiated and /KdcProxy answered 200
```

---

### 10. **kerberos-kpasswd-service** - kpasswd (RFC 3244) Service Audit
**Description:** Audits the kpasswd password-change service on port 464 (RFC 3244): a

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends one RFC 3244 change request with a deliberately invalid target key.
- Classifies: malformed (3), other error, silence.
- Reports the kpasswd posture.
- Why it matters: An open kpasswd lets any principal attempt password changes for others (set-password abuse) when policy is weak. A missing kpasswd breaks self-service and hints at legacy KDCs.
- Safety: the request is malformed by construction - no password is ever changed.

**How to Execute:**
```bash
nmap -p 464 -sV --version-intensity 0 --script kerberos-kpasswd-service dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 464 --script kerberos-kpasswd-service --script-args 'kerberos-kpasswd-service.timeout=8,kerberos-kpasswd-service.maxrequests=48,kerberos-kpasswd-service.recv_window=3,kerberos-kpasswd-service.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-kpasswd-service:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - kpasswd alive on 464 and rejects malformed change requests
```

---

### 11. **kerberos-pac-validation** - PAC Request / Enc-PA-REP Signal Audit
**Description:** Checks RFC 6806 PAC request handling: AS-REQs carrying PA-PAC-REQUEST

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends one AS-REQ with PA-PAC-REQUEST(128) + PA-REQ-ENC-PA-REP(149).
- Reads the answer padata for PA-149 acknowledgement and the PAC behaviour.
- Reports the signal posture.
- Why it matters: Enc-PA-REP support (CVE-2021-42287 era hardening) binds the PAC to the ticket; KDCs that never signal it leave ticket-forgery windows open. PAC suppression toggles document how the KDC is expected to behave.
- Safety: a single request.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-pac-validation dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-pac-validation --script-args 'kerberos-pac-validation.timeout=8,kerberos-pac-validation.maxrequests=48,kerberos-pac-validation.recv_window=3,kerberos-pac-validation.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-pac-validation:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - KDC acknowledges REQ-ENC-PA-REP; PAC binding signal present
```

---

### 12. **kerberos-preauth-required** - Pre-Authentication Enforcement Check
**Description:** Verifies whether pre-authentication is mandatory: sends one

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends one AS-REQ without PA-ENC-TIMESTAMP for administrator.
- Expects KDC_ERR_PREAUTH_REQUIRED (23) with PA-ETYPE-INFO2.
- Records the observed posture.
- Why it matters: Pre-authentication is the control that keeps offline-crackable material out of anonymous hands; a KDC that skips it for any account hands over hash material directly. The answer doubles as a health check for the pre-auth subsystem.
- Safety: one request; no credentials involved.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-preauth-required dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-preauth-required --script-args 'kerberos-preauth-required.timeout=8,kerberos-preauth-required.maxrequests=48,kerberos-preauth-required.recv_window=3,kerberos-preauth-required.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-preauth-required:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - pre-authentication enforced (KDC_ERR_PREAUTH_REQUIRED with PA-ETYPE-INFO2)
```

---

### 13. **kerberos-time-skew-audit** - KDC Clock-Skew Measurement
**Description:** Measures the KDC clock skew: a pre-auth AS-REQ triggers

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends one AS-REQ with a stale PA-ENC-TIMESTAMP.
- Reads KRB_AP_ERR_SKEW and the server stime.
- Grades the measured skew against the 300-second RFC window.
- Why it matters: Skew beyond the 5-minute default window silently breaks authentication and, worse, masks replay-window enforcement. Clock drift on a DC is usually an NTP/VM-sync failure worth catching early.
- Safety: a single request; the stale timestamp is never valid material.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-time-skew-audit dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-time-skew-audit --script-args 'kerberos-time-skew-audit.timeout=8,kerberos-time-skew-audit.maxrequests=48,kerberos-time-skew-audit.recv_window=3,kerberos-time-skew-audit.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-time-skew-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - KDC answered skew with 0s measured difference (inside the 300s window)
```

---

### 14. **kerberos-etype-negotiation** - Encryption-Type Negotiation Profile
**Description:** Maps the KDC's supported encryption types: a full etype preference list

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends one AS-REQ offering the full modern-to-legacy etype ladder.
- Records the KDC's selection and any refusal codes.
- Renders the negotiation ladder as a capability profile.
- Why it matters: The etype profile identifies the domain functional level and flags how much legacy crypto the forest still carries. Every other Kerberos audit keys off the etype answer.
- Safety: a single AS-REQ exchange.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-etype-negotiation dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-etype-negotiation --script-args 'kerberos-etype-negotiation.timeout=8,kerberos-etype-negotiation.maxrequests=48,kerberos-etype-negotiation.recv_window=3,kerberos-etype-negotiation.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-etype-negotiation:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - KDC selects aes256-cts-hmac-sha1-96 (salt revealed in PA-ETYPE-INFO2)
```

---

### 15. **kerberos-realm-discovery** - Kerberos Realm Discovery
**Description:** Probes the KDC with a dummy realm to extract the true Active Directory

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends one AS-REQ with realm DUMMY.INVALID.
- Reads the error code and the realm/sname fields of the answer.
- Reports the discovered realm and referral behaviour.
- Why it matters: The real realm name anchors every other Kerberos audit and maps the forest namespace for attackers. Some hardening guides recommend suppressing cross-realm hints.
- Safety: a single probe request.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-realm-discovery dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-realm-discovery --script-args 'kerberos-realm-discovery.timeout=8,kerberos-realm-discovery.maxrequests=48,kerberos-realm-discovery.recv_window=3,kerberos-realm-discovery.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-realm-discovery:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - KDC_ERR_WRONG_REALM answered; true realm disclosed: CORP.EXAMPLE.COM
```

---

### 16. **kerberos-tcp-udp-support** - KDC Transport Matrix (UDP/TCP 88)
**Description:** Tests whether the KDC accepts requests on both UDP/88 and TCP/88: RFC

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends an identical AS-REQ over UDP and over TCP (4-byte framing).
- Records which transports answer and with what.
- Reports the transport matrix.
- Why it matters: Transport support shapes amplification exposure (UDP) and fragmentation-handling differences (TCP). KKDCP migrations usually retire UDP first; the profile documents the migration state.
- Safety: two small requests, one per transport.

**How to Execute:**
```bash
nmap -p 88 -sV --version-intensity 0 --script kerberos-tcp-udp-support dc01.corp.example.com

# Tuned probe set (realm + request budget)
nmap -p 88 --script kerberos-tcp-udp-support --script-args 'kerberos-tcp-udp-support.timeout=8,kerberos-tcp-udp-support.maxrequests=48,kerberos-tcp-udp-support.recv_window=3,kerberos-tcp-udp-support.realm=CORP.EXAMPLE.COM' dc01.corp.example.com
```

**Sample Output:**
```
| kerberos-tcp-udp-support:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - KDC answers on both UDP/88 and TCP/88 (RFC 4120 compliant)
```

