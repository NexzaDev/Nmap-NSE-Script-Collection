# 🖥️ RDP Security Audits

**16 Nmap NSE scripts** for auditing Microsoft RDP endpoints (MS-RDPBCGR) directly on the wire:

**Covers:**

- TPKT/X.224 connection negotiation with the full rdp_neg request/response/failure structures
- CredSSP (TSRequest) revision exchange with SPNEGO/NTLMSSP challenge parsing incl

AV_PAIR identity attributes, TLS security-layer handshakes with certificate capture, GCC/MCS connect with server core/security/network-data parsing, MS-RDPEUDP transport probing, and the precondition fingerprints for CVE-2019-0708 (BlueKeep), MS12-020 (CVE-2012-0002) and CVE-2018-0886.

Every script speaks real RDP bytes - X.224 Connection Request/Confirm with routing tokens and negotiation PDUs, NTLM type-1/type-2 message codecs, DER/SPNEGO wrapping, T.125 MCS Connect-Initial/Response with GCC user-data blocks - and turns the observed protocol behaviour into evidence-based findings.

**All probes are safe, non-destructive negotiations and reads:**

- No exploit bytes
- No crash-inducing MS12-020 sequences
- Bounded request budgets and timeouts.

**Ports:** 3389/tcp (+3389/udp for the transport probe) | **Protocol:** RDP / MS-RDPBCGR over X.224/TPKT, CredSSP (MS-CSSP), NTLMSSP (MS-NLMP), MS-RDPEUDP | **Total lines of Lua:** 34,358

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [rdp-bluekeep-precondition](#1-rdp-bluekeep-precondition---bluekeep-precondition-analysis) | 🔴 CRITICAL | vuln, safe | 1917 |
| 2 | [rdp-cve-2012-0002-check](#2-rdp-cve-2012-0002-check---ms12-020-precondition-check) | 🔴 CRITICAL | vuln, safe | 1889 |
| 3 | [rdp-nla-disabled](#3-rdp-nla-disabled---nla-enforcement-check) | 🔴 CRITICAL | vuln, safe | 1871 |
| 4 | [rdp-credssp-version-audit](#4-rdp-credssp-version-audit---credssp-revision-audit) | 🟠 HIGH | defensive, safe | 1888 |
| 5 | [rdp-weak-rc4-ciphers](#5-rdp-weak-rc4-ciphers---weak-rc4-cipher-acceptance) | 🟠 HIGH | vuln, safe | 3323 |
| 6 | [rdp-cert-name-mismatch](#6-rdp-cert-name-mismatch---certificate-name-mismatch) | 🟡 MEDIUM | defensive, safe | 3348 |
| 7 | [rdp-hybrid-auth-support](#7-rdp-hybrid-auth-support---hybrid-authentication-support-map) | 🟡 MEDIUM | discovery, safe | 1862 |
| 8 | [rdp-ntlm-info-disclosure](#8-rdp-ntlm-info-disclosure---ntlm-identity-disclosure) | 🟡 MEDIUM | discovery, safe | 1914 |
| 9 | [rdp-screen-resolution-dos](#9-rdp-screen-resolution-dos---pre-auth-gcc-processing-surface) | 🟡 MEDIUM | defensive, safe | 1856 |
| 10 | [rdp-session-shadowing-risk](#10-rdp-session-shadowing-risk---session-shadowing-exposure) | 🟡 MEDIUM | defensive, safe | 1876 |
| 11 | [rdp-tls-security-layer](#11-rdp-tls-security-layer---tls-security-layer-profile) | 🟡 MEDIUM | defensive, safe | 3332 |
| 12 | [rdp-cookie-routing-token](#12-rdp-cookie-routing-token---routing-token-cookie-behaviour) | 🟢 LOW | discovery, safe | 1851 |
| 13 | [rdp-restricted-admin-mode](#13-rdp-restricted-admin-mode---restricted-admin-mode-signal) | 🟢 LOW | defensive, safe | 1858 |
| 14 | [rdp-session-negotiation](#14-rdp-session-negotiation---session-negotiation-profile) | 🟢 LOW | discovery, safe | 1853 |
| 15 | [rdp-udp-transport-check](#15-rdp-udp-transport-check---udp-transport-reachability) | 🟢 LOW | discovery, safe | 1842 |
| 16 | [rdp-virtual-channels-enum](#16-rdp-virtual-channels-enum---virtual-channel-enumeration) | 🟢 LOW | discovery, safe | 1878 |

---

### 1. **rdp-bluekeep-precondition** - BlueKeep Precondition Analysis
**Description:** Probes the RDP endpoint for the preconditions of CVE-2019-0708

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Negotiates X.224 with TLS and CredSSP requested and records how the server responds (plain confirm = legacy accepted, neg-rsp, or failure).
- Reads the server GCC core data version through a bounded MCS connect to fingerprint the RDP stack generation.
- Combines both signals into a BlueKeep precondition matrix. no exploit bytes and no malformed sequences are ever sent.
- Why it matters: BlueKeep is a wormable pre-authentication remote code execution flaw affecting RDP 5.1-7.0 listeners that still accept legacy sessions.
- Safety: protocol negotiation and one read-only MCS/GCC connect; no exploit bytes and no malformed sequences are ever sent.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-bluekeep-precondition rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-bluekeep-precondition --script-args 'rdp-bluekeep-precondition.maxrequests=24,rdp-bluekeep-precondition.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-bluekeep-precondition:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - BlueKeep preconditions met (legacy RDP without NLA on RDP 5.x)
```

---

### 2. **rdp-cve-2012-0002-check** - MS12-020 Precondition Check
**Description:** Evaluates the preconditions of CVE-2012-0002 (MS12-020) without ever

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Negotiates X.224 and records whether the legacy path is open.
- Performs one bounded MCS/GCC connect to read the server core data version and the announced virtual channel list.
- Matches the collected fingerprint against the vulnerable range. crashing packet pattern is never constructed or sent.
- Why it matters: MS12-020 is a pre-authentication kernel RCE in the RDP channel joining path of RDP 5.x-6.1 listeners.
- Safety: negotiation plus one read-only GCC connect; the known crashing packet pattern is never constructed or sent.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-cve-2012-0002-check rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-cve-2012-0002-check --script-args 'rdp-cve-2012-0002-check.maxrequests=24,rdp-cve-2012-0002-check.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-cve-2012-0002-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - MS12-020 preconditions met (legacy stack, legacy path open, MS_T120 announced)
```

---

### 3. **rdp-nla-disabled** - NLA Enforcement Check
**Description:** Checks whether the RDP endpoint accepts sessions without Network

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends an X.224 Connection Request with no security negotiation (pure legacy) and records the confirm.
- Sends a second request with TLS and CredSSP requested and compares.
- Classifies NLA enforcement from the negotiation outcomes. no session setup.
- Why it matters: Without NLA an attacker reaches authentication code before any credential exchange, which is the surface for pre-auth RCE flaws (CVE-2019-0708, MS12-020) and credential-harvesting setup screens.
- Safety: two negotiation exchanges only; no authentication and no session setup.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-nla-disabled rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-nla-disabled --script-args 'rdp-nla-disabled.maxrequests=24,rdp-nla-disabled.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-nla-disabled:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Network Level Authentication disabled (pre-auth session surface exposed)
```

---

### 4. **rdp-credssp-version-audit** - CredSSP Revision Audit
**Description:** Audits the CredSSP (TSRequest) protocol revision the server answers

**Risk Level:** 🟠 HIGH | **Category:** defensive, safe

**What it checks:**
- Negotiates CredSSP/HYBRID with the server.
- Sends a TSRequest carrying the client revision and an SPNEGO/NTLM negotiate token, then parses the server's TSRequest response.
- Maps the returned revision to the patch-era matrix and reports. exchange; no credentials are transmitted.
- Why it matters: Unpatched CredSSP (revision <= 5) allowed relay of NTLM credentials from a victim client to a target service (Redirect Attack).
- Safety: one negotiation plus one credential-free SPNEGO exchange; no credentials are transmitted.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-credssp-version-audit rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-credssp-version-audit --script-args 'rdp-credssp-version-audit.maxrequests=24,rdp-credssp-version-audit.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-credssp-version-audit:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - CredSSP revision 5 answered (pre-hardening, CVE-2018-0886 exposure window)
```

---

### 5. **rdp-weak-rc4-ciphers** - Weak RC4 Cipher Acceptance
**Description:** Tests whether the RDP TLS security layer still accepts RC4 cipher

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Negotiates the TLS security layer with the server (or confirms the plain legacy path first when the server ignores negotiation).
- Sends a ClientHello restricted to RC4 suites (128/128-SHA, MD5).
- Reports the negotiated suite: RC4 acceptance is a finding, refusal or a handshake failure proves the legacy suites are disabled. through the established channel.
- Why it matters: RC4 in TLS is biased and practically decryptable for reused plaintext; compliance regimes (PCI DSS, NIST SP 800-52r2) forbid it.
- Safety: negotiation and one TLS handshake; no data is sent through the established channel.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-weak-rc4-ciphers rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-weak-rc4-ciphers --script-args 'rdp-weak-rc4-ciphers.maxrequests=24,rdp-weak-rc4-ciphers.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-weak-rc4-ciphers:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - server accepted RC4 (TLS_RSA_WITH_RC4_128_SHA)
```

---

### 6. **rdp-cert-name-mismatch** - Certificate Name Mismatch
**Description:** Captures the RDP endpoint's TLS certificate during the security-layer

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Negotiates the TLS security layer and completes a handshake.
- Parses the certificate subject CN and SAN DNS entries.
- Compares them with the audited hostname (target name) and the certificate validity window. triggered on the server.
- Why it matters: A mismatched certificate breaks server authentication and trains users to click through warnings, enabling MITM of credentials that NLA was supposed to protect.
- Safety: negotiation plus one handshake; no validation error is triggered on the server.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-cert-name-mismatch rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-cert-name-mismatch --script-args 'rdp-cert-name-mismatch.maxrequests=24,rdp-cert-name-mismatch.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-cert-name-mismatch:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - certificate name mismatch (CN legacy.example.com vs target.example.com)
```

---

### 7. **rdp-hybrid-auth-support** - Hybrid Authentication Support Map
**Description:** Maps the complete security-layer negotiation matrix of the RDP

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends three X.224 Connection Requests: HYBRID-only, SSL-only, and no-negotiation (legacy).
- Records the response class per probe (selected protocol, refusal reason, or plain confirm).
- Summarizes the auth posture and flags legacy acceptance.
- Why it matters: The negotiation matrix reveals whether legacy standard-RDP security remains reachable, which weakens every other hardening measure.
- Safety: three negotiation exchanges; no authentication.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-hybrid-auth-support rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-hybrid-auth-support --script-args 'rdp-hybrid-auth-support.maxrequests=24,rdp-hybrid-auth-support.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-hybrid-auth-support:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - legacy security path reachable (matrix recorded)
```

---

### 8. **rdp-ntlm-info-disclosure** - NTLM Identity Disclosure
**Description:** Extracts Windows identity information (NetBIOS/DNS host and domain

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Negotiates HYBRID and sends an SPNEGO/NTLM negotiate token.
- Parses the NTLMSSP challenge: target name, AV_PAIR list, version block and negotiate flags.
- Reports each disclosed attribute and rates the disclosure. exchange.
- Why it matters: The NTLM challenge leaks internal naming that DNS does not expose, which maps the internal AD namespace without credentials.
- Safety: one negotiation and one credential-free SPNEGO exchange.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-ntlm-info-disclosure rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-ntlm-info-disclosure --script-args 'rdp-ntlm-info-disclosure.maxrequests=24,rdp-ntlm-info-disclosure.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-ntlm-info-disclosure:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - NTLM challenge discloses 6 identity attributes (TS01)
```

---

### 9. **rdp-screen-resolution-dos** - Pre-auth GCC Processing Surface
**Description:** Measures whether the server processes a full GCC/MCS connect

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Negotiates X.224 with TLS+CredSSP requested.
- Sends one standard-bounded GCC connect (moderate 1280x800 request, no extreme values, no malformed structures) and records whether the server processes it anonymously.
- Classifies the pre-auth processing surface. parameters; nothing oversized or malformed is ever sent.
- Why it matters: Pre-auth GCC processing lets an anonymous client make the server allocate session structures repeatedly; extreme resolution or color-depth claims amplify the cost per connection.
- Safety: a single well-formed GCC connect with moderate parameters; nothing oversized or malformed is ever sent.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-screen-resolution-dos rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-screen-resolution-dos --script-args 'rdp-screen-resolution-dos.maxrequests=24,rdp-screen-resolution-dos.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-screen-resolution-dos:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - GCC/MCS connect processed before authentication (pre-auth resource surface)
```

---

### 10. **rdp-session-shadowing-risk** - Session Shadowing Exposure
**Description:** Assesses the session shadowing exposure of the RDP endpoint: whether

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Negotiates X.224 and classifies the security layer (legacy open vs CredSSP-only).
- Reads the GCC server data for the channel set and early capability flags that shape shadowing behaviour.
- Produces a shadowing posture rating with hardening steps. request is ever issued.
- Why it matters: Shadowing (remote control of another user's session) without user consent is a surveillance-grade capability; misconfigured shadow policies allow unprivileged users to watch privileged sessions.
- Safety: negotiation plus one read-only GCC connect; no shadow request is ever issued.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-session-shadowing-risk rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-session-shadowing-risk --script-args 'rdp-session-shadowing-risk.maxrequests=24,rdp-session-shadowing-risk.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-session-shadowing-risk:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - shadowing prerequisites present (legacy security layer plus interactive channels)
```

---

### 11. **rdp-tls-security-layer** - TLS Security Layer Profile
**Description:** Profiles the TLS security layer of the RDP endpoint: which protocol

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Negotiates the TLS security layer (falls back to a direct TLS attempt on the legacy path).
- Offers a mixed suite list at a TLS 1.0 floor, then reads the server flight: version, suite, certificate.
- Classifies the layer as modern, acceptable or deprecated.
- Why it matters: RDP security is only as strong as its TLS layer; TLS 1.0/1.1 with CBC or RC4 suites is deprecated and commonly flagged by scanners.
- Safety: negotiation plus one TLS handshake.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-tls-security-layer rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-tls-security-layer --script-args 'rdp-tls-security-layer.maxrequests=24,rdp-tls-security-layer.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-tls-security-layer:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - deprecated RDP TLS layer (TLS 1.0 with TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
```

---

### 12. **rdp-cookie-routing-token** - Routing Token (Cookie) Behaviour
**Description:** Tests whether the RDP endpoint honours the X.224 routing token

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Opens two connections sending different mstshash cookies.
- Compares the confirm PDUs for differences that indicate token processing (routing echo, distinct confirm shapes).
- Reports whether the endpoint appears cookie-aware.
- Why it matters: Cookie-aware endpoints indicate a broker/farm in front of the host, which changes how session redirection and shadowing behave.
- Safety: two negotiation exchanges with benign random cookies.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-cookie-routing-token rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-cookie-routing-token --script-args 'rdp-cookie-routing-token.maxrequests=24,rdp-cookie-routing-token.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-cookie-routing-token:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - routing token accepted without visible routing effect
```

---

### 13. **rdp-restricted-admin-mode** - Restricted Admin Mode Signal
**Description:** Checks whether the RDP endpoint signals Restricted Administrative

**Risk Level:** 🟢 LOW | **Category:** defensive, safe

**What it checks:**
- Negotiates HYBRID and performs the SPNEGO/NTLM exchange.
- Reads the MsvAvFlags value from the NTLM challenge AV_PAIR list.
- Classifies the restricted-admin signal. exchange.
- Why it matters: Without Restricted Admin, administrator credentials are cached on the terminal server, so any compromise of that host exposes every admin who logged in.
- Safety: one negotiation and one credential-free SPNEGO exchange.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-restricted-admin-mode rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-restricted-admin-mode --script-args 'rdp-restricted-admin-mode.maxrequests=24,rdp-restricted-admin-mode.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-restricted-admin-mode:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - no restricted admin signal (admin credentials are cached on the host)
```

---

### 14. **rdp-session-negotiation** - Session Negotiation Profile
**Description:** Documents the complete session negotiation behaviour of the RDP

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Negotiates with TLS+CredSSP requested and records the confirm.
- Performs a bounded MCS/GCC connect to read the server core data, security data and early capability flags.
- Reports the full negotiation profile as the audit baseline.
- Why it matters: A negotiation fingerprint distinguishes RDP stacks quickly and is the reference point for every other RDP audit finding.
- Safety: negotiation plus one read-only GCC connect.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-session-negotiation rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-session-negotiation --script-args 'rdp-session-negotiation.maxrequests=24,rdp-session-negotiation.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-session-negotiation:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - session negotiation profiled (security layer standard-rdp-security; RDP 5.0-5.2 / Windows 2000-XP/2003 era)
```

---

### 15. **rdp-udp-transport-check** - UDP Transport Reachability
**Description:** Checks whether the RDP endpoint also answers on the UDP 3389

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends a single MS-RDPEUDP SYN probe with a random cookie to UDP 3389 and waits for a SYN/ACK-style answer.
- Reports reachability, response shape and round-trip timing.
- Leaves the TCP transport untouched. payloads.
- Why it matters: The UDP transport widens the attack surface: it bypasses TCP-only filtering rules and is commonly missed by mitigation playbooks.
- Safety: exactly one UDP datagram; no flood, no malformed payloads.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-udp-transport-check rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-udp-transport-check --script-args 'rdp-udp-transport-check.maxrequests=24,rdp-udp-transport-check.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-udp-transport-check:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - UDP 3389 transport reachable (MS-RDPEUDP)
```

---

### 16. **rdp-virtual-channels-enum** - Virtual Channel Enumeration
**Description:** Enumerates the static virtual channels the RDP server announces in

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Negotiates X.224 and performs one bounded MCS/GCC connect.
- Parses GCC server network data for the announced channel names and option flags.
- Cross-checks the list against a legacy-channel risk table. channels are joined.
- Why it matters: MS_T120 is the channel implicated in the MS12-020 kernel flaw.
- Safety: negotiation plus one read-only GCC connect; no channels are joined.

**How to Execute:**
```bash
nmap -p 3389 --script rdp-virtual-channels-enum rdpsrv.corp.example.com

# Tuned request budget
nmap -p 3389 --script rdp-virtual-channels-enum --script-args 'rdp-virtual-channels-enum.maxrequests=24,rdp-virtual-channels-enum.timeout=8' rdpsrv.corp.example.com
```

**Sample Output:**
```
| rdp-virtual-channels-enum:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - legacy MS_T120 channel announced (MS12-020 channel family present)
```

