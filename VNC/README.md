# 👁️ VNC Security Audits

**16 Nmap NSE scripts** for auditing VNC/RFB endpoints directly on the wire:

**Covers:**

- Full RFB ProtocolVersion handshake handling (3.3/3.7/3.8 plus the repeater null banner)
- Security-type offer/choice exchange with family classification (None, VNC DES challenge-response, Tight, VeNCrypt/TLS)
- A complete FIPS-46-3 DES implementation with known-answer self-tests driving real VNCAuth challenge-response verification (bit-reflected key derivation)
- CVE-2006-2369-style premature security-choice bypass testing
- ClientInit/ServerInit parsing (geometry, pixel format, desktop name)
- ServerCutText clipboard draining with credential-pattern scanning
- HTTP/websocket fingerprinting of the 5800/6080 web stacks
- VNC repeater ID-string staging on 5500

**Every probe is a bounded, safe negotiation:**

- Password auditing is capped (8 guesses by default, hard limit 32)
- No framebuffer content is ever drawn and no input events are sent.

**Ports:** 5900/tcp (RFB) + 5800/tcp (web viewer) + 6080/tcp (noVNC/websockify) + 5500/tcp (repeater staging) | **Protocol:** RFB 3.3/3.7/3.8 (RFC 6143 family), VNCAuth DES-56, VeNCrypt/TLS negotiation, VNC repeater protocol | **Total lines of Lua:** 31,446

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [vnc-auth-bypass-cve-check](#1-vnc-auth-bypass-cve-check---cve-2006-2369-authentication-bypass-check) | 🔴 CRITICAL | vuln, safe | 1964 |
| 2 | [vnc-default-passwords](#2-vnc-default-passwords---default--weak-password-audit) | 🔴 CRITICAL | vuln, safe | 1987 |
| 3 | [vnc-no-auth-check](#3-vnc-no-auth-check---no-authentication-session-check) | 🔴 CRITICAL | vuln, safe | 1944 |
| 4 | [vnc-tightvnc-backdoor-audit](#4-vnc-tightvnc-backdoor-audit---tightvnc-backdoor-pattern-audit) | 🔴 CRITICAL | vuln, safe | 1983 |
| 5 | [vnc-clipboard-leak-risk](#5-vnc-clipboard-leak-risk---clipboard-leak-exposure) | 🟠 HIGH | vuln, safe | 1965 |
| 6 | [vnc-http-web-interface](#6-vnc-http-web-interface---http-web-interface-exposure) | 🟠 HIGH | vuln, safe | 1965 |
| 7 | [vnc-novnc-websocket-probe](#7-vnc-novnc-websocket-probe---novnc--websocket-gateway-probe) | 🟠 HIGH | vuln, safe | 1986 |
| 8 | [vnc-cleartext-des-warning](#8-vnc-cleartext-des-warning---cleartext--des-56-credential-exposure-warning) | 🟡 MEDIUM | defensive, safe | 1966 |
| 9 | [vnc-max-auth-failures](#9-vnc-max-auth-failures---authentication-throttling--lockout-check) | 🟡 MEDIUM | defensive, safe | 1976 |
| 10 | [vnc-repeater-proxy-detect](#10-vnc-repeater-proxy-detect---vnc-repeater--proxy-detection) | 🟡 MEDIUM | discovery, safe | 1948 |
| 11 | [vnc-reverse-connection-probe](#11-vnc-reverse-connection-probe---reverse-connection-staging-probe) | 🟡 MEDIUM | discovery, safe | 1937 |
| 12 | [vnc-vencrypt-tls-support](#12-vnc-vencrypt-tls-support---vencrypt--tls-support-check) | 🟡 MEDIUM | defensive, safe | 1961 |
| 13 | [vnc-color-depth-dos-check](#13-vnc-color-depth-dos-check---pixel-format--colour-depth-stability-check) | 🟢 LOW | defensive, safe | 1974 |
| 14 | [vnc-desktop-geometry-leak](#14-vnc-desktop-geometry-leak---desktop-geometry-pre-auth-disclosure) | 🟢 LOW | discovery, safe | 1946 |
| 15 | [vnc-rfb-version-fingerprint](#15-vnc-rfb-version-fingerprint---rfb-version-fingerprint) | 🟢 LOW | discovery, safe | 1965 |
| 16 | [vnc-security-types-enum](#16-vnc-security-types-enum---security-type-enumeration) | 🟢 LOW | discovery, safe | 1979 |

---

### 1. **vnc-auth-bypass-cve-check** - CVE-2006-2369 Authentication Bypass Check
**Description:** Checks the CVE-2006-2369 (RealVNC 4.1 authentication bypass) behaviour

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends ProtocolVersion and the security choice in a single flight (premature selection) and reads whether the server treats it as a valid SecurityResult.
- On acceptance completes ClientInit/ServerInit to prove a session.
- Performs one 3.3 downgrade handshake and records the server-chosen type.
- Why it matters: Buggy 4.1-era stacks accepted a client-forced security type, turning a VNC-authentication server into an unauthenticated one. Servers that still honour the 3.3 downgrade may expose the same server-chosen None path to scriptable clients.
- Safety: two bounded sessions closed right after negotiation; no screen data is drawn.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-auth-bypass-cve-check target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-auth-bypass-cve-check --script-args 'vnc-auth-bypass-cve-check.timeout=8,vnc-auth-bypass-cve-check.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-auth-bypass-cve-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - server accepted a premature security choice and opened an unauthenticated session
```

---

### 2. **vnc-default-passwords** - Default & Weak Password Audit
**Description:** Tests a bounded list of well-known default and weak VNC passwords against

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Reads the security offer to confirm the VNC challenge-response type is actually offered.
- Performs at most guesslimit fresh handshakes, deriving the real DES response for every candidate password.
- Reports the accepted candidate, its position and the challenge evidence; records lockout or drop behaviour when observed.
- Why it matters: VNC authentication is a single DES-56 challenge-response; a weak password falls to a handful of offline-strength guesses. Deployments provisioned from templates routinely keep passwords such as "vncpass", "password" or "123456" in production.
- Safety: bounded candidate list (8 by default, hard cap 32), one connection per candidate, no lockout triggering floods.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-default-passwords target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-default-passwords --script-args 'vnc-default-passwords.timeout=8,vnc-default-passwords.maxrequests=64,vnc-default-passwords.guesslimit=8' target.example.com
```

**Sample Output:**
```
| vnc-default-passwords:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - weak VNC password accepted: 'vncpass' (attempt 3)
```

---

### 3. **vnc-no-auth-check** - No-Authentication Session Check
**Description:** Confirms whether the VNC server grants a full desktop session without any

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Performs the RFB handshake selecting security type 1.
- On acceptance completes ClientInit/ServerInit to confirm a real session (geometry, pixel format, server name).
- Records the session evidence and hardens guidance.
- Why it matters: An accepted None session means anyone with network reach gets keyboard, screen and clipboard control of the console. This is the highest impact finding class for VNC deployments and a frequent audit item on jump hosts and kiosks.
- Safety: the session is closed immediately after ServerInit; no framebuffer data is requested and no input events are sent.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-no-auth-check target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-no-auth-check --script-args 'vnc-no-auth-check.timeout=8,vnc-no-auth-check.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-no-auth-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - unauthenticated desktop session established (ServerInit confirmed)
```

---

### 4. **vnc-tightvnc-backdoor-audit** - TightVNC Backdoor Pattern Audit
**Description:** Correlates the classic TightVNC backdoor exposure pattern: a web viewer

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Probes the VNC HTTP port for TightVNC stack markers.
- Tests the None security type and the premature-choice bypass class.
- Correlates web-stack evidence with the working control path into a backdoor-exposure verdict.
- Why it matters: TightVNC 1.x deployments exposed web applet viewers plus permissive authentication, the exact recipe abuse tools scan for. Confirming the combination on one host means an operator with a browser and no credentials can reach the console.
- Safety: one HTTP GET plus two bounded RFB sessions closed right after negotiation; no screen content is drawn.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-tightvnc-backdoor-audit target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-tightvnc-backdoor-audit --script-args 'vnc-tightvnc-backdoor-audit.timeout=8,vnc-tightvnc-backdoor-audit.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-tightvnc-backdoor-audit:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - TightVNC web stack combined with an unauthenticated control path (None security type session)
```

---

### 5. **vnc-clipboard-leak-risk** - Clipboard Leak Exposure
**Description:** Opens a no-credential session when possible and listens for server-pushed

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Establishes a None-auth session (the exposure class under audit).
- Sends SetEncodings plus a framebuffer request to trigger server messages and drains the message stream.
- Scans ServerCutText for credential patterns and reports hits.
- Why it matters: The console clipboard routinely holds passwords, tokens and UNC paths the moment an administrator copies anything. A server that pushes clipboard data to a session before any real authentication turns anonymous viewers into secret readers.
- Safety: no clipboard content is written back and no input is sent; the session closes right after the drain.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-clipboard-leak-risk target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-clipboard-leak-risk --script-args 'vnc-clipboard-leak-risk.timeout=8,vnc-clipboard-leak-risk.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-clipboard-leak-risk:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - server pushed clipboard content containing credential-like material (credential pair)
```

---

### 6. **vnc-http-web-interface** - HTTP Web Interface Exposure
**Description:** Probes the classic VNC HTTP administration/viewer interface on port 5800

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends a bounded GET / to port 5800.
- Parses status line, headers and body for VNC-viewer markers.
- Reports the exposed interface with product evidence.
- Why it matters: The 5800 viewer exposes a browser-reachable path to the desktop and fingerprints the VNC product for follow-up attacks. Historical VNC web stacks (TightVNC viewers, vendor applets) ship with unauthenticated access and known vulnerable components.
- Safety: one GET request; nothing is submitted and no session is opened.

**How to Execute:**
```bash
nmap -p 5800 --script vnc-http-web-interface target.example.com

# Tuned request budget
nmap -p 5800 --script vnc-http-web-interface --script-args 'vnc-http-web-interface.timeout=8,vnc-http-web-interface.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-http-web-interface:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - web VNC interface exposed (TightVNC web viewer stack ('TightVNC'); VNC viewer applet reference ('vncviewer'))
```

---

### 7. **vnc-novnc-websocket-probe** - noVNC / Websocket Gateway Probe
**Description:** Detects a noVNC/websockify gateway on the target: plain HTTP fingerprint

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends a plain GET / to fingerprint the gateway page.
- Sends a websocket upgrade request and records 101 responses plus the Sec-WebSocket-Accept header presence.
- Correlates noVNC/websockify markers into an exposure verdict.
- Why it matters: A reachable noVNC gateway turns the VNC port into a browser-only target: no native client, no warnings, ideal for drive-by style abuse. Open websocket bridges (101 upgrades) usually forward straight into a RFB session, often without their own authentication.
- Safety: two GET-class requests; no websocket frames are sent after the upgrade negotiation.

**How to Execute:**
```bash
nmap -p 6080 --script vnc-novnc-websocket-probe target.example.com

# Tuned request budget
nmap -p 6080 --script vnc-novnc-websocket-probe --script-args 'vnc-novnc-websocket-probe.timeout=8,vnc-novnc-websocket-probe.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-novnc-websocket-probe:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - noVNC gateway exposed with an open websocket bridge
```

---

### 8. **vnc-cleartext-des-warning** - Cleartext / DES-56 Credential Exposure Warning
**Description:** Audits the advertised security types for credential exposure: plaintext

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Reads the advertised security list without authenticating.
- Maps each type to a strength family and computes the weakest exposed family.
- Reports a credential-exposure verdict with migration guidance.
- Why it matters: VNC challenge-response (type 2) keys are limited to 56 significant DES bits and the same response is reusable, enabling offline attacks. None sends credentials as no credential at all: the session simply opens.
- Safety: one handshake, offer read only; no authentication is attempted.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-cleartext-des-warning target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-cleartext-des-warning --script-args 'vnc-cleartext-des-warning.timeout=8,vnc-cleartext-des-warning.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-cleartext-des-warning:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - plaintext None authentication offered alongside DES-56 fallback
```

---

### 9. **vnc-max-auth-failures** - Authentication Throttling / Lockout Check
**Description:** Measures whether the server applies any account-less rate limiting:

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Confirms the VNC challenge-response type is offered.
- Performs up to guesslimit failed attempts with a fixed audit password, tracking challenge service, failures and connection drops.
- Estimates the effective lockout threshold from the observed pattern.
- Why it matters: VNC has no usernames: one weak password protects the console, and unlimited retries make offline-class guessing trivial from a single connection policy. Documenting the absence of throttling justifies gateway/front-door controls in the risk register.
- Safety: six attempts by default (hard cap 16) with a fixed audit-only password; legitimate users are never affected and no successful login is pursued.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-max-auth-failures target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-max-auth-failures --script-args 'vnc-max-auth-failures.timeout=8,vnc-max-auth-failures.maxrequests=64,vnc-max-auth-failures.guesslimit=6' target.example.com
```

**Sample Output:**
```
| vnc-max-auth-failures:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - no lockout or throttling after 6 consecutive failures
```

---

### 10. **vnc-repeater-proxy-detect** - VNC Repeater / Proxy Detection
**Description:** Detects a VNC repeater/proxy listener on port 5500: reads the null

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Connects and reads the repeater banner (RFB 000.000.000) or a normal VNC greeting.
- Sends one bounded ID-string and waits for the bridge reply.
- Classifies: open bridge, repeater ack only, plain VNC server, or silent port.
- Why it matters: Open repeaters let anyone stage inbound desktop tunnels through the host, hiding attacker infrastructure behind a legitimate asset. A repeater that answers an arbitrary ID with a live RFB peer is a full open relay for remote-control traffic.
- Safety: one connection, one ID-string; the audit ID is never bound to production sessions and the connection closes immediately.

**How to Execute:**
```bash
nmap -p 5500 --script vnc-repeater-proxy-detect target.example.com

# Tuned request budget
nmap -p 5500 --script vnc-repeater-proxy-detect --script-args 'vnc-repeater-proxy-detect.timeout=8,vnc-repeater-proxy-detect.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-repeater-proxy-detect:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - open repeater accepted the audit ID and answered with a bridged RFB peer
```

---

### 11. **vnc-reverse-connection-probe** - Reverse Connection Staging Probe
**Description:** Probes for reverse-VNC staging on port 5500: a listener waiting for a

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Reads the listener banner and distinguishes the repeater null banner from a normal VNC greeting.
- Sends one audit ID-string to test whether staging completes.
- Reports whether the host is staging reverse desktop sessions.
- Why it matters: Reverse VNC inverts the connection: the victim's desktop connects out to this listener, so the attacker never needs inbound access. A staging listener that already bridges to a live peer indicates an active remote-control channel through this host.
- Safety: single connection with one ID-string; no session data flows and the socket closes right after the handshake probe.

**How to Execute:**
```bash
nmap -p 5500 --script vnc-reverse-connection-probe target.example.com

# Tuned request budget
nmap -p 5500 --script vnc-reverse-connection-probe --script-args 'vnc-reverse-connection-probe.timeout=8,vnc-reverse-connection-probe.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-reverse-connection-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - reverse-VNC staging listener present (bridge-accepted)
```

---

### 12. **vnc-vencrypt-tls-support** - VeNCrypt / TLS Support Check
**Description:** Detects whether the server advertises TLS-capable security types

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Reads the security offer and searches the TLS-capable family.
- When found, performs one selection attempt and records the graceful refusal (the audit does not implement the TLS subprotocol).
- Reports support status with client-configuration guidance.
- Why it matters: Without an encrypted transport every VNC password is protected by 56-bit DES only and screen content travels in cleartext. Advertising VeNCrypt is the first configuration step most hardening guides require.
- Safety: offer read plus a single type selection; no handshake beyond the selection byte.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-vencrypt-tls-support target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-vencrypt-tls-support --script-args 'vnc-vencrypt-tls-support.timeout=8,vnc-vencrypt-tls-support.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-vencrypt-tls-support:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - no TLS-capable security type advertised (types: 1:None (unauthenticated), 2:VNC challenge-response (DES-56))
```

---

### 13. **vnc-color-depth-dos-check** - Pixel Format / Colour Depth Stability Check
**Description:** Reads the negotiated pixel format (bits per pixel, colour depth, byte

**Risk Level:** 🟢 LOW | **Category:** defensive, safe

**What it checks:**
- Establishes the best reachable session and parses ServerInit.
- Grades the pixel format (modern true-colour vs legacy palette).
- Reports stability-relevant characteristics without sending any format change.
- Why it matters: Very low depths (8bpp palette) and mismatched depth/bpp pairs trigger rendering bugs in several client generations and complicate encoding paths on the server. The audit documents the colour surface so image-quality and stability incidents can be correlated with the negotiated format.
- Safety: read-only; SetPixelFormat is never sent, so the server rendering path is untouched.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-color-depth-dos-check target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-color-depth-dos-check --script-args 'vnc-color-depth-dos-check.timeout=8,vnc-color-depth-dos-check.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-color-depth-dos-check:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - modern pixel format negotiated (24-bit colour depth (32bpp wire format))
```

---

### 14. **vnc-desktop-geometry-leak** - Desktop Geometry Pre-Auth Disclosure
**Description:** Reports whether the desktop geometry (screen resolution) and server name

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Establishes the best reachable pre-auth session.
- Parses ServerInit width/height/name and the pixel format.
- Grades the disclosure and maps geometry to common display profiles.
- Why it matters: Geometry and server names fingerprint the host model, locale and deployment for targeted attacks without touching authentication. Pre-auth disclosure confirms the server processes full client handshakes before any credential check.
- Safety: negotiation stops at ServerInit; no framebuffer content is requested.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-desktop-geometry-leak target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-desktop-geometry-leak --script-args 'vnc-desktop-geometry-leak.timeout=8,vnc-desktop-geometry-leak.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-desktop-geometry-leak:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - desktop geometry and server name disclosed pre-authentication (1024x768, 'legacy-vnc')
```

---

### 15. **vnc-rfb-version-fingerprint** - RFB Version Fingerprint
**Description:** Fingerprints the RFB ProtocolVersion banner the VNC server announces before

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Connects and reads the 12-byte ProtocolVersion greeting.
- Completes one offer-only handshake to learn the negotiated version.
- Maps the banner to a stack generation table and reports legacy flags.
- Why it matters: The banner fixes the maximum feature set of the session (security-type negotiation, VeNCrypt/TLS paths, result codes). Very old banners (3.3/3.7) correlate with unpatched builds that expose the MS12-020 and RealVNC 4.1 era flaws.
- Safety: one TCP session, banner read and security-type offer only; no authentication is attempted.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-rfb-version-fingerprint target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-rfb-version-fingerprint --script-args 'vnc-rfb-version-fingerprint.timeout=8,vnc-rfb-version-fingerprint.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-rfb-version-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - RFB 3.8 banner negotiated (RFB 3.8 (modern base protocol, SecurityResult mandatory))
```

---

### 16. **vnc-security-types-enum** - Security Type Enumeration
**Description:** Enumerates the security types the RFB server advertises and probes whether

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Completes one offer-only handshake and lists the advertised types.
- Classifies each type (plaintext, legacy DES, wrapper, strong, encrypted transport).
- Performs one None-selection probe to confirm what the server actually accepts.
- Why it matters: Security type 1 (None) means the desktop is reachable without any credential, the highest impact VNC exposure. The advertised list also tells whether encrypted transports (VeNCrypt/TLS family) exist at all.
- Safety: two bounded sessions; the None probe stops right after the SecurityResult and never draws screen content.

**How to Execute:**
```bash
nmap -p 5900 --script vnc-security-types-enum target.example.com

# Tuned request budget
nmap -p 5900 --script vnc-security-types-enum --script-args 'vnc-security-types-enum.timeout=8,vnc-security-types-enum.maxrequests=32' target.example.com
```

**Sample Output:**
```
| vnc-security-types-enum:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - security type None offered and accepted (unauthenticated access path)
```

