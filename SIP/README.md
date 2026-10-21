# 📞 SIP/VoIP Security Audits

**16 Nmap NSE scripts** for auditing SIP/VoIP services directly on the wire:

**Covers:**

- A full RFC 3261 message layer (request/response parsing with ordered + indexed headers, Via/Contact/URI/digest-challenge/Allow/Supported/SDP decoders)
- A self-contained MD5 with RFC 2617 digest authentication (MD5 and MD5-sess, qop=auth)
- Staged REGISTER probes that classify registrar answers (accepted/digest-challenge/not-found/forbidden)
- INVITE dialogs with SDP offers and ACK/BYE cleanup
- SUBSCRIBE presence and MESSAGE relay tests
- Blind-BYE dialog validation
- PBX engine fingerprints (Asterisk, FreePBX, Cisco CUCM, 3CX, Kamailio, OpenSIPS)
- SDP codec inventory with SRTP grading
- RFC1918 address-disclosure scanning
- A bounded OPTIONS burst rate probe (max 12) and an RFC 5630 SIPS/TLS 5061 certificate audit (subject/SAN/expiry grading)

**Every probe is bounded and self-cancelling:**

- Max 8 registration attempts
- Max 12 burst datagrams
- Dialogs torn down immediately.

**Ports:** 5060/udp+tcp (SIP) + 5061/tcp (SIPS/TLS) | **Protocol:** SIP RFC 3261, digest auth RFC 2617, SDP RFC 4566, SIPS RFC 5630 | **Total lines of Lua:** 52,400

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [sip-default-credentials](#1-sip-default-credentials---default-extension-credential-audit) | 🔴 CRITICAL | vuln, safe | 3299 |
| 2 | [sip-extension-enumeration](#2-sip-extension-enumeration---extension-enumeration-oracle) | 🔴 CRITICAL | vuln, safe | 3295 |
| 3 | [sip-unauthenticated-invite](#3-sip-unauthenticated-invite---open-call-relay-invite-test) | 🔴 CRITICAL | vuln, safe | 3265 |
| 4 | [sip-unauthenticated-register](#4-sip-unauthenticated-register---unauthenticated-register-test) | 🔴 CRITICAL | vuln, safe | 3267 |
| 5 | [sip-bye-teardown-spoof](#5-sip-bye-teardown-spoof---blind-bye-teardown--dialog-validation) | 🟠 HIGH | vuln, safe | 3267 |
| 6 | [sip-call-eavesdropping-rtp](#6-sip-call-eavesdropping-rtp---plain-rtp-vs-srtp-media-audit) | 🟠 HIGH | vuln, safe | 3280 |
| 7 | [sip-callerid-spoof-check](#7-sip-callerid-spoof-check---caller-id-spoof-acceptance-test) | 🟠 HIGH | vuln, safe | 3288 |
| 8 | [sip-message-spam-relay](#8-sip-message-spam-relay---unauthenticated-message-relay-test) | 🟠 HIGH | vuln, safe | 3265 |
| 9 | [sip-cleartext-udp-warning](#9-sip-cleartext-udp-warning---cleartext-udptcp-signaling-warning) | 🟡 MEDIUM | defensive, safe | 3247 |
| 10 | [sip-method-flood-dos](#10-sip-method-flood-dos---request-rate-limit-probe) | 🟡 MEDIUM | defensive, safe | 3281 |
| 11 | [sip-nat-traversal-leak](#11-sip-nat-traversal-leak---rfc1918-header-address-disclosure) | 🟡 MEDIUM | discovery, safe | 3262 |
| 12 | [sip-presence-subscription](#12-sip-presence-subscription---unauthenticated-presence-subscription) | 🟡 MEDIUM | discovery, safe | 3267 |
| 13 | [sip-tls-cert-validation](#13-sip-tls-cert-validation---sips-tls-certificate-validation) | 🟡 MEDIUM | defensive, safe | 3306 |
| 14 | [sip-sdp-codec-audit](#14-sip-sdp-codec-audit---sdp-codec-inventory-audit) | 🟢 LOW | discovery, safe | 3276 |
| 15 | [sip-server-fingerprint](#15-sip-server-fingerprint---pbx-engine-fingerprint) | 🟢 LOW | discovery, safe | 3267 |
| 16 | [sip-unauth-options-enum](#16-sip-unauth-options-enum---anonymous-options-capability-enum) | 🟢 LOW | discovery, safe | 3268 |

---

### 1. **sip-default-credentials** - Default Extension Credential Audit
**Description:** Tests the classic default extension credentials (100/100, admin/admin

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Checks the anonymous registration path first (200 = immediate critical finding).
- Otherwise walks the default pairs through the full MD5 digest flow.
- Reports each pair's outcome and stops at the first acceptance.
- Why it matters: Deployed phones ship with well-known extension secrets that are rarely changed; each hit is a usable PBX account. Digest authentication with a weak password falls to offline guessing once the challenge nonce is captured.
- Safety: at most guesslimit registration attempts (default cap 8), one attempt per pair, no lockout loops.

**How to Execute:**
```bash
nmap -p 5060 --script sip-default-credentials -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-default-credentials -sU --script-args 'sip-default-credentials.timeout=8,sip-default-credentials.maxrequests=48,sip-default-credentials.retries=1,sip-default-credentials.guesslimit=8' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-default-credentials:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - no default credential accepted in 4 attempt(s)
```

---

### 2. **sip-extension-enumeration** - Extension Enumeration Oracle
**Description:** Enumerates internal PBX extensions by issuing one anonymous REGISTER

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends single anonymous REGISTERs for the configured extensions (default 100-110/1000-1010 samples plus a canary).
- Classifies each answer as registered / challenge / not-found / forbidden.
- Reports the enumeration oracle and any accepted registrations.
- Why it matters: Different answers for existing vs unknown extensions give attackers a validated user list for credential guessing and spam voice phishing. Silent, uniform answers close that oracle entirely.
- Safety: one REGISTER per configured extension without credentials, hard-capped by the request budget; no password is sent.

**How to Execute:**
```bash
nmap -p 5060 --script sip-extension-enumeration -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-extension-enumeration -sU --script-args 'sip-extension-enumeration.timeout=8,sip-extension-enumeration.maxrequests=48,sip-extension-enumeration.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-extension-enumeration:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - uniform challenge answers; no registration or enumeration oracle observed
```

---

### 3. **sip-unauthenticated-invite** - Open Call Relay (INVITE) Test
**Description:** Sends one unauthenticated INVITE with a minimal SDP offer to test for

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends a single INVITE with an audit SDP offer (PCMU/PCMA/G.729).
- Classifies the final answer: relayed (2xx), auth-gated (401/407), refused (403/404/486).
- Tears the dialog down immediately with ACK/BYE on success.
- Why it matters: A PBX that completes an anonymous INVITE lets anyone place calls at the owner's expense and reach internal dial plans. Auth-gated INVITE handling (401/407) is the expected control.
- Safety: exactly one call attempt to the audit extension, cancelled right away; no DTMF, media or transfer is attempted.

**How to Execute:**
```bash
nmap -p 5060 --script sip-unauthenticated-invite -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-unauthenticated-invite -sU --script-args 'sip-unauthenticated-invite.timeout=8,sip-unauthenticated-invite.maxrequests=48,sip-unauthenticated-invite.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-unauthenticated-invite:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - INVITE is auth-gated (407; realm corp.sip)
```

---

### 4. **sip-unauthenticated-register** - Unauthenticated REGISTER Test
**Description:** Tests whether the SIP registrar accepts extension registration without

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends one anonymous REGISTER for the audit extension.
- Classifies: accepted (200), digest challenge (401/407), refused (403), unknown extension (404).
- Never follows the challenge with credentials.
- Why it matters: An unauthenticated registration is full PBX account compromise: callers can receive the target extension's calls and place outbound ones (toll fraud). Registrars demanding a challenge on first attempt expose no surface.
- Safety: a single REGISTER without credentials; the session closes immediately after classification.

**How to Execute:**
```bash
nmap -p 5060 --script sip-unauthenticated-register -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-unauthenticated-register -sU --script-args 'sip-unauthenticated-register.timeout=8,sip-unauthenticated-register.maxrequests=48,sip-unauthenticated-register.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-unauthenticated-register:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - registrar demands digest authentication before any registration (401)
```

---

### 5. **sip-bye-teardown-spoof** - Blind BYE Teardown / Dialog Validation
**Description:** Checks whether the server validates Call-ID and tags on BYE requests

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends a single BYE for a fresh, never-established Call-ID.
- Classifies: blind teardown accepted (200), validated (481/403/404), unclear.
- No real dialog is ever touched.
- Why it matters: A server that answers a forged BYE with 200 OK lets anyone drop active calls (financial desks, support lines) by guessing Call-IDs. A 481 "Call/Transaction Does Not Exist" answer proves dialog state is validated.
- Safety: one forged BYE with a random Call-ID; no existing call is referenced.

**How to Execute:**
```bash
nmap -p 5060 --script sip-bye-teardown-spoof -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-bye-teardown-spoof -sU --script-args 'sip-bye-teardown-spoof.timeout=8,sip-bye-teardown-spoof.maxrequests=48,sip-bye-teardown-spoof.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-bye-teardown-spoof:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - unknown dialog rejected (481)
```

---

### 6. **sip-call-eavesdropping-rtp** - Plain RTP vs SRTP Media Audit
**Description:** Checks whether the SDP answer negotiates plain RTP instead of SRTP: a

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends one INVITE with a plain audit SDP offer.
- Parses the server's SDP answer for the media protocol and crypto attributes.
- Classifies plain-RTP vs SRTP negotiation.
- Why it matters: Plain RTP carries the full conversation with no encryption; on-path capture reproduces the entire call. SRTP (RTP/SAVP or a=crypto) closes that channel when both sides support it.
- Safety: one SDP exchange with no media ever transmitted; the dialog is torn down immediately.

**How to Execute:**
```bash
nmap -p 5060 --script sip-call-eavesdropping-rtp -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-call-eavesdropping-rtp -sU --script-args 'sip-call-eavesdropping-rtp.timeout=8,sip-call-eavesdropping-rtp.maxrequests=48,sip-call-eavesdropping-rtp.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-call-eavesdropping-rtp:
|   Risk Level: 🟠 HIGH
|   Status: INFORMATIONAL - SDP answer gated behind authentication (407); media policy not observable
```

---

### 7. **sip-callerid-spoof-check** - Caller-ID Spoof Acceptance Test
**Description:** Tests whether the server validates From and P-Asserted-Identity headers

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends a single INVITE with a spoofed P-Asserted-Identity and a foreign From user.
- Classifies: relayed blind (2xx), refused/forbidden (403), auth-gated (401/407).
- Cleans the dialog up immediately when a call path opens.
- Why it matters: Blind acceptance of caller-ID claims enables voice phishing that displays internal or trusted numbers (bank, IT helpdesk, executive). Servers that gate the call still close the spoofing surface.
- Safety: one INVITE to the audit extension, torn down at once; no calls to external destinations.

**How to Execute:**
```bash
nmap -p 5060 --script sip-callerid-spoof-check -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-callerid-spoof-check -sU --script-args 'sip-callerid-spoof-check.timeout=8,sip-callerid-spoof-check.maxrequests=48,sip-callerid-spoof-check.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-callerid-spoof-check:
|   Risk Level: 🟠 HIGH
|   Status: INFORMATIONAL - call path auth-gated (407); identity policy could not be observed past the gate
```

---

### 8. **sip-message-spam-relay** - Unauthenticated MESSAGE Relay Test
**Description:** Tests for unauthenticated SIP MESSAGE relay: sends up to three short

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends at most three MESSAGE requests (short audit text).
- Counts acceptances (2xx) vs refusals (403/401).
- No registration state or user data is read.
- Why it matters: Open MESSAGE relay is a spam/phishing channel that renders as an internal chat or missed-call notification on desk phones. Acceptance without digest auth means any LAN host can message every extension.
- Safety: three bounded text payloads to the audit extensions; no mass messaging.

**How to Execute:**
```bash
nmap -p 5060 --script sip-message-spam-relay -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-message-spam-relay -sU --script-args 'sip-message-spam-relay.timeout=8,sip-message-spam-relay.maxrequests=48,sip-message-spam-relay.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-message-spam-relay:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - MESSAGE relay refused in all 3 probe(s)
```

---

### 9. **sip-cleartext-udp-warning** - Cleartext UDP/TCP Signaling Warning
**Description:** Flags cleartext UDP/TCP SIP signaling on port 5060 as opposed to

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Probes the plain 5060 transport with one OPTIONS.
- Records that signaling is cleartext and what it exposes.
- Notes whether the platform advertises SIPS support.
- Why it matters: Digest authentication protects the password, not the conversation: caller IDs, extensions, presence and SDP topology are all readable. SIPS (RFC 5630) moves signaling to TLS where the full metadata is protected.
- Safety: a single read-only exchange.

**How to Execute:**
```bash
nmap -p 5060 --script sip-cleartext-udp-warning -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-cleartext-udp-warning -sU --script-args 'sip-cleartext-udp-warning.timeout=8,sip-cleartext-udp-warning.maxrequests=48,sip-cleartext-udp-warning.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-cleartext-udp-warning:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - SIP signaling runs in cleartext on 5060; metadata is readable on-path
```

---

### 10. **sip-method-flood-dos** - Request Rate-Limit Probe
**Description:** Measures SIP request rate limiting: a short burst of OPTIONS requests

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Sends floodcount OPTIONS requests on one connection (hard cap 12).
- Counts replies and classifies 503/4xx throttling signals.
- Reports the observed limiting behaviour.
- Why it matters: SIP transaction processing is expensive; unthrottled servers fall to register/invite floods (the classic VoiPoS-style exhaustion). A 503 wall after N requests proves working overload protection.
- Safety: at most 12 tiny requests in one short burst - orders of magnitude below any real flood; no registration or call state.

**How to Execute:**
```bash
nmap -p 5060 --script sip-method-flood-dos -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-method-flood-dos -sU --script-args 'sip-method-flood-dos.timeout=8,sip-method-flood-dos.maxrequests=48,sip-method-flood-dos.retries=1,sip-method-flood-dos.floodcount=8' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-method-flood-dos:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - throttling engaged (5x503 after 3 served)
```

---

### 11. **sip-nat-traversal-leak** - RFC1918 Header Address Disclosure
**Description:** Inspects Via, Contact, Record-Route and related headers for internal

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends one OPTIONS and one INVITE-style probe.
- Collects every Via/Contact/Record-Route/PAI address.
- Classifies RFC1918/loopback/link-local disclosures.
- Why it matters: Internal addresses in SIP headers map the hidden PBX topology for attackers and break NAT traversal for remote handsets at the same time. The disclosure usually signals missing topography rewriting ( NAT helpers/ALGs disabled).
- Safety: read-only exchanges; no registration or calls.

**How to Execute:**
```bash
nmap -p 5060 --script sip-nat-traversal-leak -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-nat-traversal-leak -sU --script-args 'sip-nat-traversal-leak.timeout=8,sip-nat-traversal-leak.maxrequests=48,sip-nat-traversal-leak.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-nat-traversal-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - no internal addresses disclosed in the answer headers
```

---

### 12. **sip-presence-subscription** - Unauthenticated Presence Subscription
**Description:** Tests unauthenticated SIP SUBSCRIBE for user presence: one anonymous

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends one anonymous SUBSCRIBE for the presence package.
- Classifies: accepted with a PIDF body (leak), accepted without body, challenge/refused.
- The subscription is never renewed.
- Why it matters: Presence leaks working hours, call activity and out-of-office state for every listed user - a reconnaissance gift for social engineering. Open subscriptions also enable presence-flood noise on busy desks.
- Safety: a single short subscription; nothing is published or modified.

**How to Execute:**
```bash
nmap -p 5060 --script sip-presence-subscription -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-presence-subscription -sU --script-args 'sip-presence-subscription.timeout=8,sip-presence-subscription.maxrequests=48,sip-presence-subscription.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-presence-subscription:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - presence subscription refused (401)
```

---

### 13. **sip-tls-cert-validation** - SIPS TLS Certificate Validation
**Description:** Audits the SIPS TLS endpoint on 5061: performs a handshake, decodes the

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Performs a TLS handshake on 5061 with SNI set to the target name.
- Decodes subject, issuer, SAN and validity from the leaf certificate.
- Classifies hostname match, expiry window and issuer trust posture.
- Why it matters: SIPS without a valid, name-matching certificate is silently downgraded by most handsets, pushing traffic back to cleartext 5060. Expired or self-signed certificates are the top reason VoIP TLS deployments fail silently.
- Safety: a single handshake; no SIP transaction is sent inside the tunnel.

**How to Execute:**
```bash
nmap -p 5061 --script sip-tls-cert-validation pbx01.corp.example.com

# Tuned request budget
nmap -p 5061 --script sip-tls-cert-validation --script-args 'sip-tls-cert-validation.timeout=8,sip-tls-cert-validation.maxrequests=48,sip-tls-cert-validation.retries=1,sip-tls-cert-validation.tlsport=5061' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-tls-cert-validation:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - SIPS TLS present but certificate issues: hostname mismatch; expiry within 20 days
```

---

### 14. **sip-sdp-codec-audit** - SDP Codec Inventory Audit
**Description:** Inspects the audio codecs the PBX offers in its SDP answer (G.711

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends one INVITE with a codec-probing SDP offer.
- Extracts every m=audio payload with its rtpmap name.
- Grades the inventory and the media transport security.
- Why it matters: Codec inventory drives bandwidth planning and interop, and flags low-bitrate codecs (G.729, Speex, iLBC) whose transcoding and quality trade-offs need explicit approval. The media protocol row doubles as an SRTP posture check.
- Safety: one SDP exchange, no media transmitted.

**How to Execute:**
```bash
nmap -p 5060 --script sip-sdp-codec-audit -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-sdp-codec-audit -sU --script-args 'sip-sdp-codec-audit.timeout=8,sip-sdp-codec-audit.maxrequests=48,sip-sdp-codec-audit.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-sdp-codec-audit:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - SDP answer gated behind authentication (407)
```

---

### 15. **sip-server-fingerprint** - PBX Engine Fingerprint
**Description:** Fingerprints the PBX engine behind the SIP service from Server and

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends one OPTIONS request and captures the response headers.
- Classifies the engine and version from Server/User-Agent.
- Records Allow, Supported and Accept capabilities.
- Why it matters: The engine identity drives every other SIP audit: version-specific advisories, default dial-plan behaviour and vendor hardening guides. The Allow/Supported profile shows which extensions and methods the platform runs.
- Safety: a single read-only OPTIONS exchange; no registration state is touched.

**How to Execute:**
```bash
nmap -p 5060 --script sip-server-fingerprint -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-server-fingerprint -sU --script-args 'sip-server-fingerprint.timeout=8,sip-server-fingerprint.maxrequests=48,sip-server-fingerprint.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-server-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - PBX identified: Kamailio 5.7.2
```

---

### 16. **sip-unauth-options-enum** - Anonymous OPTIONS Capability Enum
**Description:** Maps what an unauthenticated OPTIONS exchange discloses: whether the

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends one anonymous OPTIONS request.
- Records status, method and extension advertisement.
- Flags sensitive methods exposed to anonymous callers.
- Why it matters: Anonymous OPTIONS answers are the standard reconnaissance step before extension scanning and registration abuse. The method list reveals risky capabilities (MESSAGE relay, SUBSCRIBE presence, REFER) reachable without authentication.
- Safety: a single OPTIONS exchange; nothing is registered, dialed or subscribed.

**How to Execute:**
```bash
nmap -p 5060 --script sip-unauth-options-enum -sU pbx01.corp.example.com

# Tuned request budget
nmap -p 23 --script sip-unauth-options-enum -sU --script-args 'sip-unauth-options-enum.timeout=8,sip-unauth-options-enum.maxrequests=48,sip-unauth-options-enum.retries=1' pbx01.corp.example.com
```

**Sample Output:**
```
| sip-unauth-options-enum:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - anonymous clients see sensitive methods: SUBSCRIBE
```

