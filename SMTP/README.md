# ✉️ SMTP Security Audits

**16 Nmap NSE scripts** for auditing SMTP/ESMTP services directly on the wire:

**Covers:**

- A full RFC 5321 layer (multiline reply parsing with enhanced status codes, EHLO keyword extraction with SIZE/AUTH-mechanism decoding, MTA engine fingerprints for Postfix/Exim/Sendmail/Exchange and peers)
- RFC 2920 pipelined-command probes with multi-reply draining
- STARTTLS upgrade with real TLS handshakes and a three-profile cipher audit (AEAD baseline, TLS 1.3 offer, legacy RC4 rejection)
- AUTH PLAIN/LOGIN probes over a self-contained base64 codec
- RSET-based envelope probes that stop before DATA (open relay, RCPT oracles, null-sender backscatter, internal-facade bypass)
- VRFY/EXPN/HELP enumeration checks
- Cleartext-AUTH/strict-TLS policy grading

**Every probe is bounded:**

- Max 8 authentication attempts
- Envelopes abandoned at the first refusal
- One-line audit payloads only.

**Ports:** 25/tcp (SMTP) + 587/tcp (submission) | **Protocol:** SMTP/ESMTP RFC 5321, pipelining RFC 2920, STARTTLS RFC 3207, AUTH RFC 4954 | **Total lines of Lua:** 44,143

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [smtp-cleartext-auth-allowed](#1-smtp-cleartext-auth-allowed---pre-tls-cleartext-auth-check) | 🔴 CRITICAL | defensive, safe | 2756 |
| 2 | [smtp-default-credentials](#2-smtp-default-credentials---submission-default-credential-audit) | 🔴 CRITICAL | vuln, safe | 2771 |
| 3 | [smtp-open-relay-check](#3-smtp-open-relay-check---open-relay-envelope-test) | 🔴 CRITICAL | vuln, safe | 2764 |
| 4 | [smtp-rcpt-to-user-enum](#4-smtp-rcpt-to-user-enum---rcpt-to-user-enumeration-oracle) | 🟠 HIGH | vuln, safe | 2775 |
| 5 | [smtp-smarthost-auth-bypass](#5-smtp-smarthost-auth-bypass---internal-facade-relay-bypass-test) | 🟠 HIGH | vuln, safe | 2766 |
| 6 | [smtp-vrfy-user-enumeration](#6-smtp-vrfy-user-enumeration---vrfyexpn-enumeration-test) | 🟠 HIGH | vuln, safe | 2785 |
| 7 | [smtp-max-message-size](#7-smtp-max-message-size---size-limit--queue-exhaustion-audit) | 🟡 MEDIUM | defensive, safe | 2750 |
| 8 | [smtp-null-sender-bounce](#8-smtp-null-sender-bounce---null-sender-bounce--backscatter-test) | 🟡 MEDIUM | defensive, safe | 2755 |
| 9 | [smtp-pipelining-dos-tolerance](#9-smtp-pipelining-dos-tolerance---pipelining-tolerance-probe) | 🟡 MEDIUM | defensive, safe | 2755 |
| 10 | [smtp-spf-dkim-dmarc-check](#10-smtp-spf-dkim-dmarc-check---email-auth-identity-alignment-audit) | 🟡 MEDIUM | defensive, safe | 2751 |
| 11 | [smtp-starttls-support](#11-smtp-starttls-support---starttls-advertisement--handshake) | 🟡 MEDIUM | defensive, safe | 2778 |
| 12 | [smtp-strict-tls-enforcement](#12-smtp-strict-tls-enforcement---cleartext-transaction-enforcement) | 🟡 MEDIUM | defensive, safe | 2751 |
| 13 | [smtp-tls-ciphers-audit](#13-smtp-tls-ciphers-audit---starttls-cipher-profile-audit) | 🟡 MEDIUM | defensive, safe | 2768 |
| 14 | [smtp-banner-grab](#14-smtp-banner-grab---smtp-banner--mta-fingerprint) | 🟢 LOW | discovery, safe | 2740 |
| 15 | [smtp-commands-enum](#15-smtp-commands-enum---esmtp-capability-enumeration) | 🟢 LOW | discovery, safe | 2738 |
| 16 | [smtp-help-info-leak](#16-smtp-help-info-leak---help-disclosure-check) | 🟢 LOW | discovery, safe | 2740 |

---

### 1. **smtp-cleartext-auth-allowed** - Pre-TLS Cleartext AUTH Check
**Description:** Checks whether the server advertises AUTH PLAIN or AUTH LOGIN before

**Risk Level:** 🔴 CRITICAL | **Category:** defensive, safe

**What it checks:**
- Opens a session on the target port and issues EHLO before any TLS.
- Extracts the AUTH mechanisms offered at this layer.
- Grades the cleartext credential surface.
- Why it matters: AUTH PLAIN/LOGIN on a cleartext port hands passwords to every on-path listener - the single most abused mail-server misconfiguration. Hardened MTAs hide AUTH until TLS is active or restrict it to ports that require TLS first.
- Safety: one EHLO; no authentication is attempted here.

**How to Execute:**
```bash
nmap -p 25 --script smtp-cleartext-auth-allowed mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-cleartext-auth-allowed --script-args 'smtp-cleartext-auth-allowed.timeout=8,smtp-cleartext-auth-allowed.maxrequests=48,smtp-cleartext-auth-allowed.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-cleartext-auth-allowed:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - no AUTH advertised before STARTTLS on this port
```

---

### 2. **smtp-default-credentials** - Submission Default Credential Audit
**Description:** Tests common default SMTP submission credentials (admin/admin,

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens the submission session and reads the AUTH advertisement.
- Walks the default pairs through AUTH PLAIN (bounded by guesslimit).
- Stops at the first acceptance and reports it.
- Why it matters: Compromised submission credentials are gold for attackers: they send authenticated phishing from the owner's own infrastructure and land in every inbox. Each accepted default pair is an immediately usable mail account.
- Safety: at most guesslimit authentication attempts (default cap 8); no mail is submitted.

**How to Execute:**
```bash
nmap -p 587 --script smtp-default-credentials mail01.corp.example.com

# Tuned request budget
nmap -p 587 --script smtp-default-credentials --script-args 'smtp-default-credentials.timeout=8,smtp-default-credentials.maxrequests=48,smtp-default-credentials.recv_window=6,smtp-default-credentials.guesslimit=8' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-default-credentials:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - no default credential accepted in 4 attempt(s)
```

---

### 3. **smtp-open-relay-check** - Open Relay Envelope Test
**Description:** Tests for open mail relaying with a non-destructive envelope: MAIL FROM

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends one MAIL FROM (external audit sender).
- Sends one RCPT TO (external victim domain).
- Classifies relay permission from the answer pair; never sends DATA.
- Why it matters: An open relay turns your MTA into spam and phishing infrastructure and gets the domain blocklisted within hours. The MAIL/RCPT answer pair alone proves or refutes relay permission.
- Safety: one envelope, aborted before DATA; no message exists.

**How to Execute:**
```bash
nmap -p 25 --script smtp-open-relay-check mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-open-relay-check --script-args 'smtp-open-relay-check.timeout=8,smtp-open-relay-check.maxrequests=48,smtp-open-relay-check.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-open-relay-check:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - transactions require TLS first (530 5.7.0); relay is policy-gated
```

---

### 4. **smtp-rcpt-to-user-enum** - RCPT TO User Enumeration Oracle
**Description:** Probes RCPT TO response codes for dictionary user harvesting: each

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Opens one session and probes each configured address with a full envelope (RSET between probes).
- Classifies every answer and measures oracle strength.
- No message data is ever sent.
- Why it matters: A working RCPT oracle gives attackers a validated recipient list for phishing and credential-spray campaigns. Uniform answers (catch-all or 4xx) close the oracle entirely.
- Safety: at most one envelope per configured name (six by default), no DATA.

**How to Execute:**
```bash
nmap -p 25 --script smtp-rcpt-to-user-enum mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-rcpt-to-user-enum --script-args 'smtp-rcpt-to-user-enum.timeout=8,smtp-rcpt-to-user-enum.maxrequests=48,smtp-rcpt-to-user-enum.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-rcpt-to-user-enum:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - uniform refusals; no recipient oracle observed
```

---

### 5. **smtp-smarthost-auth-bypass** - Internal-Facade Relay Bypass Test
**Description:** Tests whether internal-looking identities bypass authentication: an

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Performs EHLO announcing an internal IP literal.
- Sends MAIL FROM root@internal-domain and RCPT TO an external victim.
- Classifies whether the internal facade grants relay permission.
- Why it matters: Legacy "trusted network" relay rules keyed on HELO/EHLO names or sender domains let attackers on any network relay once they spoof the internal identity. Proper smarthosts require authentication or IP-based ACLs on real routing infrastructure, not string matching.
- Safety: one envelope, aborted before DATA.

**How to Execute:**
```bash
nmap -p 25 --script smtp-smarthost-auth-bypass mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-smarthost-auth-bypass --script-args 'smtp-smarthost-auth-bypass.timeout=8,smtp-smarthost-auth-bypass.maxrequests=48,smtp-smarthost-auth-bypass.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-smarthost-auth-bypass:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - TLS required before transactions (530); the facade never reached the relay decision
```

---

### 6. **smtp-vrfy-user-enumeration** - VRFY/EXPN Enumeration Test
**Description:** Tests whether VRFY and EXPN are enabled: VRFY root/admin/ghost probes

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends VRFY for each configured name plus one EXPN.
- Classifies: disclosure (250/251), weak (252), disabled (502/500), denied (550).
- Measures whether the answers separate real from unknown users.
- Why it matters: VRFY answers (250/550) are the cheapest verified-mailbox oracle in the protocol. EXPN can expose entire distribution lists with internal addresses.
- Safety: at most one VRFY per configured name and a single EXPN; no envelopes are opened.

**How to Execute:**
```bash
nmap -p 25 --script smtp-vrfy-user-enumeration mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-vrfy-user-enumeration --script-args 'smtp-vrfy-user-enumeration.timeout=8,smtp-vrfy-user-enumeration.maxrequests=48,smtp-vrfy-user-enumeration.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-vrfy-user-enumeration:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - VRFY is disabled or uniformly denied; EXPN 502
```

---

### 7. **smtp-max-message-size** - SIZE Limit / Queue Exhaustion Audit
**Description:** Checks the SIZE extension limit to gauge mailbox/connection exhaustion

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Performs EHLO and reads the SIZE keyword.
- Grades the limit (absent, small, generous, very large).
- No message data is ever sent.
- Why it matters: Unbounded message sizes are a classic queue-exhaustion vector and complicate capacity planning. A declared SIZE ceiling lets clients pre-reject and keeps the queue bounded.
- Safety: a single EHLO; zero bytes of mail payload.

**How to Execute:**
```bash
nmap -p 25 --script smtp-max-message-size mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-max-message-size --script-args 'smtp-max-message-size.timeout=8,smtp-max-message-size.maxrequests=48,smtp-max-message-size.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-max-message-size:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - SIZE limit declared: 35882577 bytes (34.2 MB)
```

---

### 8. **smtp-null-sender-bounce** - Null-Sender Bounce / Backscatter Test
**Description:** Tests bounce handling with the null sender: sends MAIL FROM:<> with a

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Sends one envelope with the null sender and a short audit payload.
- Records MAIL/RCPT/DATA outcomes and the queue decision.
- The payload is a one-line audit marker, never delivered content.
- Why it matters: Open bounce paths let attackers spam third parties using your server as the origin (backscatter amplification). Servers that reject null-sender DATA or verify recipients first stay off the backscatter blocklists.
- Safety: exactly one tiny message; no third-party recipients.

**How to Execute:**
```bash
nmap -p 25 --script smtp-null-sender-bounce mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-null-sender-bounce --script-args 'smtp-null-sender-bounce.timeout=8,smtp-null-sender-bounce.maxrequests=48,smtp-null-sender-bounce.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-null-sender-bounce:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - envelope refused before DATA (530/-)
```

---

### 9. **smtp-pipelining-dos-tolerance** - Pipelining Tolerance Probe
**Description:** Tests the server's command pipelining behaviour: sends three ordinary

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Sends NOOP/NOOP/RSET batched in one write (three tiny commands).
- Counts the replies and checks EHLO's PIPELINING advertisement.
- No oversized lines are ever sent - the parser robustness boundary.
- Why it matters: Pipelining accelerates spam delivery; servers must advertise it and bound its use. Tolerating arbitrary pipelined input without advertisement or limits signals a permissive parser worth monitoring.
- Safety: three trivial commands in one burst; no DATA payload.

**How to Execute:**
```bash
nmap -p 25 --script smtp-pipelining-dos-tolerance mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-pipelining-dos-tolerance --script-args 'smtp-pipelining-dos-tolerance.timeout=8,smtp-pipelining-dos-tolerance.maxrequests=48,smtp-pipelining-dos-tolerance.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-pipelining-dos-tolerance:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - batch answered (3/3) without PIPELINING advertisement
```

---

### 10. **smtp-spf-dkim-dmarc-check** - Email-Auth Identity Alignment Audit
**Description:** Audits the MTA-side email-auth posture: collects the server's announced

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Captures the 220 greeting and the EHLO capability hostname.
- Grades identity alignment between the two.
- Documents the SPF/DKIM/DMARC verification checklist for the domain.
- Why it matters: Misaligned HELO identities and missing SPF/DKIM/DMARC records are the top reasons legitimate mail is spoofed or rejected. The banner hostname is what other MTAs check first.
- Safety: one session, one greeting, one EHLO.

**How to Execute:**
```bash
nmap -p 25 --script smtp-spf-dkim-dmarc-check mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-spf-dkim-dmarc-check --script-args 'smtp-spf-dkim-dmarc-check.timeout=8,smtp-spf-dkim-dmarc-check.maxrequests=48,smtp-spf-dkim-dmarc-check.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-spf-dkim-dmarc-check:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - MTA identity alignment looks consistent (corp.example.com ESMTP Postfix (hardened)
```

---

### 11. **smtp-starttls-support** - STARTTLS Advertisement + Handshake
**Description:** Checks whether the server advertises and actually negotiates STARTTLS

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Reads the EHLO STARTTLS advertisement.
- Issues STARTTLS and expects 220.
- Performs a real TLS handshake on the upgraded socket.
- Why it matters: Many MTAs advertise STARTTLS but break at the handshake (expired certs, protocol mismatches), silently degrading everyone to cleartext. Verified TLS support is the baseline for every credential-bearing mail flow.
- Safety: one handshake attempt; no mail is exchanged inside the tunnel.

**How to Execute:**
```bash
nmap -p 25 --script smtp-starttls-support mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-starttls-support --script-args 'smtp-starttls-support.timeout=8,smtp-starttls-support.maxrequests=48,smtp-starttls-support.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-starttls-support:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - STARTTLS advertised and a real handshake completed (TLS 1.2)
```

---

### 12. **smtp-strict-tls-enforcement** - Cleartext Transaction Enforcement
**Description:** Tests whether the server requires TLS before accepting mail

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Performs EHLO and sends one MAIL FROM without issuing STARTTLS.
- Records whether the transaction layer accepts cleartext envelopes.
- The envelope is abandoned with RSET; nothing is delivered.
- Why it matters: Strict-mode MTAs (required STARTTLS / DANE-validated) refuse cleartext transactions, closing the downgrade window. Accepting MAIL FROM pre-TLS means every envelope - senders, recipients, sizes - transits in cleartext when the peer skips TLS.
- Safety: one envelope command, no RCPT, no DATA.

**How to Execute:**
```bash
nmap -p 25 --script smtp-strict-tls-enforcement mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-strict-tls-enforcement --script-args 'smtp-strict-tls-enforcement.timeout=8,smtp-strict-tls-enforcement.maxrequests=48,smtp-strict-tls-enforcement.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-strict-tls-enforcement:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - transaction refused without TLS (530 5.7.0 Must issue a STARTTLS command first)
```

---

### 13. **smtp-tls-ciphers-audit** - STARTTLS Cipher Profile Audit
**Description:** Audits the TLS profile negotiated after STARTTLS: a modern AEAD

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Baseline handshake with AEAD-only suites.
- TLS 1.3 offer via supported_versions.
- Legacy RC4-only offer (should be rejected).
- Why it matters: Mail TLS is often the oldest certificate and protocol stack on the network; RC4/CBC/export suites still linger on legacy gateways. The negotiated profile is what actually protects the credentials and envelopes.
- Safety: three handshakes total; no mail flows inside the tunnels.

**How to Execute:**
```bash
nmap -p 25 --script smtp-tls-ciphers-audit mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-tls-ciphers-audit --script-args 'smtp-tls-ciphers-audit.timeout=8,smtp-tls-ciphers-audit.maxrequests=48,smtp-tls-ciphers-audit.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-tls-ciphers-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - modern TLS baseline negotiates (TLS 1.2 / TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); RC4 rejected; TLS1.3 offered
```

---

### 14. **smtp-banner-grab** - SMTP Banner / MTA Fingerprint
**Description:** Captures the SMTP 220 greeting and extracts the announced hostname, the

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Opens a session and reads the 220 greeting.
- Classifies the MTA engine and version.
- Records the announced hostname and protocol level.
- Why it matters: The banner identifies the MTA product and version, which drives version-specific advisory checking for the whole mail stack. The announced hostname feeds SPF/MX alignment checks.
- Safety: one connection, one greeting read, QUIT immediately.

**How to Execute:**
```bash
nmap -p 25 --script smtp-banner-grab mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-banner-grab --script-args 'smtp-banner-grab.timeout=8,smtp-banner-grab.maxrequests=48,smtp-banner-grab.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-banner-grab:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - MTA identified: Postfix
```

---

### 15. **smtp-commands-enum** - ESMTP Capability Enumeration
**Description:** Sends EHLO and extracts every supported ESMTP capability: SIZE limit,

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Opens a session and performs EHLO.
- Records every advertised keyword with its parameters.
- Highlights security-relevant extensions.
- Why it matters: The capability set defines the attack surface: STARTTLS presence, the message-size ceiling and pipelining all shape the other audits. Extension profiles identify the MTA product line and configuration depth.
- Safety: one EHLO exchange; QUIT immediately after.

**How to Execute:**
```bash
nmap -p 25 --script smtp-commands-enum mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-commands-enum --script-args 'smtp-commands-enum.timeout=8,smtp-commands-enum.maxrequests=48,smtp-commands-enum.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-commands-enum:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - capability map captured (6 extension(s))
```

---

### 16. **smtp-help-info-leak** - HELP Disclosure Check
**Description:** Sends HELP and HELP <command> to check for verbose help disclosures:

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends one bare HELP and one HELP MAIL.
- Classifies the answers (214 disclosure vs 502 disabled).
- Records any text returned.
- Why it matters: Verbose HELP text confirms the exact MTA build to attackers and occasionally documents non-standard internal commands. Most hardened servers answer 502; a 214 answer documents the disclosure.
- Safety: two HELP exchanges; nothing else.

**How to Execute:**
```bash
nmap -p 25 --script smtp-help-info-leak mail01.corp.example.com

# Tuned request budget
nmap -p 23 --script smtp-help-info-leak --script-args 'smtp-help-info-leak.timeout=8,smtp-help-info-leak.maxrequests=48,smtp-help-info-leak.recv_window=6' mail01.corp.example.com
```

**Sample Output:**
```
| smtp-help-info-leak:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - HELP is not disclosed (502)
```

