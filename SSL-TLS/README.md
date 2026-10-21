# 🛡️ SSL/TLS Security Audits

**16 Nmap NSE scripts** for auditing TLS endpoints:

**Covers:**

- Protocol version exposure (SSLv3/POODLE, deprecated TLS 1.0/1.1)
- Cipher suite quality (NULL/RC4/export/3DES/SWEET32)
- Certificate hygiene (expiry, hostname/SAN verification, signature algorithm and key strength, full fingerprint)
- Key exchange parameter strength (Logjam-class Diffie-Hellman)
- RFC 5746 secure renegotiation
- RFC 7507 fallback-SCSV behavior
- RFC 6520 heartbeat (Heartbleed precondition)
- TLS compression (CRIME)
- ALPN negotiation
- OCSP stapling availability and HSTS policy strength

Every script speaks TLS directly — building real ClientHello flights with targeted cipher/extension profiles, parsing ServerHello, certificate and alert responses from the wire — and reports evidence-based verdicts.

**Port:** 443/tcp + 8443/tcp (any `ssl`-matched port) | **Protocol:** TLS 1.0 – 1.3 / SSLv3 (ClientHello-level probing; no full record-layer crypto) | **Total lines of Lua:** 32,090

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [ssl-heartbleed-precondition](#1-ssl-heartbleed-precondition---heartbeat-over-read) | 🔴 CRITICAL | vuln, safe | 1995 |
| 2 | [ssl-poodle-sslv3](#2-ssl-poodle-sslv3---sslv3-poodle-exposure) | 🔴 CRITICAL | vuln, safe | 1986 |
| 3 | [ssl-cert-expiry](#3-ssl-cert-expiry---certificate-validity-window) | 🟠 HIGH | safe, discovery, vuln | 2000 |
| 4 | [ssl-cert-hostname-mismatch](#4-ssl-cert-hostname-mismatch---certificate-hostname-verification) | 🟠 HIGH | safe, discovery, vuln | 2028 |
| 5 | [ssl-cert-weak-signature](#5-ssl-cert-weak-signature---certificate-signature--key-strength) | 🟠 HIGH | safe, discovery, vuln | 2019 |
| 6 | [ssl-compression-check](#6-ssl-compression-check---tls-compression-crime) | 🟠 HIGH | safe, discovery, vuln | 1997 |
| 7 | [ssl-dh-params-weak](#7-ssl-dh-params-weak---logjam-class-diffie-hellman) | 🟠 HIGH | vuln, safe | 2001 |
| 8 | [ssl-secure-renegotiation](#8-ssl-secure-renegotiation---rfc-5746-renegotiation-security) | 🟠 HIGH | safe, discovery, vuln | 2035 |
| 9 | [ssl-sweet32-check](#9-ssl-sweet32-check---3des-sweet32-availability) | 🟠 HIGH | vuln, safe | 1969 |
| 10 | [ssl-weak-ciphers](#10-ssl-weak-ciphers---weak-cipher-suite-negotiability) | 🟠 HIGH | safe, discovery, vuln | 1999 |
| 11 | [ssl-fallback-scsv](#11-ssl-fallback-scsv---rfc-7507-fallback-protection) | 🟡 MEDIUM | defensive, safe | 1977 |
| 12 | [ssl-hsts-preload-status](#12-ssl-hsts-preload-status---hsts-policy-strength) | 🟡 MEDIUM | defensive, safe | 2037 |
| 13 | [ssl-ocsp-stapling](#13-ssl-ocsp-stapling---ocsp-stapling-availability) | 🟡 MEDIUM | safe, discovery | 1991 |
| 14 | [ssl-protocol-versions](#14-ssl-protocol-versions---tls-version-support-map) | 🟡 MEDIUM | safe, discovery, vuln | 2015 |
| 15 | [ssl-alpn-negotiation](#15-ssl-alpn-negotiation---alpn-negotiation) | 🟢 LOW | discovery, safe | 2020 |
| 16 | [ssl-cert-info](#16-ssl-cert-info---certificate-fingerprint) | 🟢 LOW | safe, discovery, default | 2021 |

---

## ⚙️ Common Script Arguments

All 16 scripts share the following `--script-args` (script-specific extras are listed per script):

| Argument | Default | Purpose |
|----------|---------|---------|
| `maxrequests` | per script | Hard request budget for the run |
| `timeout` | 10 | Per-exchange timeout (seconds) |

---

## 📜 Script Details

### 1. **ssl-heartbleed-precondition** - Heartbeat Over-Read
**Description:** Negotiates the RFC 6520 Heartbeat extension and, once enabled, sends a bounded heartbeat request (4-byte payload, 16-byte padding) then measures the response length. A response that carries data beyond the declared payload length is the exact CVE-2014-0160 (Heartbleed) out-of-bounds read; exact-length echoes, alerts, or silence are the safe outcomes.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- heartbeat extension negotiation in the ClientHello/ServerHello pair
- single bounded heartbeat request (payload 4 bytes + padding 16)
- trailer byte count beyond the declared payload length

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-heartbleed-precondition target.example.com
```

**Sample Output:**
```
| ssl-heartbleed-precondition:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - heartbeat over-read precondition probed.
|   Findings:
|     [CRITICAL] server's heartbeat response carries 64 byte(s) BEYOND
|            the declared payload length: the heartbeat implementation
|            reads out of bounds, which is the exact CVE-2014-0160
|            (Heartbleed) memory over-read; an attacker can drain
|            process memory 64 KiB at a time and typically recovers
|            private keys and session secrets within a handful of
|            requests (heartbeat-over-read)
|            [evidence: declared_payload_len=18 trailer_bytes=64 echoed_data=tl-heartbeat-probe]
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 10
|   probe_notes:
|     1: heartbeat request (4-byte payload, 16-byte padding):
|        heartbeat response: payload_len=18 trailer=64 bytes
```

---

### 2. **ssl-poodle-sslv3** - SSLv3 (POODLE) Exposure
**Description:** Attempts a full SSLv3 (0x0300) handshake with the classic CBC-era cipher suites. If the server completes it, the endpoint is exposed to POODLE (CVE-2014-3566) — a practical padding oracle against SSLv3 CBC modes; a `protocol_version` alert (70) refusal is the protected outcome.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- SSLv3 ClientHello (0x0300) with CBC cipher suites
- completion (vulnerable) vs fatal protocol_version alert 70 (protected)
- negotiated cipher of the completed SSLv3 handshake

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-poodle-sslv3 target.example.com
```

**Sample Output:**
```
| ssl-poodle-sslv3:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - SSLv3 (POODLE) exposure tested.
|   Findings:
|     [CRITICAL] server COMPLETES a full SSLv3 handshake (negotiated
|            SSLv3, cipher TLS_DHE_RSA_WITH_AES_256_CBC_SHA): the
|            endpoint is exposed to POODLE (CVE-2014-3566), where a
|            passive-then-active attacker recovers session plaintext
|            through the SSLv3 padding oracle (sslv3-accepted-poodle)
|            [evidence: version=SSLv3 cipher=TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 10
|   probe_notes:
|     1: SSLv3 (0x0300) handshake attempt: handshake COMPLETED at SSLv3
|        with cipher TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

---

### 3. **ssl-cert-expiry** - Certificate Validity Window
**Description:** Checks the validity window of the presented TLS certificate against the current time. Flags certificates that are already expired, not yet valid, or expiring within a configurable warning threshold (default 30 days, override with `ssl-cert-expiry.warndays`).

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- full X.509 parse of the leaf certificate (notBefore / notAfter)
- classification: valid / expiring_soon / expired / not_yet_valid
- exact remaining (or overrun) day count against the threshold

**How to Execute:**
```bash
# Basic scan (30-day warning window)
nmap -p 443 --script ssl-cert-expiry target.example.com

# Custom warning window
nmap -p 443 --script ssl-cert-expiry --script-args ssl-cert-expiry.warndays=14 target.example.com
```

**Sample Output:**
```
| ssl-cert-expiry:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - certificate validity window evaluated.
|   Findings:
|     [HIGH] certificate EXPIRES SOON: 21 day(s) remaining (threshold 30
|            day(s)); start renewal now because CA issuance plus deployment routinely
|            exceeds one week (cert-expiring-soon) [evidence: notAfter=2026-10-14
|            15:32:55 UTC days_left=21]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 7
|   classification: expiring_soon
|   days_to_expiry: 21
|   issuer: C=US / O=Mock CA Org / CN=Mock Root CA
|   probe_notes:
|     1: window: 2026-09-22 15:32:55 UTC -> 2026-10-14 15:32:55 UTC (now 2026-09-22 15:33:04 UTC, warndays=30, days_to_expiry=21)
|   subject: C=US / O=Target Corp / CN=target.example.com
|   threshold_reference:
|     1: warndays=30: the standard operational tripwire; leaves room for CA issuance, internal rollout and rollback.
|     2: warndays=7: aggressive, for automated-renewal environments that re-issue weekly.
|     3: warndays=90: conservative, for organizations with slow change management or long approval chains.
|   valid_from: 2026-09-22 15:32:55 UTC
|   valid_until: 2026-10-14 15:32:55 UTC
|   warning_threshold_days: 30
```

---

### 4. **ssl-cert-hostname-mismatch** - Certificate Hostname Verification
**Description:** Verifies the presented certificate against the name the connection is made for, using RFC 6125/2818 semantics: SubjectAlternativeName first (exact DNS names and single-label wildcards), CN only as legacy fallback when no SAN is present. The audit name defaults to the target's DNS name and can be overridden (e.g. to audit a virtual host or a name about to be cut over).

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- SAN entries (DNS names + wildcards) against the audit name
- CN fallback when the certificate carries no SAN
- which entry matched (SAN:exact, SAN:wildcard, CN) or that nothing matched

**How to Execute:**
```bash
# Basic scan (uses the target's DNS name)
nmap -p 443 --script ssl-cert-hostname-mismatch target.example.com

# Audit a specific virtual host name
nmap -p 443 --script ssl-cert-hostname-mismatch \
    --script-args ssl-cert-hostname-mismatch.name=shop.target.example.com target.example.com
```

**Sample Output:**
```
| ssl-cert-hostname-mismatch:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - certificate hostname verification performed.
|   Findings:
|     [HIGH] hostname target.example.com matches NOTHING on the
|            presented certificate (tried: CN:legacy.example.com):
|            every conforming TLS client aborts with a hostname
|            verification error; check for a wrong vhost, a stale
|            certificate after DNS cut-over, or a missing SAN for
|            this name (cert-hostname-mismatch)
|            [evidence: name=target.example.com sans=0 cn=legacy.example.com]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 7
|   audit_name: target.example.com
|   verification_result: mismatch
|   subject: C=GR / O=Legacy Org / CN=legacy.example.com
|   subject_cn: legacy.example.com
```

---

### 5. **ssl-cert-weak-signature** - Certificate Signature & Key Strength
**Description:** Evaluates the cryptographic strength of the presented certificate: signature algorithm (MD5/SHA-1 vs SHA-256+), public key size (RSA 1024 vs 2048+, EC floor) and self-signed status. Each weakness class is reported with its real-world breakage status and the concrete re-issuance action required.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- signature algorithm OID classified as broken / weak / strong
- public key type and bit size against the CA/B Forum floor
- self-signed leaf (subject == issuer)
- combination of weaknesses (e.g. SHA-1 + 1024-bit)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-cert-weak-signature target.example.com
```

**Sample Output:**
```
| ssl-cert-weak-signature:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - certificate signature and key strength evaluated.
|   Findings:
|     [HIGH] certificate is signed with MD5, a broken hash
|            (1.2.840.113549.1.1.4): SHA-1 collisions are practical (SHAttered 2017)
|            and MD5 is long dead, so a forged certificate for this identity is
|            achievable by an attacker who controls the CA pipeline; the certificate
|            chain cannot be trusted and the leaf must be re-issued with
|            sha256WithRSAEncryption or stronger (cert-weak-signature) [evidence:
|            signature=md5WithRSAEncryption oid=1.2.840.113549.1.1.4]
|     [HIGH] public key is only 1024-bit RSA, below the 2048-bit CA/B Forum
|            floor: 1024-bit RSA is within reach of well-resourced adversaries and
|            can be factored to forge the certificate or decrypt sessions where the
|            key is exposed (cert-weak-key) [evidence: key=RSA 1024-bit]
|     [LOW] certificate is self-signed (subject == issuer ==
|            CN=legacy.example.com / O=Legacy Org / C=GR): no public CA chain exists,
|            so standard clients cannot validate it without manual trust; on a
|            public-facing service this is the condition that enables transparent
|            interception (cert-self-signed) [evidence: subject=CN=legacy.example.com
|            / O=Legacy Org / C=GR issuer=C=GR / O=Legacy Org /
|            CN=legacy.example.com]
|   Severity counts: CRITICAL=0 HIGH=2 MEDIUM=0 LOW=1 INFO=0
|   Weighted score: 16
|   probe_notes:
|     1: signature=md5WithRSAEncryption (1.2.840.113549.1.1.4) class=weak key=RSA bits=1024 self_signed=true
|   public_key: RSA 1024-bit
|   self_signed: yes
|   signature_algorithm: md5WithRSAEncryption
|   signature_class: weak
|   signature_oid: 1.2.840.113549.1.1.4
|   subject: CN=legacy.example.com / O=Legacy Org / C=GR
|   weak_reference:
|     1: MD5 (1.2.840.113549.1.1.4): broken since 2004; no collision resistance at all.
|     2: SHA-1 (1.3.14.3.2.26): collision-broken since 2017; CA/B Forum forbids it after 2016-01-01.
|     3: RSA < 2048 bits: below the CA/B Forum minimum; 1024-bit keys are practically breakable.
|     4: EC < 224 bits: below the NIST SP 800-131A minimum.
|     5: Self-signed leaf: no public CA chain; clients must pin or trust the key manually.
```

---

### 6. **ssl-compression-check** - TLS Compression (CRIME)
**Description:** Tests whether the endpoint negotiates TLS-level compression when DEFLATE is offered (RFC 3749), then re-tests with NULL-only as a baseline. A selected DEFLATE compression means CRIME-style byte-at-a-time secret recovery is possible against secrets embedded in the compressed stream.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- compression list offered (NULL + DEFLATE) and the server's selection
- NULL-only baseline handshake to confirm the server is not forced
- negotiated protocol version context (compression is impossible in TLS 1.3)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-compression-check target.example.com
```

**Sample Output:**
```
| ssl-compression-check:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - TLS compression posture assessed.
|   Findings:
|     [HIGH] server selected DEFLATE compression when offered
|            (negotiated TLS 1.2): TLS-level compression enables
|            CRIME-style byte-at-a-time secret recovery; RFC 3749
|            has been deprecated for this exact reason and the
|            cipher suite policy should be re-issued with NULL-only
|            compression (tls-deflate-compression)
|            [evidence: offered=NULL,DEFLATE; selected=DEFLATE; version=TLS 1.2]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 7
|   deflate_selected: yes
|   probe_notes:
|     1: probe NULL+DEFLATE offered: handshake TLS 1.2, compression=DEFLATE
|     2: probe NULL only (baseline): handshake TLS 1.2, compression=NULL
```

---

### 7. **ssl-dh-params-weak** - Logjam-class Diffie-Hellman
**Description:** Offers DHE-only cipher suites so the server must publish its finite-field Diffie-Hellman parameters in ServerKeyExchange, then measures the prime length and fingerprints it against the known RFC 3526 / RFC 7919 groups. Primes below 2048 bits are the Logjam-class configuration where the shared secret can be broken or pre-computed at nation-state cost.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- DH prime bit length from the ServerKeyExchange parameters
- group fingerprint (RFC 3526 group 1/2/5, RFC 7919 ffdhe2048/3072/4096)
- strength classification: critically_weak / weak / acceptable

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-dh-params-weak target.example.com
```

**Sample Output:**
```
| ssl-dh-params-weak:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - Diffie-Hellman parameter strength measured.
|   Findings:
|     [HIGH] server negotiates a 1024-bit Diffie-Hellman prime,
|            identified as RFC 3526 group 14 (1024-bit MODP), below
|            the 2048-bit floor: this is the Logjam-class
|            configuration where the shared secret can be broken (or
|            the group pre-computed in a downgrade) at nation-state
|            cost (dh-weak-prime)
|            [evidence: bits=1024 group=RFC 3526 group 14 (1024-bit MODP)]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 7
|   probe_notes:
|     1: DHE-only offer (0x0033,0x0035): dh_prime_bits=1024 generator=?
|     2: prime fingerprint: RFC 3526 group 14 (1024-bit MODP)
```

---

### 8. **ssl-secure-renegotiation** - RFC 5746 Renegotiation Security
**Description:** After a first handshake, sends a second ClientHello without the RFC 5746 `renegotiation_info` extension (the CVE-2009-3555 splicing vector), then one with it. A bare-CH that is accepted marks the endpoint vulnerable to insecure-renegotiation splicing; a `no_renegotiation` (100) or `handshake_failure` (40) refusal is the compliant behavior.

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- first full handshake to establish the session
- second ClientHello WITHOUT renegotiation_info (vulnerability probe)
- second ClientHello WITH renegotiation_info (support check + echo verification)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-secure-renegotiation target.example.com
```

**Sample Output:**
```
| ssl-secure-renegotiation:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - TLS renegotiation security (RFC 5746) assessed.
|   Findings:
|     [HIGH] server accepted a second ClientHello WITHOUT the RFC 5746
|            renegotiation_info extension: the endpoint is exposed to
|            the TLS insecure-renegotiation splicing attack
|            (CVE-2009-3555), where an active network attacker can
|            merge their own session with a victim's (insecure-renegotiation-accepted)
|            [evidence: bare second ClientHello accepted, new ServerHello returned]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 8
|   probe_notes:
|     1: second ClientHello WITHOUT renegotiation_info: RENEGOTIATED
|        (new session at TLS 1.2, renegotiation_info echo=no)
|     2: second ClientHello WITH renegotiation_info: RENEGOTIATED
|        (new session at TLS 1.2, renegotiation_info echo=yes)
```

---

### 9. **ssl-sweet32-check** - 3DES (SWEET32) Availability
**Description:** Offers only the eight 3DES-EDE cipher suites (0x0008–0x000d, 0xc008, 0xc012, 0xc02b). If any is negotiated, the endpoint is exposed to SWEET32 (CVE-2016-2183): a birthday attack on 64-bit block ciphers that leaks 32 bits of plaintext per ~785 GiB session (or far less per session in the correlated multi-session variant). All 3DES suites are obsoleted by RFC 9155.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- 3DES-only cipher offer (8 suites)
- negotiated 3DES suite name (vulnerable) vs refusal alert (protected)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-sweet32-check target.example.com
```

**Sample Output:**
```
| ssl-sweet32-check:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - 3DES (SWEET32) cipher availability tested.
|   Findings:
|     [HIGH] server negotiated a 3DES-EDE cipher suite
|            (TLS_RSA_WITH_3DES_EDE_CBC_SHA): 64-bit block ciphers
|            expose the session to SWEET32 (CVE-2016-2183), where
|            ~785 GiB of traffic on one session (or a correlated
|            multi-session variant) leaks 32 bits of plaintext
|            (sweet32-3des-negotiable)
|            [evidence: cipher=TLS_RSA_WITH_3DES_EDE_CBC_SHA]
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 7
|   probe_notes:
|     1: 3DES-only cipher offer (8 suites): handshake COMPLETED with
|        cipher TLS_RSA_WITH_3DES_EDE_CBC_SHA
```

---

### 10. **ssl-weak-ciphers** - Weak Cipher Suite Negotiability
**Description:** Probes the endpoint's willingness to negotiate each class of weak cipher suite in isolated offers: NULL encryption, RC4, export-grade/single-DES, and MD5-MAC. Each class is tested with its own handshake so the result names the exact suite the server chose to negotiate. (3DES is covered by the dedicated `ssl-sweet32-check` to keep this probe focused.)

**Risk Level:** 🟠 HIGH | **Category:** safe, discovery, vuln

**What it checks:**
- NULL group (0x0001/0x0002) — HIGH when negotiated
- RC4 group (0x0005/0x0004/0x0016/0x0013) — HIGH
- export/DES group (0x0006/0x0007) — HIGH
- MD5-MAC (0x0003) — MEDIUM
- negotiated suite name per accepted group

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-weak-ciphers target.example.com
```

**Sample Output:**
```
| ssl-weak-ciphers:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - weak cipher suite negotiability mapped.
|   Findings:
|     [HIGH] server negotiated a NULL cipher suite
|            (TLS_RSA_WITH_NULL_MD5): the TLS connection authenticates
|            but encrypts NOTHING (weak-cipher-null)
|            [evidence: group=null cipher=TLS_RSA_WITH_NULL_MD5]
|     [HIGH] server negotiated an RC4 cipher suite
|            (TLS_KRB5_WITH_RC4_128_SHA): RC4 is retired by RFC 7465
|            (weak-cipher-rc4) [evidence: group=rc4 cipher=TLS_KRB5_WITH_RC4_128_SHA]
|     [HIGH] server negotiated an export-grade/single-DES cipher suite
|            (TLS_RSA_WITH_DES_CBC_SHA) (weak-cipher-export)
|            [evidence: group=export_des cipher=TLS_RSA_WITH_DES_CBC_SHA]
|     [MEDIUM] server negotiated an MD5-MAC cipher suite
|            (TLS_RSA_WITH_RC4_128_MD5): the message authentication
|            rests on a collision-broken hash (weak-cipher-md5)
|            [evidence: group=md5 cipher=TLS_RSA_WITH_RC4_128_MD5]
|   Severity counts: CRITICAL=0 HIGH=3 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 25
|   probe_notes:
|     1: null: ACCEPTED, server chose TLS_RSA_WITH_NULL_MD5
|     2: rc4: ACCEPTED, server chose TLS_KRB5_WITH_RC4_128_SHA
|     3: export_des: ACCEPTED, server chose TLS_RSA_WITH_DES_CBC_SHA
|     4: md5: ACCEPTED, server chose TLS_RSA_WITH_RC4_128_MD5
```

---

### 11. **ssl-fallback-scsv** - RFC 7507 Fallback Protection
**Description:** Sends a TLS 1.1 ClientHello that includes the TLS_FALLBACK_SCSV sentinel (0x5600) alongside a real cipher, as RFC 7507 requires of downgraded clients. A compliant server that supports a higher version must abort with the fatal `inappropriate_fallback` alert (86); a server that simply completes the downgraded handshake leaves the MITM version-stripping downgrade path open.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- SCSV (0x5600) + real cipher offered at TLS 1.1
- server reaction: fatal alert 86 (compliant) vs completed handshake (vulnerable)
- negotiated version and cipher of the completed (vulnerable) handshake

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-fallback-scsv target.example.com
```

**Sample Output:**
```
| ssl-fallback-scsv:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - TLS fallback SCSV reaction verified.
|   Findings:
|     [MEDIUM] server ignored TLS_FALLBACK_SCSV (0x5600) and completed
|            the handshake at TLS 1.1: the RFC 7507 downgrade
|            protection is not in effect, so a man-in-the-middle that
|            strips newer versions from the ClientHello will succeed
|            in downgrading clients (scsv-ignored)
|            [evidence: completed at TLS 1.1 cipher=TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 4
|   probe_notes:
|     1: TLS_FALLBACK_SCSV offer at TLS 1.1: handshake completed at
|        TLS 1.1 with cipher TLS_DHE_RSA_WITH_AES_256_CBC_SHA (SCSV ignored)
```

---

### 12. **ssl-hsts-preload-status** - HSTS Policy Strength
**Description:** Completes a TLS handshake, issues a plain `GET` over the secure session and audits the Strict-Transport-Security header (RFC 6797): presence, `max-age` against the 183-day preload floor and the 1-year de-facto standard, `includeSubDomains` and `preload` directives.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- HTTP response status over TLS (the GET must actually succeed)
- STS header presence (absent → MEDIUM: SSL-stripping possible)
- `max-age` value (absent or < 15768000 → MEDIUM)
- `includeSubDomains` / `preload` directives (preload requires both floor + includeSubDomains)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-hsts-preload-status target.example.com

# Audit a specific path
nmap -p 443 --script ssl-hsts-preload-status --script-args ssl-hsts-preload-status.path=/login target.example.com
```

**Sample Output:**
```
| ssl-hsts-preload-status:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - HSTS header presence and strength assessed.
|   Findings:
|     no weaknesses detected by this audit
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=2
|   Weighted score: 2
|   http_status: 200
|   sts_header: max-age=31536000; includeSubDomains; preload
|   probe_notes:
|     1: GET / over TLS: HTTP 200
|     2: STS header: max-age=31536000; includeSubDomains; preload
|     3: parsed directives: max-age=31536000 includeSubDomains=yes preload=yes
|     4: includeSubDomains present: all subdomains inherit the policy
```

---

### 13. **ssl-ocsp-stapling** - OCSP Stapling Availability
**Description:** Sends a ClientHello with the `status_request` extension (RFC 6066, type 5) and inspects the server flight: a `CertificateStatus` handshake message carrying a DER OCSP response means stapling is enabled; the extension echoed without a `CertificateStatus` message is the misconfigured state; no echo means stapling is not offered at all.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- status_request extension echo in the ServerHello
- CertificateStatus message (handshake type 5) presence in the flight
- OCSP response type/length from the CertificateStatus payload

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-ocsp-stapling target.example.com
```

**Sample Output:**
```
| ssl-ocsp-stapling:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - OCSP stapling availability checked.
|   Findings:
|     no weaknesses detected by this audit
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 1
|   probe_notes:
|     1: status_request ClientHello: handshake TLS 1.2,
|        status_request_echo=yes, certificate_status=type 1 ocsp_len 216
```

---

### 14. **ssl-protocol-versions** - TLS Version Support Map
**Description:** Maps exactly which protocol versions the endpoint accepts: one handshake per version (SSLv3, TLS 1.0, TLS 1.1, TLS 1.2) plus a TLS 1.3 probe that uses the `supported_versions` extension (43) and offers TLS 1.3-only cipher suites. Distinguishes explicit refusals (protocol_version alert 70) from completions and reports the negotiated version for each accepted probe.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- SSLv3 acceptance (MEDIUM — POODLE surface)
- TLS 1.0 / 1.1 acceptance (LOW — RFC 8996 deprecated, CA/B-prohibited)
- TLS 1.2 / 1.3 acceptance (INFO — current baseline)
- per-version negotiated result and refusal alert details

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-protocol-versions target.example.com
```

**Sample Output:**
```
| ssl-protocol-versions:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - TLS protocol version support mapped.
|   Findings:
|     [MEDIUM] server accepts SSLv3 (0x0300): an obsoleted protocol with
|            a practical padding-oracle (POODLE, CVE-2014-3566) is still
|            on the table (protocol-sslv3-accepted)
|            [evidence: negotiated=SSL 3.0]
|     [LOW] server accepts TLS 1.0 (0x0301), a protocol deprecated by
|            RFC 8996 and prohibited for CA-issued certificates
|            (protocol-tls10-accepted) [evidence: negotiated=TLS 1.0]
|     [LOW] server accepts TLS 1.1 (0x0302), a protocol deprecated by
|            RFC 8996 and prohibited for CA-issued certificates
|            (protocol-tls11-accepted) [evidence: negotiated=TLS 1.1]
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=2 INFO=2
|   Weighted score: 10
|   accepted_versions:
|     1: SSLv3
|     2: TLS 1.0
|     3: TLS 1.1
|     4: TLS 1.2
|     5: TLS 1.3
|   probe_notes:
|     1: SSLv3: ACCEPTED (negotiated SSL 3.0)
|     2: TLS 1.0: ACCEPTED (negotiated TLS 1.0)
|     3: TLS 1.1: ACCEPTED (negotiated TLS 1.1)
|     4: TLS 1.2: ACCEPTED (negotiated TLS 1.2)
|     5: TLS 1.3: ACCEPTED (negotiated TLS 1.2)
```

---

### 15. **ssl-alpn-negotiation** - ALPN Negotiation
**Description:** Profiles the application-layer protocols the TLS endpoint negotiates via ALPN (RFC 7301): offers `h2` + `http/1.1`, offers only `http/1.1`, and offers no ALPN extension at all, then compares what the server selects in each flight to establish the effective protocol profile of the endpoint.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- ALPN extension presence and selected protocol (h2 vs http/1.1)
- whether the server selects h2 when offered alongside http/1.1
- behavior when no ALPN extension is offered (legacy NPN-era fallback)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-alpn-negotiation target.example.com
```

**Sample Output:**
```
| ssl-alpn-negotiation:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - ALPN protocol negotiation profiled.
|   Findings:
|     no weaknesses detected by this audit
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 1
|   negotiated_protocol: h2
|   probe_notes:
|     1: probe h2+http/1.1: handshake TLS 1.2, alpn=h2
|     2: probe http/1.1 only: handshake TLS 1.2, alpn=http/1.1
|     3: probe without ALPN extension: handshake TLS 1.2, alpn=(none selected)
```

---

### 16. **ssl-cert-info** - Certificate Fingerprint
**Description:** Captures a full fingerprint of the leaf certificate the server presents: subject, issuer, serial, validity window, signature algorithm (with OID), public key type/size, SAN entries and self-signed status — the baseline record for change detection and certificate inventory.

**Risk Level:** 🟢 LOW | **Category:** safe, discovery, default

**What it checks:**
- subject / issuer / serial / x509 version
- notBefore / notAfter, DER length
- signature algorithm + OID, public key (RSA bits)
- SAN entries, self-signed (subject == issuer) detection

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-cert-info target.example.com
```

**Sample Output:**
```
| ssl-cert-info:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - certificate fingerprint captured.
|   Findings:
|     no weaknesses detected by this audit
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 1
|   der_length_bytes: 927
|   extensions_present:
|     1: subjectAltName
|     2: basicConstraints
|     3: extendedKeyUsage
|     4: keyUsage
|     5: 2.5.29.35
|   field_reference:
|     1: subject: who the certificate claims to be; the CN is the legacy name, the SAN is what clients actually check.
|     2: issuer: the CA (or the certificate itself, when self-signed) that signed it.
|     3: serial: must be unique per CA; a short or predictable serial is a policy violation (CA/B Forum 7.1).
|     4: signature: sha256WithRSAEncryption and stronger are expected in 2026; sha1/md5 are broken.
|     5: public key: RSA >= 2048 bits or EC >= 224 bits is the current floor.
|   issuer: C=US / O=Mock CA Org / CN=Mock Root CA
|   probe_notes: {}
|   public_key: RSA 2048-bit
|   self_signed: no
|   serial_number: -2996897801500126975
|   signature_algorithm: sha256WithRSAEncryption
|   signature_oid: 1.2.840.113549.1.1.11
|   subject: C=US / O=Target Corp / CN=target.example.com
|   subject_alt_names:
|     1: DNS target.example.com
|     2: DNS *.target.example.com
|   valid_from: 2026-09-22 15:32:55 UTC
|   valid_until: 2026-10-14 15:32:55 UTC
|   x509_version: 2
```

##  Typical Scan

```bash
# Full SSL/TLS audit of an endpoint
nmap -p 443 --script ssl-* target.example.com

# Include the alternate TLS port
nmap -p 443,8443 --script ssl-* target.example.com
```
