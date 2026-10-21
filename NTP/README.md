# ⏱️ NTP Security Audits

**16 Nmap NSE scripts** for auditing NTP services directly on the wire:

**Covers:**

- Real NTPv4 mode 3/4 client-server exchanges with the full four-timestamp offset computation
- Mode 6 private-control packets (Read Status / Read Variables with status-word and key=value parsing)
- Mode 7 private-mode requests from the ntp_request.h table (MON_GETLIST/GET_RESTRICT/TRAPS/AUTH_INFO with err/nitems/item-size header decoding)
- Kiss-of-death and reference-ID classification
- Peer status word bit decoding (configured/auth/reach/broadcast/selection)
- Bounded monlist amplification measurement (CVE-2013-5211, capped at 30 entries)
- Symmetric-key MAC enforcement probes with invalid digests
- Association-table walks for Autokey (RFC 5906/7384) and broadcast-mode detection
- Clock-offset measurement with drift classification
- Leap-second advisory correlation
- A spoofability matrix
- An NTS Key Exchange (RFC 8915) TLS probe on 4460

**Every probe is a bounded, read-only exchange:**

- No configuration writes
- No flood patterns
- Entry caps on every list.

**Ports:** 123/udp (NTP) + 4460/tcp (NTS-KE) | **Protocol:** NTPv4 (RFC 5905), mode 6 control, mode 7 private (ntp_request.h), NTS-KE RFC 8915 | **Total lines of Lua:** 26,388

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [ntp-monlist-amplification](#1-ntp-monlist-amplification---monlist-amplification-cve-2013-5211) | 🔴 CRITICAL | vuln, safe | 1539 |
| 2 | [ntp-peer-association-spoof](#2-ntp-peer-association-spoof---peer-association-spoofability-matrix) | 🔴 CRITICAL | vuln, safe | 1570 |
| 3 | [ntp-unauth-config-dump](#3-ntp-unauth-config-dump---unauthenticated-peer-config-dump) | 🔴 CRITICAL | vuln, safe | 1587 |
| 4 | [ntp-autokey-support-audit](#4-ntp-autokey-support-audit---autokey-rfc-5906-support-audit) | 🟠 HIGH | vuln, safe | 1578 |
| 5 | [ntp-trap-logging-leak](#5-ntp-trap-logging-leak---trap-registry--logging-leak) | 🟠 HIGH | discovery, safe | 1546 |
| 6 | [ntp-unauth-reslist-query](#6-ntp-unauth-reslist-query---unauthenticated-restriction-list-query) | 🟠 HIGH | discovery, safe | 1553 |
| 7 | [ntp-broadcast-mode-detect](#7-ntp-broadcast-mode-detect---broadcast-mode-detection) | 🟡 MEDIUM | discovery, safe | 1564 |
| 8 | [ntp-control-query-rate-limit](#8-ntp-control-query-rate-limit---control-query-rate-limit-check) | 🟡 MEDIUM | defensive, safe | 1557 |
| 9 | [ntp-leap-second-vulnerability](#9-ntp-leap-second-vulnerability---leap-second-readiness-audit) | 🟡 MEDIUM | vuln, safe | 1565 |
| 10 | [ntp-mac-authentication-test](#10-ntp-mac-authentication-test---symmetric-key-mac-enforcement-test) | 🟡 MEDIUM | defensive, safe | 1551 |
| 11 | [ntp-mode6-readlist-leak](#11-ntp-mode6-readlist-leak---mode-6-association-list-leak) | 🟡 MEDIUM | discovery, safe | 1593 |
| 12 | [ntp-mode6-readvar-leak](#12-ntp-mode6-readvar-leak---mode-6-readvar-system-leak) | 🟡 MEDIUM | discovery, safe | 1539 |
| 13 | [ntp-stratum-zero-anomaly](#13-ntp-stratum-zero-anomaly---stratum--kiss-of-death-anomalies) | 🟡 MEDIUM | discovery, safe | 1565 |
| 14 | [ntp-nts-support-check](#14-ntp-nts-support-check---nts-key-exchange-support-rfc-8915) | 🟢 LOW | discovery, safe | 2976 |
| 15 | [ntp-time-offset-skew](#15-ntp-time-offset-skew---time-offset--clock-skew-measurement) | 🟢 LOW | discovery, safe | 1540 |
| 16 | [ntp-version-fingerprint](#16-ntp-version-fingerprint---version--daemon-fingerprint) | 🟢 LOW | discovery, safe | 1565 |

---

### 1. **ntp-monlist-amplification** - Monlist Amplification (CVE-2013-5211)
**Description:** Tests the CVE-2013-5211 monlist DRDoS vector: sends the mode 7 private

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends the modern monlist variant and, if refused, the legacy one.
- Caps collection at 30 entries and reports measured amplification.
- Lists sampled source IPs/ports from the captured entries.
- Why it matters: A monlist-enabled server answers small queries with up to hundreds of 72-byte traffic samples, making it a reflection/amplification weapon. The captured source list also leaks every client that recently queried the server.
- Safety: at most two bounded queries; collection stops early at 30 entries so the audit never pulls full-sized replies.

**How to Execute:**
```bash
nmap -p 123 --script ntp-monlist-amplification -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-monlist-amplification --script-args 'ntp-monlist-amplification.timeout=8,ntp-monlist-amplification.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-monlist-amplification:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - monlist enabled with 4.67x measured amplification
```

---

### 2. **ntp-peer-association-spoof** - Peer Association Spoofability Matrix
**Description:** Assesses how spoofable the server's time distribution is: accepts an

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Performs a client exchange and records MAC presence and origin echo.
- Reads the association table for broadcast/unauthenticated peers.
- Probes the control interface and combines all signals into a spoofability matrix.
- Why it matters: Unauthenticated mode 4 answers let any off-path spoofer race the real server (Kiss-o'-death and interleaving tricks widen the window). Broadcast associations multiply one spoofed packet into a whole segment; an open control plane adds remote reconfiguration on top.
- Safety: one client packet plus read-only control queries; no spoofed packets are ever transmitted.

**How to Execute:**
```bash
nmap -p 123 --script ntp-peer-association-spoof -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-peer-association-spoof --script-args 'ntp-peer-association-spoof.timeout=8,ntp-peer-association-spoof.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-peer-association-spoof:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - high spoofability: unauthenticated answers + broadcast associations + open control interface
```

---

### 3. **ntp-unauth-config-dump** - Unauthenticated Peer Config Dump
**Description:** Chains two unauthenticated mode 6 operations - Read Status (assoc list)

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends mode 6 readstat and lists the associations.
- For up to 4 associations issues readvar and captures the variables.
- Reports the dumped peer matrix and grades the exposure.
- Why it matters: The peer dump is effectively a network map: internal upstream IPs, broadcast services and their authentication state. This is the interface abused for remote configuration change; its unauthenticated readability almost always correlates with a writable control configuration.
- Safety: read-only queries only (one readstat + up to four readvar); nothing is written to the daemon.

**How to Execute:**
```bash
nmap -p 123 --script ntp-unauth-config-dump -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-unauth-config-dump --script-args 'ntp-unauth-config-dump.timeout=8,ntp-unauth-config-dump.maxrequests=32,ntp-unauth-config-dump.maxassocs=4' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-unauth-config-dump:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - full peer configuration readable without authentication (3 association(s): 192.0.2.50, 192.0.2.51, 10.0.0.9)
```

---

### 4. **ntp-autokey-support-audit** - Autokey (RFC 5906) Support Audit
**Description:** Detects Autokey (RFC 5906) public-key authentication on any association

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends mode 6 readstat for the association list.
- Reads variables per association (bounded) and searches the flags for the autokey marker.
- Reports every Autokey association and grades the exposure.
- Why it matters: RFC 7384 formally declares Autokey security broken: its identity scheme is replayable and its certificates are self-signed without a revocation model. Deployments still showing Autokey associations believe they have authenticated time while an on-path attacker can takeover the association.
- Safety: one readstat plus bounded readvar queries; no keys or certificates are exchanged.

**How to Execute:**
```bash
nmap -p 123 --script ntp-autokey-support-audit -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-autokey-support-audit --script-args 'ntp-autokey-support-audit.timeout=8,ntp-autokey-support-audit.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-autokey-support-audit:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - Autokey associations active (1: assoc 3)
```

---

### 5. **ntp-trap-logging-leak** - Trap Registry / Logging Leak
**Description:** Reads the mode 7 trap list (REQ_TRAPS, impl 3, code 29) without

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Sends mode 7 REQ_TRAPS with bounded receive.
- Decodes each registered trap (local address, receiver, port, flags).
- Grades the logging-diversion exposure.
- Why it matters: Traps push operational logs (association events, clock anomalies) to arbitrary registered addresses; unauthenticated trap management lets an attacker register itself and silently harvest telemetry, or flood the daemon with trap state (CVE-2016-9311 family). A configured trap also reveals the address of the monitoring host.
- Safety: one read-only query; the audit never registers or removes traps.

**How to Execute:**
```bash
nmap -p 123 --script ntp-trap-logging-leak -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-trap-logging-leak --script-args 'ntp-trap-logging-leak.timeout=8,ntp-trap-logging-leak.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-trap-logging-leak:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - trap service readable without authentication (1 registered trap)
```

---

### 6. **ntp-unauth-reslist-query** - Unauthenticated Restriction List Query
**Description:** Queries the mode 7 private restrictions list (REQ_GET_RESTRICT, impl 3,

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Sends mode 7 REQ_GET_RESTRICT with bounded receive.
- Decodes each restriction entry (address, mask, flags, hit count).
- Grades exposure of the management plane.
- Why it matters: The restriction list reveals the server's trust topology: which subnets may query/modify and which are limited - a blueprint for bypass planning. Unauthenticated mode 7 readability indicates the legacy management plane is still active (monlist/CVE-2013-5211 family surface).
- Safety: one read-only mode 7 query; no restriction entries are added or removed.

**How to Execute:**
```bash
nmap -p 123 --script ntp-unauth-reslist-query -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-unauth-reslist-query --script-args 'ntp-unauth-reslist-query.timeout=8,ntp-unauth-reslist-query.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-unauth-reslist-query:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - restriction list readable without authentication (2 entries)
```

---

### 7. **ntp-broadcast-mode-detect** - Broadcast Mode Detection
**Description:** Detects broadcast/multicast NTP associations through the mode 6

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends mode 6 readstat and decodes every association status word.
- Isolates associations carrying the broadcast status bit.
- Reports the broadcast service with its authentication posture.
- Why it matters: Broadcast NTP pushes time to every listener on the segment; a single spoofed "server" packet steers the clocks of the whole subnet. Broadcast associations without cryptographic authentication (autokey/symmetric keys) are the classic time-poisoning entry point.
- Safety: one read-only control query; no packets are ever sent to broadcast addresses.

**How to Execute:**
```bash
nmap -p 123 --script ntp-broadcast-mode-detect -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-broadcast-mode-detect --script-args 'ntp-broadcast-mode-detect.timeout=8,ntp-broadcast-mode-detect.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-broadcast-mode-detect:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - broadcast association(s) present (1, unauthenticated: 0)
```

---

### 8. **ntp-control-query-rate-limit** - Control Query Rate-Limit Check
**Description:** Measures whether the mode 6 control interface applies any rate limiting:

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Sends up to guesslimit readvar queries in sequence.
- Classifies each outcome: answered, refused (error flag), dropped.
- Estimates the effective rate-limit threshold from the pattern.
- Why it matters: Unlimited control queries make every other mode 6/7 finding trivially exploitable at scale and enable control-packet reflection. Documented throttling is a compensating control when key enforcement is missing.
- Safety: six bounded queries by default (hard cap 16) with a few bytes of payload; no flood, no amplification vectors used.

**How to Execute:**
```bash
nmap -p 123 --script ntp-control-query-rate-limit -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-control-query-rate-limit --script-args 'ntp-control-query-rate-limit.timeout=8,ntp-control-query-rate-limit.maxrequests=64,ntp-control-query-rate-limit.querylimit=6' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-control-query-rate-limit:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - no rate limiting on mode 6 control queries (6 answered in a row)
```

---

### 9. **ntp-leap-second-vulnerability** - Leap-Second Readiness Audit
**Description:** Audits leap-second readiness: decodes the leap indicator from a live

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, safe

**What it checks:**
- Sends one client exchange and decodes the leap indicator.
- Reads the daemon version through the control interface when open.
- Matches the build against leap-advisory families and the LI state against alarm conditions.
- Why it matters: The 2015/2016 leap second events crashed or deranged unpatched ntpd builds and the kernels behind them; 4.2.8p9+ handles insertion and smearing correctly. A server with the leap alarm bit stuck (LI=3) has been unsynchronized for hours yet still answers clients - invalid time in distribution.
- Safety: one client packet plus one read-only control query.

**How to Execute:**
```bash
nmap -p 123 --script ntp-leap-second-vulnerability -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-leap-second-vulnerability --script-args 'ntp-leap-second-vulnerability.timeout=8,ntp-leap-second-vulnerability.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-leap-second-vulnerability:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - leap-indicator healthy but the build family (ntpd 4.2.6) predates the leap-smear fixes
```

---

### 10. **ntp-mac-authentication-test** - Symmetric-Key MAC Enforcement Test
**Description:** Probes whether the NTP management planes verify symmetric-key MACs: sends

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Sends mode 7 AUTH_INFO with a keyed (invalid) MAC.
- Sends a mode 6 readvar with the same invalid MAC.
- Compares responses: served data = no MAC enforcement; error/refusal = enforcement present.
- Why it matters: If management queries are answered despite an invalid MAC, the requestkey/controlkey enforcement is absent - every mode 6/7 operation (including configuration writes) relies purely on network ACLs. Answering AUTH_INFO also leaks authentication counters.
- Safety: two queries carrying invalid authentication only; the audit never uses real keys and never performs writes.

**How to Execute:**
```bash
nmap -p 123 --script ntp-mac-authentication-test -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-mac-authentication-test --script-args 'ntp-mac-authentication-test.timeout=8,ntp-mac-authentication-test.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-mac-authentication-test:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - management queries answered with an invalid MAC (no key enforcement)
```

---

### 11. **ntp-mode6-readlist-leak** - Mode 6 Association List Leak
**Description:** Enumerates the NTP association table with an unauthenticated mode 6

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends mode 6 readstat (assoc 0).
- Parses "associd=status" rows and decodes the peer status bits.
- Flags unauthenticated and broadcast associations.
- Why it matters: The association list maps the clock topology: upstreams, peers and broadcast services, each with its authentication posture. Broadcast/weak-auth associations are the entry point for time-spoofing attacks against the whole broadcast domain.
- Safety: one read-only control query.

**How to Execute:**
```bash
nmap -p 123 --script ntp-mode6-readlist-leak -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-mode6-readlist-leak --script-args 'ntp-mode6-readlist-leak.timeout=8,ntp-mode6-readlist-leak.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-mode6-readlist-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - association table disclosed and includes broadcast association(s)
```

---

### 12. **ntp-mode6-readvar-leak** - Mode 6 Readvar System Leak
**Description:** Reads the mode 6 control interface system variables (assoc 0 readvar)

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends a mode 6 readvar for the standard variable list.
- Parses the returned key=value stream and decodes the status word.
- Grades the disclosure and maps it to restriction guidance.
- Why it matters: version/processor/system give attackers an exact software fingerprint for CVE targeting with zero credentials. stratum/refid/leap leak the clock topology of the estate.
- Safety: one read-only control query; nothing is written.

**How to Execute:**
```bash
nmap -p 123 --script ntp-mode6-readvar-leak -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-mode6-readvar-leak --script-args 'ntp-mode6-readvar-leak.timeout=8,ntp-mode6-readvar-leak.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-mode6-readvar-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - mode 6 readvar discloses system variables without authentication (ntpd 4.2.6p5@1.2349-o Fri Jul 17 06:17:34 UTC 2015 (1))
```

---

### 13. **ntp-stratum-zero-anomaly** - Stratum / Kiss-of-Death Anomalies
**Description:** Performs two client exchanges and audits the stratum/reference-ID/leap

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends two mode 3 client exchanges and records stratum, reference ID class and leap indicator for both.
- Classifies kiss codes against the standard table.
- Flags unsynchronized or alarm-state servers.
- Why it matters: Stratum 0 responses are kiss-of-death packets: the code tells you how the server policy treats this client (rate limiting, denial). A stratum 16 or leap-alarm server that still answers clients is distributing invalid time - an availability and integrity issue.
- Safety: two client packets only; the audit never floods to trigger rate limiting on purpose.

**How to Execute:**
```bash
nmap -p 123 --script ntp-stratum-zero-anomaly -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-stratum-zero-anomaly --script-args 'ntp-stratum-zero-anomaly.timeout=8,ntp-stratum-zero-anomaly.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-stratum-zero-anomaly:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - server answered normally then issued kiss-of-death (exchange 2: kiss-of-death RATE)
```

---

### 14. **ntp-nts-support-check** - NTS Key Exchange Support (RFC 8915)
**Description:** Checks Network Time Security (RFC 8915) support by attempting an NTS Key

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Opens a TCP connection to port 4460 and sends a TLS ClientHello with SNI and the ntske/1 ALPN.
- Parses the server flight for a ServerHello and the negotiated ALPN.
- Reports NTS-KE availability and the offered protocol version.
- Why it matters: NTS is the only IETF-standardized way to authenticate NTP time; its absence means clients must trust the network path. Detecting a live NTS-KE endpoint documents the modern authenticated time option available to clients.
- Safety: one handshake attempt that is closed immediately; no NTS keys are negotiated beyond the hello exchange.

**How to Execute:**
```bash
nmap -p 4460 --script ntp-nts-support-check ntp.corp.example.com

# Tuned request budget
nmap -p 4460 --script ntp-nts-support-check --script-args 'ntp-nts-support-check.timeout=8,ntp-nts-support-check.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-nts-support-check:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - no NTS Key Exchange on TCP 4460 (no_server_hello)
```

---

### 15. **ntp-time-offset-skew** - Time Offset / Clock Skew Measurement
**Description:** Measures the clock offset between the server and the auditor using the

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends one mode 3 exchange with a fresh transmit timestamp.
- Validates the origin echo and computes offset = ((t2-t1)+(t3-t4))/2.
- Classifies the offset against drift thresholds.
- Why it matters: A server handing out time seconds away from UTC breaks Kerberos, TLS OCSP windows, logs correlation and scheduled jobs downstream. Large root delay/dispersion values mark low-quality sync chains even when the offset looks acceptable.
- Safety: one client packet; no configuration is touched.

**How to Execute:**
```bash
nmap -p 123 --script ntp-time-offset-skew -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-time-offset-skew --script-args 'ntp-time-offset-skew.timeout=8,ntp-time-offset-skew.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-time-offset-skew:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - server clock offset +2.688 s exceeds the 1 s drift threshold
```

---

### 16. **ntp-version-fingerprint** - Version & Daemon Fingerprint
**Description:** Fingerprints the NTP service: mode 3 client exchange (protocol version,

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Performs one mode 3 client exchange and records the version echo, stratum, precision, root delay/dispersion and reference ID class.
- Issues one mode 6 readvar (assoc 0) for the version/processor/system variables when the control interface answers.
- Matches the discovered version against the advisory table.
- Why it matters: The version string (ntpd 4.2.6p5 etc.) drives every CVE decision an auditor makes; older 4.2.6/early 4.2.8 series carry critical advisories. The protocol version echo and stratum reveal stack generation and sync health without authentication.
- Safety: one client packet plus one read-only control query; no configuration or state is touched.

**How to Execute:**
```bash
nmap -p 123 --script ntp-version-fingerprint -sU ntp.corp.example.com

# Tuned request budget
nmap -p 123 --script ntp-version-fingerprint --script-args 'ntp-version-fingerprint.timeout=8,ntp-version-fingerprint.maxrequests=32' ntp.corp.example.com
```

**Sample Output:**
```
| ntp-version-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - daemon version disclosed with known advisories (ntpd 4.2.6)
```

