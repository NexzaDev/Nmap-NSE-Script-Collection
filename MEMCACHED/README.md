# ⚡ Memcached Security Audits

**16 Nmap NSE scripts** for auditing Memcached servers directly on the wire:

**Covers:**

- A full ASCII-protocol client (version, stats, stats settings/items/sizes, stats cachedump, set/get/delete/touch with an audit-unique sentinel key, flush_all with a far-future expiry sentinel, verbosity, watch) plus a complete binary-protocol codec (24-byte header request/response framing, opcodes VERSION/GET/SET/DELETE/TOUCH/NOOP/STAT/SASL list and SASL PLAIN auth, status-name decoding)
- A bounded UDP datagram transport with request-id framing
- Reassembly and amplification-ratio grading
- A stats knowledge layer (counter snapshot/diff, per-slab item/age analysis, settings interpretation, slab-class size math with the default 1.25 growth factor, LRU-crawler metadump parsing)
- Expiry semantics (relative vs absolute epoch at the 30-day boundary)
- Flag-bit decoding and version-to-advisory mapping

**The suite covers the classic Memcached attack surface:**

- Anonymous service exposure
- Sentinel-key read/write/delete proof
- Slab and cached-key metadata disclosure
- Memory topology dumps
- Runtime settings leaks
- Destructive-command reachability (flush_all, meta deletes, lru_crawler metadump)
- SASL posture with a single clearly-invalid credential probe
- Touch/TTL manipulation
- Verbosity leaks
- Connection-budget posture
- The UDP amplification measurement that powered the 2018 memcrashed reflection attacks
- The ASCII-over-UDP disable check

**Every probe is bounded and non-destructive:**

- Reads only
- The only writes are the audit's own uniquely-named sentinel key (always deleted afterwards)
- Flush_all is tested with a sentinel expiry that clears nothing
- Exactly one invalid-credential SASL attempt is made - no brute force
- No flooding
- No user-key access.

**Port:** 11211/tcp + 11211/udp (memcached) | **Protocols:** Memcached ASCII protocol, Memcached binary protocol, Memcached UDP transport | **Total lines of Lua:** 27,538

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [memcached-key-data-retrieval](#1-memcached-key-data-retrieval---anonymous-key-data-retrieval--manipulation) | 🔴 CRITICAL | vuln, safe | 1741 |
| 2 | [memcached-slabs-item-dump](#2-memcached-slabs-item-dump---slab--cached-item-metadata-dump) | 🔴 CRITICAL | vuln, safe | 1746 |
| 3 | [memcached-udp-amplification-ddos](#3-memcached-udp-amplification-ddos---udp-amplification-ddos-reflector-measurement) | 🔴 CRITICAL | vuln, safe | 1748 |
| 4 | [memcached-unauthenticated-access](#4-memcached-unauthenticated-access---unauthenticated-service-exposure) | 🔴 CRITICAL | vuln, safe | 1719 |
| 5 | [memcached-flush-all-risk](#5-memcached-flush-all-risk---flush_all-destructive-command-exposure) | 🟠 HIGH | vuln, safe | 1723 |
| 6 | [memcached-sasl-auth-enforced](#6-memcached-sasl-auth-enforced---sasl-authentication-enforcement) | 🟠 HIGH | defensive, safe | 1724 |
| 7 | [memcached-watch-stream-exposure](#7-memcached-watch-stream-exposure---watch--stats-stream-exposure) | 🟠 HIGH | vuln, safe | 1724 |
| 8 | [memcached-ascii-udp-disable-check](#8-memcached-ascii-udp-disable-check---udp-transport-disable-check-ascii-over-udp) | 🟡 MEDIUM | defensive, safe | 1706 |
| 9 | [memcached-connection-limit-dos](#9-memcached-connection-limit-dos---connection-budget--saturation-posture) | 🟡 MEDIUM | defensive, safe | 1720 |
| 10 | [memcached-settings-leak](#10-memcached-settings-leak---runtime-settings-disclosure) | 🟡 MEDIUM | discovery, safe | 1709 |
| 11 | [memcached-sizes-memory-dump](#11-memcached-sizes-memory-dump---stats-sizes-memory-topology-dump) | 🟡 MEDIUM | discovery, safe | 1719 |
| 12 | [memcached-touch-command-audit](#12-memcached-touch-command-audit---touch--ttl-manipulation-audit) | 🟡 MEDIUM | defensive, safe | 1717 |
| 13 | [memcached-verbosity-command-leak](#13-memcached-verbosity-command-leak---verbosity-command-exposure) | 🟡 MEDIUM | discovery, safe | 1711 |
| 14 | [memcached-binary-protocol-probe](#14-memcached-binary-protocol-probe---binary-protocol-capability-probe) | 🟢 LOW | discovery, safe | 1711 |
| 15 | [memcached-slab-automove-audit](#15-memcached-slab-automove-audit---slab-reassign--automove-posture) | 🟢 LOW | defensive, safe | 1710 |
| 16 | [memcached-version-fingerprint](#16-memcached-version-fingerprint---version-fingerprint--advisory-mapping) | 🟢 LOW | discovery, safe | 1710 |

---

### 1. **memcached-key-data-retrieval** - Anonymous Key Data Retrieval & Manipulation
**Description:** Proves the anonymous set/get/delete primitive end to end using a

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- set <sentinel-key> with a unique marker value.
- get <sentinel-key> and verifies the round trip.
- delete <sentinel-key> to clean up.
- Grades the manipulation capability.
- Why it matters: An anonymous set+get round trip is the full cache-manipulation primitive - the same one used to poison sessions and smuggle web objects. The sentinel name guarantees no user data is touched.
- Safety: only the sentinel key is written and deleted; no user keys are read.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-key-data-retrieval cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-key-data-retrieval --script-args 'memcached-key-data-retrieval.timeout=8,memcached-key-data-retrieval.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-key-data-retrieval:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - anonymous cache manipulation proven (set/get/delete round trip on sentinel key)
```

---

### 2. **memcached-slabs-item-dump** - Slab & Cached-Item Metadata Dump
**Description:** Enumerates slab classes and runs one bounded stats cachedump per

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- stats slabs + stats items for the class map.
- stats cachedump <slab> 5 (hard limit 5 keys per class).
- Grades the key-disclosure exposure.
- Why it matters: cachedump reveals actual key names - session IDs, tokens and object names - the direct input for targeted key theft. The dump capability was the core of the GitHub memcached key theft incidents.
- Safety: metadata only; item values are never fetched.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-slabs-item-dump cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-slabs-item-dump --script-args 'memcached-slabs-item-dump.timeout=8,memcached-slabs-item-dump.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-slabs-item-dump:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - cache key names readable without authentication (10 keys sampled from live slabs)
```

---

### 3. **memcached-udp-amplification-ddos** - UDP Amplification (DDoS Reflector) Measurement
**Description:** Measures the UDP amplification surface with a single tiny request:

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends ONE framed stats request (15 bytes) over UDP.
- Computes the amplification ratio from the response size.
- Grades the amplifier exposure.
- Why it matters: Open Memcached UDP was the memcrashed amplifier used for 1.7 Tbps DDoS floods; even one measurable response proves the endpoint is usable as an internet amplifier. The measurement needs exactly one request - no flooding ever.
- Safety: a single request, no repeat, no spoofed sources, no flood - pure ratio measurement.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-udp-amplification-ddos cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-udp-amplification-ddos --script-args 'memcached-udp-amplification-ddos.timeout=8,memcached-udp-amplification-ddos.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-udp-amplification-ddos:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - UDP amplifier surface active (99.93x ratio, grade extreme)
```

---

### 4. **memcached-unauthenticated-access** - Unauthenticated Service Exposure
**Description:** Probes whether the Memcached command surface answers without any

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends version + stats over ASCII and the binary version frame.
- Counts which surfaces answer without credentials.
- Grades the exposure.
- Why it matters: Memcached has no built-in authentication (SASL is optional); any network peer with 11211 reachability gets full cache control. The unauthenticated surface is the precondition for cache poisoning, key enumeration and UDP amplification abuse.
- Safety: three read-only requests.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-unauthenticated-access cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-unauthenticated-access --script-args 'memcached-unauthenticated-access.timeout=8,memcached-unauthenticated-access.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-unauthenticated-access:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Memcached answers commands without authentication (version 1.6.22)
```

---

### 5. **memcached-flush-all-risk** - flush_all Destructive Command Exposure
**Description:** Probes whether the flush-all channel is open to anonymous callers:

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends flush_all 2147483647 (no live entry is affected).
- Grades OK (wipe capability) versus ERROR (refused).
- Reports the availability risk.
- Why it matters: An accepted flush_all is a one-shot cache wipe - the availability weapon behind database-stamping attacks on misconfigured clusters. The sentinel delay makes the probe safe by construction.
- Safety: the scheduled flush is beyond any practical uptime; nothing is invalidated during or after the audit.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-flush-all-risk cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-flush-all-risk --script-args 'memcached-flush-all-risk.timeout=8,memcached-flush-all-risk.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-flush-all-risk:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - flush-all accepted from an anonymous caller (cache wipe capability)
```

---

### 6. **memcached-sasl-auth-enforced** - SASL Authentication Enforcement
**Description:** Grades SASL enforcement: combines the ASCII answer surface and the

**Risk Level:** 🟠 HIGH | **Category:** defensive, safe

**What it checks:**
- Probes ASCII version (anonymous command access).
- Sends binary SASL list-mechs.
- Grades the authentication posture.
- Why it matters: SASL disabled plus network reachability equals full anonymous cache control - the baseline hardening failure. The mech list confirms whether the binary surface could even authenticate.
- Safety: two read-only requests.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-sasl-auth-enforced cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-sasl-auth-enforced --script-args 'memcached-sasl-auth-enforced.timeout=8,memcached-sasl-auth-enforced.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-sasl-auth-enforced:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - no authentication layer: ASCII answers anonymously and SASL advertises no mechanisms
```

---

### 7. **memcached-watch-stream-exposure** - watch / Stats-Stream Exposure
**Description:** Probes the watch event stream: sends watch fetchers and grades

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends watch fetchers and reads the immediate answer.
- Grades OK (stream offered) versus ERROR (refused).
- Reports the surveillance exposure.
- Why it matters: An open watch stream lets any peer observe live cache operations - keys and access patterns stream past in real time. Combined with cachedump it completes the passive key-theft chain.
- Safety: the probe opens the stream, reads the acknowledgement only, and closes immediately; no events are consumed beyond the handshake.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-watch-stream-exposure cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-watch-stream-exposure --script-args 'memcached-watch-stream-exposure.timeout=8,memcached-watch-stream-exposure.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-watch-stream-exposure:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - live cache event stream offered without authentication
```

---

### 8. **memcached-ascii-udp-disable-check** - UDP Transport Disable Check (ASCII-over-UDP)
**Description:** Verifies whether UDP is disabled on the ASCII surface: sends one

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Sends one framed version request over UDP 11211.
- Records whether the datagram service answers.
- Grades the UDP exposure.
- Why it matters: UDP enabled is the memcrashed amplifier configuration; the CIS benchmark and every hardening guide require -U 0. Detection needs exactly one datagram.
- Safety: a single request.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-ascii-udp-disable-check cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-ascii-udp-disable-check --script-args 'memcached-ascii-udp-disable-check.timeout=8,memcached-ascii-udp-disable-check.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-ascii-udp-disable-check:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - UDP datagram service enabled on 11211
```

---

### 9. **memcached-connection-limit-dos** - Connection Budget & Saturation Posture
**Description:** Audits connection-exhaustion headroom using statistics only: reads

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- stats + stats settings for curr_connections/maxconns.
- Computes remaining headroom as a percentage.
- Grades the exhaustion exposure.
- Why it matters: Memcached connection exhaustion is a simple DoS primitive; the stats counters reveal how close the server runs to its cap and whether maxconns_fast protection is on. Statistical evidence replaces any actual connection flood.
- Safety: one connection total (this one); capacity is read from counters, never tested.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-connection-limit-dos cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-connection-limit-dos --script-args 'memcached-connection-limit-dos.timeout=8,memcached-connection-limit-dos.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-connection-limit-dos:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - connection capacity disclosed without authentication (6/1024 used, 99.4% headroom)
```

---

### 10. **memcached-settings-leak** - Runtime Settings Disclosure
**Description:** Reads stats settings and reports the server configuration: max

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- stats settings without credentials.
- Decodes the interesting configuration keys.
- Grades the configuration disclosure.
- Why it matters: Settings reveal the amplification surface (udpport bound) and the DoS headroom (maxconns, maxbytes) - the inputs for disruption planning. The configuration itself is unauthenticated intelligence.
- Safety: one read-only stats command.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-settings-leak cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-settings-leak --script-args 'memcached-settings-leak.timeout=8,memcached-settings-leak.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-settings-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - server configuration disclosed without authentication (67108864 bytes cap, udpport 11211)
```

---

### 11. **memcached-sizes-memory-dump** - stats sizes Memory Topology Dump
**Description:** Reads the item size histogram (stats sizes) and the general stats

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- stats sizes for the histogram.
- stats for item/byte counters.
- Renders the memory profile and grades the disclosure.
- Why it matters: The size histogram plus curr_items/bytes reveals the volume and shape of cached data - the profile attackers use to plan extraction or eviction attacks. It is another unauthenticated telemetry surface to close.
- Safety: two read-only stats commands.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-sizes-memory-dump cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-sizes-memory-dump --script-args 'memcached-sizes-memory-dump.timeout=8,memcached-sizes-memory-dump.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-sizes-memory-dump:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - cache memory profile disclosed without authentication (137 items, 2 size classes)
```

---

### 12. **memcached-touch-command-audit** - touch / TTL Manipulation Audit
**Description:** Audits the touch command surface: sends touch against the sentinel

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- touch <sentinel-key> 60.
- Grades NOT_FOUND (command processed) versus ERROR (refused).
- Reports the lifecycle-control exposure.
- Why it matters: touch processes prove anonymous callers can manipulate item expiry - the primitive for forced-recomputation and cache-stamping attacks on live entries. The sentinel name cannot affect any real item.
- Safety: the sentinel key does not exist; no live item is touched.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-touch-command-audit cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-touch-command-audit --script-args 'memcached-touch-command-audit.timeout=8,memcached-touch-command-audit.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-touch-command-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - item lifecycle commands processed for anonymous callers (NOT_FOUND)
```

---

### 13. **memcached-verbosity-command-leak** - verbosity Command Exposure
**Description:** Checks whether the verbosity command is accepted from anonymous

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends verbosity 0 (the current default level - no change).
- Grades OK (runtime command accepted) versus ERROR.
- Reports the control-plane exposure.
- Why it matters: An accepted verbosity command proves arbitrary runtime reconfiguration is possible: an attacker can raise logging to exhaust disk or lower it to hide their own activity. It marks the server as fully command-controlled.
- Safety: verbosity 0 sets the level most servers already run; no behavioural change.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-verbosity-command-leak cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-verbosity-command-leak --script-args 'memcached-verbosity-command-leak.timeout=8,memcached-verbosity-command-leak.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-verbosity-command-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - runtime verbosity command accepted anonymously
```

---

### 14. **memcached-binary-protocol-probe** - Binary Protocol Capability Probe
**Description:** Probes the binary protocol surface: sends the binary version frame

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends binary version + binary SASL list-mechs.
- Decodes version and mechanism list.
- Grades the binary surface.
- Why it matters: The binary protocol historically carried heap-overflow CVEs (2016-8705/8706); version mapping flags exposure. An empty SASL mech list proves no authentication is configured on the binary surface.
- Safety: two read-only binary requests.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-binary-protocol-probe cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-binary-protocol-probe --script-args 'memcached-binary-protocol-probe.timeout=8,memcached-binary-protocol-probe.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-binary-protocol-probe:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - binary protocol answers (version 1.6.22, 0 SASL mechanism(s), 1 mapped advisory/ies)
```

---

### 15. **memcached-slab-automove-audit** - Slab Reassign / Automove Posture
**Description:** Audits slab maintenance settings: reads the automove/slab_reassign

**Risk Level:** 🟢 LOW | **Category:** defensive, safe

**What it checks:**
- stats settings for automove/slab_reassign/lru_crawler keys.
- Reports the maintenance posture.
- Grades the disclosure and configuration sanity.
- Why it matters: Aggressive automove can evict live items under churn; disabled slab_reassign wastes memory on skewed workloads - an operational hardening check. It is another unauthenticated configuration read to close.
- Safety: one read-only stats command.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-slab-automove-audit cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-slab-automove-audit --script-args 'memcached-slab-automove-audit.timeout=8,memcached-slab-automove-audit.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-slab-automove-audit:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - slab maintenance configuration disclosed (automove=1, reassign=true)
```

---

### 16. **memcached-version-fingerprint** - Version Fingerprint & Advisory Mapping
**Description:** Extracts the exact Memcached engine version over both ASCII and

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends ASCII version and the binary protocol version frame.
- Maps the version to the advisory table.
- Reports the fingerprint.
- Why it matters: The version selects the applicable CVE set (binary protocol heap overflows, SASL bypasses) for the rest of the audit. ASCII-vs-binary answer differences also fingerprint proxies.
- Safety: two read-only requests.

**How to Execute:**
```bash
nmap -p 11211 --script memcached-version-fingerprint cache01.corp.example.com

# Tuned request budget
nmap -p 11211 --script memcached-version-fingerprint --script-args 'memcached-version-fingerprint.timeout=8,memcached-version-fingerprint.maxrequests=48' cache01.corp.example.com
```

**Sample Output:**
```
| memcached-version-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Memcached version 1.6.22 (1 mapped advisory/ies)
```

