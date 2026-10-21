# 📡 MQTT Security Audits

**16 Nmap NSE scripts** for auditing MQTT message brokers:

**Covers:**

- Unauthenticated broker access and anonymous publish
- Default/weak IoT credential sweeps
- Root-wildcard and sensitive-namespace topic ACL bypass
- Retained-message harvesting
- $SYS internal metric disclosure
- Broker engine fingerprinting
- Duplicate Client-ID session hijacking and privileged Client-ID acceptance
- KeepAlive extremes (session pinning)
- Packet-size limit enforcement
- Legacy protocol-level support
- The QoS 2 exactly-once state machine (four-step handshake + grant table)
- Last Will and Testament injection (including retained wills)
- TLS/mTLS client-certificate enforcement on the 8883 listener

Every script speaks real MQTT 3.1.1 bytes over TCP - CONNECT/CONNACK, SUBSCRIBE/SUBACK, PUBLISH/PUBACK/PUBREC/PUBREL/PUBCOMP, PINGREQ/PINGRESP, UNSUBSCRIBE and DISCONNECT - and turns the observed protocol facts into evidence-based findings.

All probes are bounded, use auditor-owned topics (nmap-audit/*) with inert payloads, and never touch device control channels.

**Ports:** 1883, 8883, 1884 (TLS scripts: 8883, 8884, 8885) or matched `mqtt`/`mqtt-s`/`mosquitto`/`emqx` service | **Protocol:** MQTT 3.1.1 (MQTT-3.1.1 OASIS standard) over plain TCP and TLS | **Total lines of Lua:** 29,113

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [mqtt-anonymous-publish-test](#1-mqtt-anonymous-publish-test---anonymous-write-injection) | 🔴 CRITICAL | vuln, auth, safe | 1809 |
| 2 | [mqtt-default-credentials](#2-mqtt-default-credentials---factory-default-secret-sweep) | 🔴 CRITICAL | vuln, auth, safe | 1818 |
| 3 | [mqtt-unauthenticated-broker](#3-mqtt-unauthenticated-broker---anonymous-broker-access) | 🔴 CRITICAL | vuln, auth, discovery, safe | 1805 |
| 4 | [mqtt-wildcard-subscribe-all](#4-mqtt-wildcard-subscribe-all---root-wildcard-wiretap) | 🔴 CRITICAL | vuln, discovery, safe | 1816 |
| 5 | [mqtt-clientid-spoof-hijack](#5-mqtt-clientid-spoof-hijack---duplicate-client-id-session-takeover) | 🟠 HIGH | vuln, safe | 1837 |
| 6 | [mqtt-tls-client-cert-check](#6-mqtt-tls-client-cert-check---mtls-enforcement-on-the-tls-listener) | 🟠 HIGH | vuln, defensive, safe | 1842 |
| 7 | [mqtt-cleartext-credential-risk](#7-mqtt-cleartext-credential-risk---credentials-over-plain-tcp) | 🟡 MEDIUM | vuln, defensive, safe | 1776 |
| 8 | [mqtt-keepalive-dos-tolerance](#8-mqtt-keepalive-dos-tolerance---session-pinning-via-keepalive-extremes) | 🟡 MEDIUM | vuln, defensive, safe | 1813 |
| 9 | [mqtt-packet-size-limit](#9-mqtt-packet-size-limit---maximum-packet-size-enforcement) | 🟡 MEDIUM | vuln, defensive, safe | 1819 |
| 10 | [mqtt-qos2-handshake-audit](#10-mqtt-qos2-handshake-audit---exactly-once-state-machine) | 🟡 MEDIUM | discovery, safe | 1825 |
| 11 | [mqtt-retained-message-harvest](#11-mqtt-retained-message-harvest---persistent-fleet-state-snapshot) | 🟡 MEDIUM | vuln, discovery, safe | 1843 |
| 12 | [mqtt-sys-topic-leak](#12-mqtt-sys-topic-leak---internal-broker-metrics-exposure) | 🟡 MEDIUM | discovery, safe | 1795 |
| 13 | [mqtt-topic-permission-bypass](#13-mqtt-topic-permission-bypass---topic-acl-enforcement) | 🟡 MEDIUM | vuln, auth, safe | 1840 |
| 14 | [mqtt-will-message-injection](#14-mqtt-will-message-injection---last-will-and-testament-registration) | 🟡 MEDIUM | vuln, safe | 1825 |
| 15 | [mqtt-broker-fingerprint](#15-mqtt-broker-fingerprint---engine-and-version-identification) | 🟢 LOW | discovery, safe | 1853 |
| 16 | [mqtt-protocol-version-support](#16-mqtt-protocol-version-support---legacy-protocol-level-probes) | 🟢 LOW | discovery, safe | 1797 |

---

### 1. **mqtt-anonymous-publish-test** - Anonymous Write Injection
**Description:** Evaluates whether unauthenticated clients can publish messages: QoS 0 and QoS 1 publish acceptance plus a retain-flagged publish verified by re-subscribing to confirm persistence in the broker.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, auth, safe

**What it checks:**
- QoS 0 publish acceptance (fire-and-forget write)
- QoS 1 publish with PUBACK acknowledgement (broker-level write confirmation)
- Retained publish + re-subscribe round-trip (persistent injection proof)
- Full refusal classified cleanly when the session itself is denied

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-anonymous-publish-test target.example.com
```

**Sample Output:**
```
| mqtt-anonymous-publish-test:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Unauthenticated clients can publish messages to the broker
|   Severity counts: CRITICAL=2 HIGH=1 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [CRITICAL] Anonymous publish accepted by the broker (nmap-audit/publish-test)
|     [CRITICAL] Broker acknowledged the anonymous QoS 1 publish (PUBACK) (nmap-audit/publish-test)
|     [HIGH] Anonymous retain-flagged publish persisted in the broker (nmap-audit/publish-test/retain)
|   Anonymous Publish Matrix:
|     QoS 0 publish: accepted
|     QoS 1 publish: accepted, PUBACK received (packet id 2)
|     Retain publish + re-subscribe: PERSISTED - retained value redelivered to the new subscription
|   CVSS Score: 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
```

---

### 2. **mqtt-default-credentials** - Factory Default Secret Sweep
**Description:** Attempts broker authentication with a curated set of documented default/weak IoT credential pairs (admin/admin, guest/guest, test/test, mqtt/mqtt, root/root, ...); any accepted pair is a CRITICAL finding with the documented source.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, auth, safe

**What it checks:**
- Anonymous baseline first (short-circuits the sweep when no auth is required)
- 12 documented default pairs, each with a fresh short-lived connection
- Per-pair CONNACK recording (0x00 accepted / 0x04 bad credentials / 0x05 not authorized)
- Full attempt inventory with the accepted pairs listed separately

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-default-credentials target.example.com
```

**Sample Output:**
```
| mqtt-default-credentials:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 1 documented default credential pair(s) accepted by the broker
|   Severity counts: CRITICAL=1 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] Default credential pair 'admin' accepted by the broker (default credentials)
|   Default Credential Sweep:
|     admin / admin: ACCEPTED (CONNACK 0x00)
|     admin / password: refused (CONNACK 0x04 Connection refused: bad username or password)
|     guest / guest: refused (CONNACK 0x04 Connection refused: bad username or password)
|   Accepted Default Pairs:
|     Pair 1: admin / admin
|     Pair 1 source: EMQX / HiveMQ / many IoT gateways ship admin/admin out of the box
|   CVSS Score: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
```

---

### 3. **mqtt-unauthenticated-broker** - Anonymous Broker Access
**Description:** Detects unauthenticated MQTT brokers by sending an anonymous MQTT 3.1.1 CONNECT and classifying the CONNACK return code; when accepted, measures the actual anonymous capabilities ($SYS read, publish, keepalive).

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, auth, discovery, safe

**What it checks:**
- Anonymous CONNECT (no username/password, no will) and CONNACK return-code classification (0x00 accepted / 0x04 bad credentials / 0x05 not authorized / protocol refusals)
- Anonymous $SYS/# subscription (internal metric disclosure)
- Single QoS 1 publish into an auditor-owned topic with PUBACK verification
- PINGREQ/PINGRESP keepalive check on the anonymous session

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-unauthenticated-broker target.example.com

# Custom client id
nmap -p 1883 --script mqtt-unauthenticated-broker --script-args 'mqtt-unauthenticated-broker.client_id=audit-01' target.example.com
```

**Sample Output:**
```
| mqtt-unauthenticated-broker:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Unauthenticated Anonymous MQTT Broker Access Permitted
|   Severity counts: CRITICAL=2 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] Anonymous client can publish messages to the broker (nmap-audit/publish-probe)
|     [CRITICAL] MQTT broker accepted an anonymous connection with no credentials (anonymous CONNECT)
|     [MEDIUM] Broker internal $SYS metrics are readable without authentication ($SYS/#)
|   Anonymous Capability Probes:
|     $SYS/# subscription: accepted, 10 $SYS metric messages delivered
|     Publish probe (nmap-audit/publish-probe): accepted (PUBACK received, QoS 1)
|   CONNACK Analysis:
|     CONNACK Return Code: 0x00 (Connection accepted)
|     Protocol: MQTT 3.1.1 (protocol level 4)
|   CVSS Score: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
```

---

### 4. **mqtt-wildcard-subscribe-all** - Root Wildcard Wiretap
**Description:** Connects anonymously, subscribes to the root multi-level wildcard # and listens to the delivery burst - a granted # is a complete wiretap of the broker, including retained state and control topics.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, discovery, safe

**What it checks:**
- Root # SUBSCRIBE grant (SUBACK QoS) and denial (0x80)
- Delivery burst drain (up to 64 messages): total, unique topics, retained count
- Topic class breakdown (control/shadow/telemetry/alarm/sys/private/data)
- Sensitive topic sample with truncated payloads

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-wildcard-subscribe-all target.example.com
```

**Sample Output:**
```
| mqtt-wildcard-subscribe-all:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Anonymous client subscribed to # and received 15 messages across 15 topics
|   Severity counts: CRITICAL=2 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] Root wildcard # granted to an anonymous session (full broker wiretap) (# subscription)
|     [CRITICAL] 12 sensitive topics (control/shadow/sys) delivered in the burst (sensitive topics)
|   Root Wildcard Delivery:
|     Messages delivered: 15
|     Unique topics: 15
|     Retained-flagged messages: 5
|   Topic Class Breakdown:
|     control: 4
|     data: 2
|     sys: 10
|   CVSS Score: 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H)
```

---

### 5. **mqtt-clientid-spoof-hijack** - Duplicate Client ID Session Takeover
**Description:** Tests whether the broker accepts privileged Client IDs (admin, root, broker, system, service) and whether a second client can hijack an existing session by registering the same Client ID (the victim session is disconnected per the MQTT spec when IDs collide).

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Privileged Client ID acceptance matrix (5 IDs, fresh connections)
- Duplicate-ID hijack test: victim session + attacker session with the same ID
- Victim liveness check after the duplicate connect (PINGREQ answer / packet read)
- Client-ID policy classification (privileged-sounding, short, empty)

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-clientid-spoof-hijack target.example.com
```

**Sample Output:**
```
| mqtt-clientid-spoof-hijack:
|   Risk Level: 🟠 HIGH
|   Status: AT RISK - 5 privileged Client IDs accepted (hijack not confirmed)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Findings:
|     [MEDIUM] Broker accepts privileged-sounding Client IDs without restriction (privileged Client IDs)
|   Privileged Client ID Probe:
|     admin: accepted (CONNACK 0x00) - client id length 5
|     root: accepted (CONNACK 0x00) - client id length 4
|     broker: accepted (CONNACK 0x00) - client id length 6
|   Duplicate-ID Hijack Test:
|     Victim Client ID: victim_9f2ab1c0
|     Duplicate-ID connection: accepted (CONNACK 0x00)
|     Victim session state after duplicate connect: still responsive (hijack not confirmed)
```

---

### 6. **mqtt-tls-client-cert-check** - mTLS Enforcement on the TLS Listener
**Description:** Sends a minimal TLS ClientHello to the broker's TLS port (8883) and parses the server handshake flight: a CertificateRequest (0x0D) means client certificates are required (mTLS enforced); its absence means any client can join with no device identity.

**Risk Level:** 🟠 HIGH | **Category:** vuln, defensive, safe

**What it checks:**
- Minimal ClientHello (TLS_RSA_WITH_AES_128_CBC_SHA) over plain TCP
- Handshake message inventory (ServerHello, Certificate, CertificateRequest, ServerHelloDone)
- CertificateRequest presence = mTLS posture
- MQTT CONNACK posture after the TLS probe (anonymous accepted over TLS?)

**How to Execute:**
```bash
nmap -p 8883 --script mqtt-tls-client-cert-check target.example.com
```

**Sample Output:**
```
| mqtt-tls-client-cert-check:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - TLS endpoint does not require a client certificate (mTLS not enforced)
|   Severity counts: CRITICAL=0 HIGH=2 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [HIGH] Server did not send a CertificateRequest: any client can complete the TLS handshake without a certificate (mTLS enforcement)
|     [HIGH] Anonymous MQTT session is accepted directly over the TLS listener (TLS + anonymous auth)
|   TLS Handshake Analysis:
|     Handshake messages seen: ServerHello
|     CertificateRequest (0x0D): absent - no client certificate requested
|   MQTT Authz Posture:
|     MQTT CONNACK after TLS probe: 0x00 (Connection accepted)
|     Anonymous session over TLS: accepted
|   CVSS Score: 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N)
```

---

### 7. **mqtt-cleartext-credential-risk** - Credentials Over Plain TCP
**Description:** Evaluates whether the broker accepts authentication credentials over the unencrypted plain TCP listener: anonymous baseline plus a CONNECT carrying a randomly generated (non-secret) audit credential pair.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, defensive, safe

**What it checks:**
- Anonymous baseline CONNACK (is auth required at all?)
- Credential CONNECT with a random per-run audit pair (flags 0xC0) over plain TCP
- Posture classification: credentials accepted in cleartext / auth enforced / auth unnecessary
- Listener facts (port, transport, protocol)

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-cleartext-credential-risk target.example.com
```

**Sample Output:**
```
| mqtt-cleartext-credential-risk:
|   Risk Level: 🟡 MEDIUM
|   Status: AT RISK - Broker requires no credentials at all on the plain listener (see mqtt-unauthenticated-broker)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Anonymous access is accepted, so any credentials used on this listener are optional and cleartext (plain TCP 1883)
|   Credential Transport Analysis:
|     Anonymous baseline: CONNACK 0x00 (Connection accepted)
|     Credential CONNECT: CONNACK 0x04 (Connection refused: bad username or password) for a randomly generated audit pair (length 14/12)
|     Credential format observed: MQTT CONNECT flags 0xC0 (username + password bits set) on plain TCP
|   Listener Facts:
|     Listener port: 1883
|     Transport: plain TCP (no TLS on this listener)
```

---

### 8. **mqtt-keepalive-dos-tolerance** - Session Pinning via KeepAlive Extremes
**Description:** Connects with KeepAlive = 0 (timeout disabled per spec) and KeepAlive = 65535 (two-byte maximum, ~18h idle tolerance) and measures whether the broker enforces any server-side idle cap - the precondition for session-pinning denial of service.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, defensive, safe

**What it checks:**
- CONNACK acceptance of KeepAlive = 0 and KeepAlive = 65535
- PINGREQ/PINGRESP responsiveness on the extreme-keepalive sessions
- Idle observation window: does the broker reclaim the idle session?

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-keepalive-dos-tolerance target.example.com
```

**Sample Output:**
```
| mqtt-keepalive-dos-tolerance:
|   Risk Level: 🟡 MEDIUM
|   Status: AT RISK - Broker tolerates extreme KeepAlive values without a server-side idle limit
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=2 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Sessions with KeepAlive = 0 stay attached indefinitely (session pinning possible) (keepalive tolerance)
|     [MEDIUM] KeepAlive = 65535 is accepted, allowing ~18h idle tolerance per session (keepalive tolerance)
|   KeepAlive Tolerance Matrix:
|     KeepAlive = 0: accepted, PINGREQ answered, session still alive after 1s idle (no server-side idle cap observed)
|     KeepAlive = 65535: accepted, PINGREQ answered, session still alive after 1s idle (no server-side idle cap observed)
|   CVSS Score: 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
```

---

### 9. **mqtt-packet-size-limit** - Maximum Packet Size Enforcement
**Description:** Publishes QoS 0 payloads of 1 KiB, 64 KiB and 256 KiB (fresh connection after each disconnection) plus a structurally malformed 5-byte remaining-length header, and derives the broker's effective maximum packet size.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, defensive, safe

**What it checks:**
- Payload size ladder (1 KiB / 64 KiB / 256 KiB) with acceptance or disconnection per size
- Post-publish liveness check (was the session dropped by the broker?)
- Malformed remaining-length probe (5-byte varint, spec caps at 4 bytes)

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-packet-size-limit target.example.com
```

**Sample Output:**
```
| mqtt-packet-size-limit:
|   Risk Level: 🟡 MEDIUM
|   Status: AT RISK - Broker accepted oversized PUBLISH payloads (no effective maximum)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=2 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Oversized PUBLISH payloads were accepted by the broker (max packet size)
|     [MEDIUM] Malformed 5-byte remaining-length header was tolerated (parser robustness)
|   Payload Size Ladder:
|     1 KiB: accepted
|     64 KiB: accepted
|     256 KiB: accepted
|   Malformed Remaining Length:
|     Probe: malformed 5-byte remaining length tolerated (session still alive)
|   CVSS Score: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)
```

---

### 10. **mqtt-qos2-handshake-audit** - Exactly-Once State Machine
**Description:** Audits the QoS 2 exactly-once implementation: SUBSCRIBE grants at QoS 2/1/0 (detecting silent downgrades via the broker's max_qos) and the full four-step handshake PUBLISH -> PUBREC -> PUBREL -> PUBCOMP with packet-id consistency.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- SUBSCRIBE grant table (requested QoS 2/1/0 -> granted QoS or 0x80 denial)
- QoS 2 publish four-step handshake (PUBREC/PUBREL/PUBCOMP packet-id matching)
- Downgrade detection (exactly-once silently reduced to at-least-once)

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-qos2-handshake-audit target.example.com
```

**Sample Output:**
```
| mqtt-qos2-handshake-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: QoS 2 audit: QoS 2 subscription downgraded to QoS 1
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Broker downgrades QoS 2 SUBSCRIBE requests (max_qos configuration)
|   SUBSCRIBE Grant Table:
|     Requested QoS 2: granted QoS 1
|     Requested QoS 1: granted QoS 1
|     Requested QoS 0: granted QoS 0
|   QoS 2 Handshake Trace:
|     PUBLISH QoS 2: accepted (packet id 1)
|     PUBREC: received with matching packet id
|     PUBREL: sent with matching packet id
|     PUBCOMP: received with matching packet id
|     Verdict: four-step QoS 2 state machine consistent
|   CVSS Score: 4.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)
```

---

### 11. **mqtt-retained-message-harvest** - Persistent Fleet State Snapshot
**Description:** Subscribes to # and drains the delivery burst, keeping only RETAIN-flagged messages - the broker's long-term fleet memory (last door state, camera URIs, config, alarms) - and classifies what is exposed.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- Root # subscription grant and delivery drain (up to 48 messages)
- RETAIN-flag filtering and per-message topic/payload/size recording
- Topic classification (control/shadow/telemetry/alarm/sys/private/data)
- Sensitive payload markers (URIs, credential-like values, configuration documents)

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-retained-message-harvest target.example.com
```

**Sample Output:**
```
| mqtt-retained-message-harvest:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 15 retained messages harvested, 12 carry sensitive content
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=2 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Broker delivers 15 retained messages to a new subscriber (fleet state snapshot) (retained messages)
|     [MEDIUM] 12 retained messages expose sensitive content (URIs, config, control/shadow state) (sensitive retained state)
|   Classification Breakdown:
|     control: 4
|     data: 2
|     sys: 9
|     Sensitive retained: 12
|   CVSS Score: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
```

---

### 12. **mqtt-sys-topic-leak** - Internal Broker Metrics Exposure
**Description:** Subscribes to the $SYS/# internal hierarchy and rebuilds the broker's operational dashboard: version string, client counts, message/byte counters, stored message count, heap size and uptime.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- $SYS/# subscription grant and metric drain
- Flat name/value reconstruction of the $SYS topic tree
- Derived operational summary (version, connected clients, lifetime counters, heap, uptime)
- Exact version disclosure as a separate CVE-selection finding

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-sys-topic-leak target.example.com
```

**Sample Output:**
```
| mqtt-sys-topic-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - $SYS/# exposed: 10 internal broker metrics readable without authentication
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=1 INFO=0
|   Findings:
|     [MEDIUM] Broker internal $SYS metrics are readable (version, client counts, message counters, heap, uptime) ($SYS/#)
|     [LOW] Exact broker version is disclosed: 2.0.18 ($SYS/broker/version)
|   Operational Summary:
|     Broker version: 2.0.18
|     Connected clients: 3
|     Messages received (lifetime): 512
|     Stored/retained messages: 6
|     Uptime: 3600 s (~1.0 h)
|   CVSS Score: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
```

---

### 13. **mqtt-topic-permission-bypass** - Topic ACL Enforcement
**Description:** Audits topic ACLs: subscribes to each sensitive pattern (admin/#, $SYS/#, commands/#, cmd/#, devices/#/set, shadow/#, #) recording the SUBACK grant/deny, then publishes one small message into a write-probe topic and verifies delivery (silent-drop detection).

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, auth, safe

**What it checks:**
- Session establishment (anonymous, falling back to one documented default credential when refused)
- Sensitive topic grant table (9 patterns, granted QoS or 0x80 denial)
- Write probe: publish + drain round-trip (delivery proves the write reached the broker)
- Root wildcard # grant reported as the strongest bypass

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-topic-permission-bypass target.example.com
```

**Sample Output:**
```
| mqtt-topic-permission-bypass:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Root wildcard (#) subscription granted to anonymous session
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [HIGH] The root wildcard # is granted, exposing every topic on the broker (# subscription)
|   Sensitive Topic Grant Table:
|     admin/#: GRANTED (QoS 0) - administrative command tree
|     $SYS/#: GRANTED (QoS 0) - internal broker metrics
|     commands/#: GRANTED (QoS 0) - device command channel
|     #: GRANTED (QoS 0) - root wildcard (maximum scope)
|   Write Probe:
|     Publish nmap-audit/acl-write-probe: delivered (write reached the broker)
|   CVSS Score: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)
```

---

### 14. **mqtt-will-message-injection** - Last Will and Testament Registration
**Description:** Registers anonymous Last Will messages (QoS 1, plus a RETAIN-flagged variant on a fresh connection) and verifies the retained will redelivers to a new subscription - the broker itself publishing an attacker-chosen message.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, safe

**What it checks:**
- Anonymous CONNECT with will flags (auditor-owned topic, inert payload, QoS 1)
- Retain-flagged will variant (persistent injection)
- Retained will redelivery check (fresh subscription receives the will value)
- Will safety classification of the probe itself

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-will-message-injection target.example.com
```

**Sample Output:**
```
| mqtt-will-message-injection:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Anonymous clients can register retained Last Will messages
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=2 LOW=0 INFO=1
|   Findings:
|     [MEDIUM] Anonymous CONNECT with a RETAIN-flagged will was accepted (nmap-audit/will-probe/retained)
|     [MEDIUM] Anonymous non-retained will registration is also accepted (nmap-audit/will-probe)
|   Will Registration Matrix:
|     Will on nmap-audit/will-probe: registered (CONNACK 0x00, will QoS 1)
|     Will on nmap-audit/will-probe/retained (RETAIN): registered (CONNACK 0x00, will QoS 1)
|   CVSS Score: 5.9 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)
```

---

### 15. **mqtt-broker-fingerprint** - Engine and Version Identification
**Description:** Harvests the $SYS hierarchy from an anonymous session and runs a signature engine (version-string patterns first, then key-set signatures) to identify the broker engine and major version - Mosquitto 1.x/2.x, EMQX 4/5, HiveMQ, VerneMQ, ActiveMQ - plus the fleet metrics that size the exposure.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Anonymous $SYS/# harvest (stops cleanly when the session is refused - no brute force)
- Signature engine: version-string patterns (2.x/1.x/5.x/4.x) + key-set signatures
- Confidence + runner-up candidate reporting
- Fleet metrics (connected clients, message/byte counters, heap, uptime) and protocol facts

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-broker-fingerprint target.example.com
```

**Sample Output:**
```
| mqtt-broker-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: Broker fingerprinted: 10 $SYS metrics harvested, engine identification follows
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=2
|   Findings:
|     [INFO] MQTT broker exposes 10 $SYS internal metrics to anonymous clients ($SYS/#)
|     [INFO] Broker engine identified as Eclipse Mosquitto 2.x (confidence: high) (fingerprint)
|   Broker Fingerprint:
|     Identified engine: Eclipse Mosquitto 2.x
|     Engine family: mosquitto
|     Confidence: high
|     Version value: 2.0.18
|   Fleet Metrics:
|     Connected clients: 3
|     Total clients (session scope): 12
|     Messages received (lifetime): 512
|     Uptime: 3600s
|   CVSS Score: n/a - discovery audit
```

---

### 16. **mqtt-protocol-version-support** - Legacy Protocol Level Probes
**Description:** Probes the broker across protocol versions - MQTT 3.1.1 (name MQTT, level 4), legacy MQTT 3.1 (name MQIsdp, level 3), MQTT 3.1 (name MQTT, level 3) and an invalid level 0 handshake - recording the CONNACK code for each.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Per-(protocol name, level) CONNECT matrix with fresh connections
- Accepted / protocol-refused (0x01) / other classification per probe
- Legacy 3.1 availability flag (policy decision signal)
- Invalid level 0 acceptance (parser robustness observation)

**How to Execute:**
```bash
nmap -p 1883 --script mqtt-protocol-version-support target.example.com
```

**Sample Output:**
```
| mqtt-protocol-version-support:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Broker supports MQTT 3.1.1 and legacy MQTT 3.1 (MQIsdp)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=2 INFO=0
|   Findings:
|     [LOW] Legacy MQTT 3.1 (MQIsdp) protocol level is still negotiable (protocol versions)
|   Protocol Version Matrix:
|     MQTT 3.1.1 (name MQTT, level 4): ACCEPTED (CONNACK 0x00)
|     MQTT 3.1 legacy (name MQIsdp, level 3): ACCEPTED (CONNACK 0x00)
|     MQTT 3.1 (name MQTT, level 3): ACCEPTED (CONNACK 0x00)
|     invalid level 0 handshake: refused (CONNACK 0x01 Connection refused: unacceptable protocol level)
|   CVSS Score: n/a - discovery audit
```

## 🧰 Shared Infrastructure

All 16 scripts are assembled from a shared MQTT wire/transport bundle (spec-driven generation via `tools/gen_mqtt_script.py` + `tools/helpers/mqttwire.lua` + `tools/helpers/mqtttransport.lua`):

- **MQTT 3.1.1 packet codec** - remaining-length varint, UTF-8 string fields, CONNECT (will/username/password flags), CONNACK, PUBLISH (QoS 0/1/2, retain, dup), SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, PUBACK/PUBREC/PUBREL/PUBCOMP, PINGREQ/PINGRESP, DISCONNECT builders and parsers
- **Topic engine** - wildcard matching (`#`/`+`), topic classification (sys/private/control/shadow/telemetry/alarm), depth-risk scoring
- **$SYS parsing** - metric name/value reconstruction and fleet-metric summarization
- **Fingerprint signatures** - Mosquitto 1.x/2.x, EMQX 4/5, HiveMQ, VerneMQ, ActiveMQ (version-string + key-set matching)
- **Session transport** - packet-id allocation, await-by-type with retained-publish draining, QoS 2 four-way handshake, request budget, retries, inter-request delay, safe teardown
- **Finding model** - severity weights, deduplication, weighted scoring, ordered output table

## 🛡️ Safety Notes

- Probes publish only to auditor-owned `nmap-audit/*` topics with inert payloads (bounded size, single send per probe).
- Default-credential sweeps use only pairs from public vendor documentation - no brute force, no list spraying.
- Will probes target `nmap-audit/will/*` topics; retained wills are cleaned up by the broker's own retention on next publish to the same topic.
- Every script enforces a request budget (`--script-args '<script>.maxrequests=N'`) and per-attempt timeouts.
