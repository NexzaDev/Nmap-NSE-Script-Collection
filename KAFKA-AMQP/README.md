# 📨 Kafka & RabbitMQ Security Audits

**16 Nmap NSE scripts** for auditing Apache Kafka brokers and RabbitMQ message buses directly on the wire:

**Covers:**

- A full Kafka binary-protocol client (size-prefixed request framing with correlation ids, ApiVersions version-floor inference, wildcard/named Metadata with per-partition leader and ISR decoding, ListGroups/DescribeGroups member extraction, CreateTopics/DeleteTopics sentinel semantics, SaslHandshake mechanism enumeration) with 40+ Kafka error-code names and version-to-advisory era mapping; a complete AMQP 0-9-1 codec (protocol preamble, connection.start/start-ok with field-table encode/decode, tune/tune-ok, open/open-ok, close/close-ok, channel.open, passive queue.declare, SASL PLAIN) with close-code interpretation; a RabbitMQ management HTTP/JSON layer (overview, definitions, queues with chunked-transfer decoding); and a TLS greeting grader for the AMQPS listener

**The suite covers the messaging attack surface:**

- Unauthenticated broker APIs
- Anonymous topic and consumer-group enumeration
- Sentinel create/delete authorization probes
- SASL posture (PLAIN over cleartext, SCRAM grading)
- Default-credential and anonymous logins
- Management API authentication
- Definitions export exposure
- Queue/message inventory with dead-queue analysis and TLS/auth enforcement on 5671

**Every probe is bounded and non-destructive:**

- Read-only frames or single well-known/default credential attempts
- Uniquely-named sentinel topics that are deleted and verified gone
- Passive declares on sentinel queues that cannot exist
- No brute force
- No message consumption or production.

**Ports:** 9092/tcp (kafka) + 5672/tcp (amqp) + 5671/tcp (amqps) + 15672/tcp (http) | **Protocols:** Kafka binary protocol, AMQP 0-9-1, RabbitMQ management HTTP/JSON, TLS | **Total lines of Lua:** 33,051

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [kafka-anonymous-consumer-group](#1-kafka-anonymous-consumer-group---anonymous-consumer-group-enumeration) | 🔴 CRITICAL | vuln, safe | 2093 |
| 2 | [kafka-metadata-topic-leak](#2-kafka-metadata-topic-leak---topic-inventory--partition-topology-leak) | 🔴 CRITICAL | vuln, safe | 2081 |
| 3 | [kafka-unauth-broker-access](#3-kafka-unauth-broker-access---unauthenticated-broker-api-access) | 🔴 CRITICAL | vuln, safe | 2069 |
| 4 | [rabbitmq-amqp-anonymous-login](#4-rabbitmq-amqp-anonymous-login---default-credential-login--capability-probe) | 🔴 CRITICAL | vuln, safe | 2059 |
| 5 | [rabbitmq-default-credentials](#5-rabbitmq-default-credentials---guestguest-default-credential-check) | 🔴 CRITICAL | vuln, safe | 2045 |
| 6 | [rabbitmq-definitions-export-leak](#6-rabbitmq-definitions-export-leak---definitions-export-usersvhostspolicies) | 🔴 CRITICAL | vuln, safe | 2066 |
| 7 | [rabbitmq-management-unauth](#7-rabbitmq-management-unauth---management-api-authentication-posture) | 🔴 CRITICAL | vuln, safe | 2055 |
| 8 | [kafka-create-topic-allowed](#8-kafka-create-topic-allowed---anonymous-createtopics-sentinel-probe) | 🟠 HIGH | vuln, safe | 2067 |
| 9 | [kafka-delete-topic-allowed](#9-kafka-delete-topic-allowed---anonymous-deletetopics-sentinel-probe) | 🟠 HIGH | vuln, safe | 2070 |
| 10 | [rabbitmq-queue-messages-dump](#10-rabbitmq-queue-messages-dump---queue-inventory--backlog-analysis) | 🟠 HIGH | vuln, safe | 2074 |
| 11 | [rabbitmq-tls-auth-enforced](#11-rabbitmq-tls-auth-enforced---tls-enforcement--auth-posture-on-5671) | 🟠 HIGH | defensive, safe | 2082 |
| 12 | [kafka-plain-auth-over-cleartext](#12-kafka-plain-auth-over-cleartext---sasl-plain-over-cleartext-listener) | 🟡 MEDIUM | defensive, safe | 2053 |
| 13 | [kafka-sasl-mechanism-audit](#13-kafka-sasl-mechanism-audit---sasl-mechanism-enumeration--grading) | 🟡 MEDIUM | discovery, safe | 2048 |
| 14 | [kafka-broker-fingerprint](#14-kafka-broker-fingerprint---broker-version-fingerprint-apiversions-floor) | 🟢 LOW | discovery, safe | 2054 |
| 15 | [kafka-controller-epoch-leak](#15-kafka-controller-epoch-leak---cluster-topology--controller-disclosure) | 🟢 LOW | discovery, safe | 2064 |
| 16 | [rabbitmq-amqp-protocol-handshake](#16-rabbitmq-amqp-protocol-handshake---amqp-0-9-1-handshake-fingerprint) | 🟢 LOW | discovery, safe | 2071 |

---

### 1. **kafka-anonymous-consumer-group** - Anonymous Consumer-Group Enumeration
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends ListGroups (key 16) anonymously.
- Describes every returned group with DescribeGroups (key 15).
- Collects member_id/client_id/client_host per member.
- Grades the disclosure.
- Why it matters: Group names and member client_ids expose the processing topology: which applications consume which data streams. client_host values are an internal network map handed to any unauthenticated client, useful for lateral movement planning.
- Safety: two read-only admin frames; the audit never joins or mutates any group.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-anonymous-consumer-group broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-anonymous-consumer-group --script-args 'kafka-anonymous-consumer-group.timeout=8,kafka-anonymous-consumer-group.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-anonymous-consumer-group:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - consumer group inventory and membership readable anonymously
```

---

### 2. **kafka-metadata-topic-leak** - Topic Inventory & Partition Topology Leak
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends wildcard Metadata and decodes every returned topic entry.
- Sends named Metadata probes for common business topic names.
- Flags internal topics (__consumer_offsets) visibility.
- Grades disclosure and lists broker/controller topology seen.
- Why it matters: Topic names are business intelligence: orders, payments, customers. Leaking them maps the entire data pipeline for an attacker. Partition and ISR topology reveal replica layout, which is exactly what a targeted follower-fetch or leader-transfer abuse needs.
- Safety: two Metadata reads only; no consume, no produce, no topic mutations; the sentinel name can never match a real topic.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-metadata-topic-leak broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-metadata-topic-leak --script-args 'kafka-metadata-topic-leak.timeout=8,kafka-metadata-topic-leak.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-metadata-topic-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - topic inventory disclosed without authentication
```

---

### 3. **kafka-unauth-broker-access** - Unauthenticated Broker API Access
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends ApiVersions (key 18) and decodes the advertised API surface.
- Sends wildcard Metadata (key 3) to test anonymous cluster visibility.
- Sends SaslHandshake (key 17, PLAIN) to fingerprint the auth posture.
- Grades the endpoint and maps the version floor to advisories.
- Why it matters: An unauthenticated ApiVersions + Metadata answer is the entry point for every Kafka attack: topic enumeration, consumer-group theft and data reads all start from these two frames. The SASL handshake state (ILLEGAL_SASL_STATE vs mechanism list) proves whether authentication is even configured on this listener.
- Safety: three read-only frames; no credentials, no topic mutations, no data reads.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-unauth-broker-access broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-unauth-broker-access --script-args 'kafka-unauth-broker-access.timeout=8,kafka-unauth-broker-access.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-unauth-broker-access:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - broker API fully answers without authentication
```

---

### 4. **rabbitmq-amqp-anonymous-login** - Default-Credential Login & Capability Probe
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Runs connection.start/start-ok with PLAIN guest/guest.
- On tune sends connection.open for vhost /.
- If opened: channel.open plus a passive declare of the sentinel.
- Grades the login outcome from open-ok vs close codes.
- Why it matters: A working anonymous login is full message-bus compromise: an attacker can consume, produce and declare entities in the vhost. The passive queue.declare sentinel proves channel and declare reachability without touching any real queue.
- Safety: one login attempt with well-known defaults, no brute force; the sentinel queue never exists so the declare is read-shaped (passive) and the connection closes immediately after.

**How to Execute:**
```bash
nmap -p 5672 --script rabbitmq-amqp-anonymous-login mq01.corp.example.com

# Tuned request budget
nmap -p 5672 --script rabbitmq-amqp-anonymous-login --script-args 'rabbitmq-amqp-anonymous-login.timeout=8,rabbitmq-amqp-anonymous-login.maxrequests=48' mq01.corp.example.com
```

**Sample Output:**
```
| rabbitmq-amqp-anonymous-login:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - anonymous/default credentials grant a working AMQP connection
```

---

### 5. **rabbitmq-default-credentials** - guest/guest Default Credential Check
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Fingerprints the broker from connection.start.
- Sends exactly one start-ok with PLAIN guest/guest.
- Completes tune/open when accepted; records close 403 when refused.
- Grades the authentication posture.
- Why it matters: guest/guest is the first pair every attacker tries; its acceptance means full unauthenticated message access and management pivoting. A single-attempt check gives defenders the exact same signal as an attacker's recon without any brute-force noise.
- Safety: one login attempt, no wordlists, no queue or exchange operations; the connection is closed immediately after the verdict.

**How to Execute:**
```bash
nmap -p 5672 --script rabbitmq-default-credentials mq01.corp.example.com

# Tuned request budget
nmap -p 5672 --script rabbitmq-default-credentials --script-args 'rabbitmq-default-credentials.timeout=8,rabbitmq-default-credentials.maxrequests=48' mq01.corp.example.com
```

**Sample Output:**
```
| rabbitmq-default-credentials:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - default credentials grant broker access
```

---

### 6. **rabbitmq-definitions-export-leak** - Definitions Export (Users/VHosts/Policies)
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends GET /api/definitions with no credentials.
- On 200 decodes users, vhosts, permissions, queues, exchanges, bindings and policies.
- Flags guest presence and administrator-tagged accounts.
- Grades the export exposure.
- Why it matters: The definitions export is a blueprint of the broker: every user with role tags, every vhost, every queue and binding. Password hashes ride along in a real export, so an open endpoint is effectively a credential-cracking target list.
- Safety: a single GET; the audit never uploads definitions and never renders password hashes in its output.

**How to Execute:**
```bash
nmap -p 15672 --script rabbitmq-definitions-export-leak mq01.corp.example.com

# Tuned request budget
nmap -p 15672 --script rabbitmq-definitions-export-leak --script-args 'rabbitmq-definitions-export-leak.timeout=8,rabbitmq-definitions-export-leak.maxrequests=48' mq01.corp.example.com
```

**Sample Output:**
```
| rabbitmq-definitions-export-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - broker definitions export readable without credentials
```

---

### 7. **rabbitmq-management-unauth** - Management API Authentication Posture
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends GET /api/overview with no Authorization header.
- Distinguishes 200 (open), 401/403 (auth enforced) and others.
- Decodes the overview JSON: versions, node, listeners, totals.
- Grades the management exposure.
- Why it matters: /api/overview is the keyscreen of the message bus: versions, node names, listeners, live queue/connection/consumer totals. An unauthenticated 200 means every other /api endpoint (queues, users, policies) is equally open until proven otherwise.
- Safety: a single GET request; no POST/PUT/DELETE, no configuration changes, no queue operations.

**How to Execute:**
```bash
nmap -p 15672 --script rabbitmq-management-unauth mq01.corp.example.com

# Tuned request budget
nmap -p 15672 --script rabbitmq-management-unauth --script-args 'rabbitmq-management-unauth.timeout=8,rabbitmq-management-unauth.maxrequests=48' mq01.corp.example.com
```

**Sample Output:**
```
| rabbitmq-management-unauth:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - management API fully readable without credentials
```

---

### 8. **kafka-create-topic-allowed** - Anonymous CreateTopics Sentinel Probe
**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends CreateTopics (key 19) for the sentinel: 1 partition, RF 1.
- Decodes the topic error code (NO_ERROR vs CLUSTER_AUTHORIZATION_FAILED).
- On success deletes the sentinel and verifies removal via Metadata.
- Grades the create path.
- Why it matters: Topic creation is a control-plane write: an open create path lets an attacker shadow real topics, exhaust disk via partition floods and confuse downstream consumers with look-alike names. The probe distinguishes authorization failures from policy failures so defenders know exactly which layer blocked the request.
- Safety: one create of a uniquely-named 1-partition, RF-1 topic that is deleted immediately and its absence verified.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-create-topic-allowed broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-create-topic-allowed --script-args 'kafka-create-topic-allowed.timeout=8,kafka-create-topic-allowed.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-create-topic-allowed:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - anonymous clients may create topics
```

---

### 9. **kafka-delete-topic-allowed** - Anonymous DeleteTopics Sentinel Probe
**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Verifies via Metadata that the sentinel topic does not exist.
- Sends DeleteTopics (key 20) for the sentinel.
- Decodes the error code to distinguish authorization from policy.
- Grades the delete path.
- Why it matters: An authorized delete path means one unauthenticated request can erase production data pipelines: the deletion of a real topic is irreversible and cascades to downstream consumers. UNKNOWN_TOPIC_OR_PARTITION for a nonexistent sentinel is definitive proof that authorization passed and only the name was missing.
- Safety: nothing that exists is ever deleted - the sentinel is checked absent beforehand and the probe deletes only that name.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-delete-topic-allowed broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-delete-topic-allowed --script-args 'kafka-delete-topic-allowed.timeout=8,kafka-delete-topic-allowed.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-delete-topic-allowed:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - delete path authorized for anonymous clients
```

---

### 10. **rabbitmq-queue-messages-dump** - Queue Inventory & Backlog Analysis
**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends GET /api/queues with no Authorization header.
- On 200 decodes every queue: name, vhost, depth, consumers, flags.
- Computes backlog totals and finds dead queues with backlog.
- Grades the inventory exposure.
- Why it matters: Queue names + message counts map data flows and business volume; consumerless backlogs mark exactly where messages pile up for a denial-of-service or data-loss push. The inventory is also a targeting list for consuming or purging queues once any credential is found.
- Safety: a single read-only GET; no messages are consumed, purged or moved.

**How to Execute:**
```bash
nmap -p 15672 --script rabbitmq-queue-messages-dump mq01.corp.example.com

# Tuned request budget
nmap -p 15672 --script rabbitmq-queue-messages-dump --script-args 'rabbitmq-queue-messages-dump.timeout=8,rabbitmq-queue-messages-dump.maxrequests=48' mq01.corp.example.com
```

**Sample Output:**
```
| rabbitmq-queue-messages-dump:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - queue inventory and message counts readable without credentials
```

---

### 11. **rabbitmq-tls-auth-enforced** - TLS Enforcement & Auth Posture on 5671
**Risk Level:** 🟠 HIGH | **Category:** defensive, safe

**What it checks:**
- Sends a TLS ClientHello and grades the negotiated version.
- Sends the AMQP header in cleartext to test fallback refusal.
- Runs one guest/guest handshake to check auth enforcement.
- Grades the combined TLS+auth posture.
- Why it matters: A 5671 listener that still answers cleartext AMQP or negotiates TLS 1.0 gives attackers the encryption-bypass they hope for. TLS without auth enforcement is theater: guest/guest over strong TLS is still total broker compromise.
- Safety: one ClientHello, one 8-byte cleartext probe, one default-credential attempt with immediate close; nothing else.

**How to Execute:**
```bash
nmap -p 5671 --script rabbitmq-tls-auth-enforced mq01.corp.example.com

# Tuned request budget
nmap -p 5671 --script rabbitmq-tls-auth-enforced --script-args 'rabbitmq-tls-auth-enforced.timeout=8,rabbitmq-tls-auth-enforced.maxrequests=48' mq01.corp.example.com
```

**Sample Output:**
```
| rabbitmq-tls-auth-enforced:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - TLS listener does not enforce modern TLS-only authenticated access
```

---

### 12. **kafka-plain-auth-over-cleartext** - SASL PLAIN over Cleartext Listener
**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Handshakes SaslHandshake on the connected listener.
- Checks whether PLAIN is in the mechanism list.
- Classifies the transport (plaintext vs TLS listener) from the port.
- Grades the credential-exposure combination.
- Why it matters: PLAIN over PLAINTEXT hands every on-path observer the exact bytes of a working credential pair. Defenders need per-listener visibility: a broker can enforce TLS on 9093 while still exposing a wide-open legacy 9092.
- Safety: one handshake frame; no authentication is attempted and no credential material is ever transmitted.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-plain-auth-over-cleartext broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-plain-auth-over-cleartext --script-args 'kafka-plain-auth-over-cleartext.timeout=8,kafka-plain-auth-over-cleartext.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-plain-auth-over-cleartext:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - no cleartext-credential mechanism detected on this listener
```

---

### 13. **kafka-sasl-mechanism-audit** - SASL Mechanism Enumeration & Grading
**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Sends SaslHandshake (key 17) with the PLAIN probe mechanism.
- Decodes the advertised mechanism list or the error state.
- Grades mechanisms (SCRAM-SHA-512 ... PLAIN) with a strength class.
- Reports the posture without ever sending credentials.
- Why it matters: The mechanism list tells you whether credentials can cross the wire in the clear (PLAIN without TLS) and whether the broker supports modern SCRAM variants. ILLEGAL_SASL_STATE proves the listener has no SASL at all - the root finding for every downstream Kafka attack.
- Safety: exactly one handshake frame; no SaslAuthenticate, no credential material, no brute force.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-sasl-mechanism-audit broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-sasl-mechanism-audit --script-args 'kafka-sasl-mechanism-audit.timeout=8,kafka-sasl-mechanism-audit.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-sasl-mechanism-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - SASL is not enabled on this listener
```

---

### 14. **kafka-broker-fingerprint** - Broker Version Fingerprint (ApiVersions Floor)
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends ApiVersions (key 18) and records every API key range.
- Infers the version floor from first-introduced API keys.
- Sends wildcard Metadata to enumerate brokers and the controller.
- Maps the floor to era advisories.
- Why it matters: Kafka does not expose a version string pre-auth; the ApiVersions table is the only fingerprint, and each API key's first appearance pins the release line. Era advisories (JAAS/JNDI injection patterns, missing hostname verification fixes) turn the fingerprint into an upgrade priority.
- Safety: two read-only frames.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-broker-fingerprint broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-broker-fingerprint --script-args 'kafka-broker-fingerprint.timeout=8,kafka-broker-fingerprint.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-broker-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - fingerprint collected; era advisories matched
```

---

### 15. **kafka-controller-epoch-leak** - Cluster Topology & Controller Disclosure
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends wildcard Metadata (key 3) anonymously.
- Resolves the controller node id to a broker endpoint.
- Builds the leader distribution across observed partitions.
- Reports topology with an INFO-grade finding.
- Why it matters: The controller broker is the brain of the cluster; knowing its id and address focuses targeted disruption (controlled shutdown abuse, metadata flooding). Leader distribution is an operational health signal defenders can compare against rebalance expectations.
- Safety: a single metadata read; no leadership changes, no reassignments, no produce or consume traffic.

**How to Execute:**
```bash
nmap -p 9092 --script kafka-controller-epoch-leak broker01.corp.example.com

# Tuned request budget
nmap -p 9092 --script kafka-controller-epoch-leak --script-args 'kafka-controller-epoch-leak.timeout=8,kafka-controller-epoch-leak.maxrequests=48' broker01.corp.example.com
```

**Sample Output:**
```
| kafka-controller-epoch-leak:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - cluster topology collected
```

---

### 16. **rabbitmq-amqp-protocol-handshake** - AMQP 0-9-1 Handshake Fingerprint
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends the AMQP protocol header (AMQP\0\0\x09\x01).
- Decodes connection.start: version, product, mechanisms, locales.
- Maps the broker version to advisories.
- Closes politely with connection.close and checks close-ok.
- Why it matters: connection.start discloses product, version, platform and the SASL mechanism list before any credential is sent - everything needed to pick the right attack or the right upgrade path. Version-to-advisory mapping flags managers still exposed with CVE-carrying release lines (management XSS, frame DoS lineages).
- Safety: one unauthenticated handshake plus a graceful close; no credentials, no channels, no queue operations.

**How to Execute:**
```bash
nmap -p 5672 --script rabbitmq-amqp-protocol-handshake mq01.corp.example.com

# Tuned request budget
nmap -p 5672 --script rabbitmq-amqp-protocol-handshake --script-args 'rabbitmq-amqp-protocol-handshake.timeout=8,rabbitmq-amqp-protocol-handshake.maxrequests=48' mq01.corp.example.com
```

**Sample Output:**
```
| rabbitmq-amqp-protocol-handshake:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - AMQP handshake fingerprint collected
```

