# 🔄 Rewrite progress — measured

This file is the running ledger for the rewrite that replaces the 320
placeholder scripts (see `docs/AUDIT.md`) with real implementations, category by
category, in risk order.

Reproduce every number below:

```bash
node tools/syntax-check.js                                   # compile + contract gate
for f in tools/tests/*.test.js; do node tools/nse-sim.js "$f"; done   # behaviour
node tools/repo-stats.js                                     # line counts per category
```

## Status by category

The coverage tracker answers "what is left, per script" without any hand
maintained list:

```bash
node tools/coverage.js          # summary per category
node tools/coverage.js --all    # one line per script: risk, lines, required band, gaps
```

| Category | Status | Notes |
|---|---|---|
| KERBEROS | 🟡 in progress (13 / 16) | 6 CRITICAL/HIGH scripts at spec depth plus 7 MEDIUM/LOW in the 500-800 band; 13 suites, 95 integration scenarios, 0 failed assertions |
| KAFKA-AMQP | 🟡 in progress (7 / 16) | 5 CRITICAL/HIGH scripts at spec depth (`kafka-metadata-topic-leak.nse` 2,307, `kafka-unauth-broker-access.nse` 1,724, `kafka-create-topic-allowed.nse` 1,574, `kafka-anonymous-consumer-group.nse` 1,572, `kafka-delete-topic-allowed.nse` 1,556) plus two LOW scripts (`kafka-controller-epoch-leak.nse` 800, `kafka-broker-fingerprint.nse` 753) on top of the 3,085-line `nselib/kafka.lua` wire engine and its 1,240-line mock; 9 suites, 71 integration scenarios, 0 failed assertions |
| LDAP, SMB, RDP, ICS-SCADA, KUBERNETES, SSH, SNMP, NFS-RPC, … | ⬜ not started | still placeholder scripts; see `docs/AUDIT.md` |

## Completed scripts

`node tools/coverage.js` reports 20 scripts meeting both contracts (depth rule and
a wired integration scenario) out of 432: 13 in KERBEROS and 7 in KAFKA-AMQP.
The integration battery is 22 suites and 166 scenarios with 0 failed assertions,
and `node tools/syntax-check.js` compiles 435 files (435 OK, 0 errors) with 126 of
them performing real network I/O.

| Script | Risk | Lines | Shared engine | Verified behaviour |
|---|---|---:|---|---|
| `KERBEROS/kerberos-asrep-roasting.nse` | 🔴 CRITICAL | 1,563 | `nselib/kerberos5.lua` | real AS-REQ → AS-REP/KRB-ERROR exchange; realm-leak retry; KDC error classification; PA-ETYPE-INFO2 policy extraction; lockout abort; UDP→TCP fallback on `KRB_ERR_RESPONSE_TOO_BIG`; crack-cost model; masked hashes by default; probe transcript; detection, verification and remediation guidance |
| `KERBEROS/kerberos-user-enum.nse` | 🟠 HIGH | 1,567 | `nselib/kerberos5.lua` | authoritative KDC error-code decision table; calibrated baselines; confidence model (error code + fingerprint + RTT); pacing, jitter and lockout guard; wordlist support; privileged-name heuristics; log-footprint and lockout-semantics reporting |
| `KERBEROS/kerberos-spn-probe.nse` | 🟠 HIGH | 1,566 | `nselib/kerberos5.lua` | TGS-REQ/AP-REQ construction; SPN lookup-path oracle with a calibration probe that detects normalising KDCs; service class catalogue with product mapping and value ranking; supplied-ticket inspection (shape, realm, etype, mismatch warnings); class-specific guidance, attack chains, KDC implementation behaviour table, verification recipes |
| `KERBEROS/kerberos-time-skew-audit.nse` | 🟡 MEDIUM | 796 | `nselib/kerberos5.lua` | multi-sample Kerberos clock measurement with RTT correction; a real RFC 5905 SNTP client (4-timestamp algorithm, stratum/root delay/dispersion decoding); cross-check that attributes drift to the KDC rather than the scanner; grading against the Kerberos skew tolerance with headroom reporting; platform remediation (w32tm, chrony, ntpd, timesyncd) |
| `KERBEROS/kerberos-weak-encryption.nse` | 🔴 CRITICAL | 1,666 | `nselib/kerberos5.lua` | one full AS-REQ negotiation per etype in the catalogue; ACCEPTED/REFUSED/UNDETERMINED classification with evidence; PA-ETYPE-INFO2 and PA-SUPPORTED-ENCTYPES decoding; msDS-SupportedEncryptionTypes mapping; offline attack cost model; platform policy matrix; CVE, detection and verification guidance |
| `KERBEROS/kerberos-cve-2020-1472-prep.nse` | 🔴 CRITICAL | 1,656 | `nselib/netlogon.lua` + `nselib/kerberos5.lua` | Kerberos characterisation phase (realm leak, etype policy, machine-account oracle with a `krbtgt` calibration) followed by a real MS-NRPC probe: SMB2 negotiate/session/tree/CREATE on `\pipe\netlogon`, DCE/RPC bind to the Netlogon interface, `NetrServerReqChallenge` then `NetrServerAuthenticate3` with an all-zero credential and a second measurement with the Secure RPC bit offered; ACCEPTS-ANY-CREDENTIAL → CRITICAL + `vulns.add`, DOWNGRADE_DETECTED / patched / refused → LOW, unreachable → MEDIUM; the control credential is only sent after a first acceptance; opnum 30 (password set) is never marshalled; the server credential is printed masked; 14 integration scenarios passing |
| `KERBEROS/kerberos-realm-discovery.nse` | 🟢 LOW | 798 | `nselib/kerberos5.lua` | foreign-realm leak probe, candidate matrix from the target name, KDC_ERR_WRONG_REALM redirect handling, confidence grading and per-code verdict table; 6 scenarios |
| `KERBEROS/kerberos-etype-negotiation.nse` | 🟢 LOW | 779 | `nselib/kerberos5.lua` | one AS-REQ per encryption type; accepted / refused / undecided verdicts from AS-REP, error 14 and the PA-ETYPE-INFO2 list inside error 24/25 answers; whole-catalogue preference probe; DES and RC4 findings; 7 scenarios |
| `KERBEROS/kerberos-tcp-udp-support.nse` | 🟢 LOW | 798 | `nselib/kerberos5.lua` | UDP and TCP exchanges of the same AS-REQ; RFC 4120 7.2.2 length-prefix validation on every frame; connection reuse across a configurable number of messages; KRB_ERR_RESPONSE_TOO_BIG (52) fallback; the engine's own transport used as a second, independent observation; transport-blocked, framing-defect and disagreement findings; 6 scenarios |
| `KERBEROS/kerberos-preauth-required.nse` | 🟡 MEDIUM | 786 | `nselib/kerberos5.lua` | one AS-REQ per account carrying no padata at all; exempt / covered / unknown / revoked classification with a calibration name that proves the KDC is not answering uniformly; PA-ETYPE-INFO2 salt extraction; lockout-aware abort; account-list file support; optional AS-REP material with masked output by default; 7 scenarios |
| `KERBEROS/kerberos-pac-validation.nse` | 🟠 HIGH | 1,566 | `nselib/kerberos5.lua` | one AS-REQ per encryption type for the machine account plus a `krbtgt` calibration oracle; PA-SUPPORTED-ENCTYPES mask decoding and an agreement check against the per-type answers; ticket facts read from issued AS-REPs (service principal, realm, etype, key version) with an AS-REP-without-pre-auth finding; an eight-entry padata capability matrix (PKINIT, S4U, FAST, cookie, PAC request); repeat sampling that detects a pool of controllers behind one name; an explicit method-limits section and the registry switches that decide what a client cannot see; 8 scenarios |
| `KERBEROS/kerberos-fast-negotiation.nse` | 🟡 MEDIUM | 730 | `nselib/kerberos5.lua` | RFC 6113 negotiation: a plain AS-REQ, one carrying an unarmored PA-FX-FAST container, and a control name; PA-FX-FAST/PA-FX-COOKIE advertisement from the NEEDED_PREAUTH padata; not-supported / supported / required / inconsistent verdicts including a downgrade finding; salt-withholding detection; 7 scenarios |
| `KERBEROS/kerberos-kpasswd-service.nse` | 🟡 MEDIUM | 800 | `nselib/kerberos5.lua` | RFC 3244 password service probe on 464 with its own two byte framing; synthetic AP-REQ for `kadmin/changepw` (AP-REP answer = HIGH finding); result-code decoding from the KRB-PRIV reply (success code before authentication = HIGH); version field negotiation (0xff80 vs 0xff81); per-transport measurement; 8 scenarios |
| `KAFKA-AMQP/kafka-controller-epoch-leak.nse` | 🟢 LOW | 800 | `nselib/kafka.lua` | measures what an unauthenticated Metadata request exposes: controller identity and placement (broker or separate quorum), cluster id, broker inventory with racks, the full partition/replica/ISR map, leader epochs and offline replicas, with an honest "fields this broker version omits" list derived from the negotiated Metadata version; finds under-replicated partitions (MEDIUM, because the exposure is the availability inventory), offline replicas, leader concentration and a controller election observed while sampling; 7 scenarios |
| `KAFKA-AMQP/kafka-broker-fingerprint.nse` | 🟢 LOW | 753 | `nselib/kafka.lua` (§18) | fingerprints the broker from its own advertisement: schema-generation inference from API-version markers (classic → 0.11 → the 2.4 flexible family → the KRaft-aware admin APIs), KRaft-versus-ZooKeeper evidence from DescribeCluster placement and endpoint types, broker inventory with racks and controller placement, platform markers matched against the internal topics that actually exist (Schema Registry, Connect, Strimzi, MSK, Confluent, transactions), SASL posture from the handshake plus the refusal behaviour, quota enforcement from reported throttle times, and a configuration section that prints names and sensitivity but never values; 8 scenarios |
| `KAFKA-AMQP/kafka-metadata-topic-leak.nse` | 🔴 CRITICAL | 2,307 | `nselib/kafka.lua` | full Metadata census over a real wire exchange: null-topic listing, per-name re-query for the authorization boundary, a generated-name probe with `allow_auto_topic_creation=false` that separates an existence oracle from an authorization-first refusal, DescribeConfigs for broker and topic settings with byte/duration rendering and sensitive-value detection, and DescribeCluster; findings for the inventory (CRITICAL), internal-topic exposure with a per-topic meaning table (`__consumer_offsets` = coordinator count, `__transaction_state`, `__cluster_metadata`, `_schemas`, Connect), configuration and secret disclosure, sensitive topic names, replica topology, topic ids, operation masks, listing-vs-ACL inconsistency, under-replication/offline/ISR-less partitions and leader concentration, plus the `kafka.names` argument that finds a topic the listing hides; 12 integration scenarios |
| `KAFKA-AMQP/kafka-create-topic-allowed.nse` | 🟠 HIGH | 1,574 | `nselib/kafka.lua` | measures the creation permission without ever creating anything: every CreateTopics carries `validate_only=true`, the error code is interpreted as proof of the authorization check (a validation error means the ACL let the request through, because Kafka authorizes before validating), a variant matrix sweeps partitions x replication x a configuration override, a second name confirms that the grant generalises, and the probe name is checked before and after; a pre-0.11 broker is never sent a creating request (the script names an existing topic and reads TOPIC_ALREADY_EXISTS); findings for anonymous create, ACL-refused create, validation-only refusal, a topic created in spite of the flag (CRITICAL), auto-creation, weak new-topic defaults and an observed quota; 13 integration scenarios |
| `KAFKA-AMQP/kafka-delete-topic-allowed.nse` | 🟠 HIGH | 1,556 | `nselib/kafka.lua` | measures the deletion permission without deleting anything: DeleteTopics is only ever asked about names the script generated and verified absent, the v6 topic-id form is exercised with a random id, and DeleteRecords is sent with offset 0 on a bounded sample of existing topics - below every log start offset, so no record can be eligible while the DELETE ACL is still consulted; the topic list is read before and after and every request the engine sends is checked against the inventory, so a deletion by this scan would be reported as a critical incident rather than hidden; findings for the name path, the topic-id path, record deletion in scope, internal topics, weak defaults, controller-dependent answers and observed quotas; 12 integration scenarios |
| `KAFKA-AMQP/kafka-anonymous-consumer-group.nse` | 🔴 CRITICAL | 1,572 | `nselib/kafka.lua` | walks the consumer-group plane unauthenticated: ListGroups (with the v4 state filter), batched DescribeGroups, FindCoordinator and OffsetFetch with a null topic list, then ListOffsets to turn committed offsets into lag; decodes the opaque ConsumerProtocol bytes the broker hands out, so the report names the subscribed topics, the user data, the generation, the rack and the exact partitions each member owns; findings for anonymous group access, member identity disclosure, assignment disclosure, committed offsets, lag, double ownership, rebalance churn and the coordinator map; 9 integration scenarios |
| `KAFKA-AMQP/kafka-unauth-broker-access.nse` | 🔴 CRITICAL | 1,724 | `nselib/kafka.lua` | twelve-probe access matrix over a real Kafka wire exchange (ApiVersions version negotiation, null-topic Metadata, DescribeCluster, ListGroups, DescribeGroups, FindCoordinator, OffsetFetch, ListOffsets, DescribeConfigs, a `validate_only` CreateTopics and a generated-name DeleteTopics, SaslHandshake) plus an opt-in bounded Fetch sample; anonymous-granted, ACL-denied and unanswered requests are counted separately, a run in which nothing answered is reported as UNKNOWN rather than clean, internal topics/groups/committed offsets/sensitive configuration values are quoted as evidence, and no request in the script can change state (`validate_only=true`, delete names generated per run); 8 integration scenarios |

```bash
node tools/syntax-check.js --depth        # exit 1 while any script breaches its class
```

| Class | Contract | Meeting it now | Still to rewrite |
|---|---|---:|---:|
| CRITICAL | ≥ 1,538 lines | 6 (`kafka-metadata-topic-leak.nse` 2,307; `kafka-unauth-broker-access.nse` 1,724; `kerberos-weak-encryption.nse` 1,668; `kerberos-cve-2020-1472-prep.nse` 1,656; `kafka-anonymous-consumer-group.nse` 1,572; `kerberos-asrep-roasting.nse` 1,567) | 100 |
| HIGH | ≥ 1,538 lines | 5 (`kafka-create-topic-allowed.nse` 1,574; `kerberos-user-enum.nse` 1,571; `kerberos-pac-validation.nse` 1,566; `kerberos-spn-probe.nse` 1,565; `kafka-delete-topic-allowed.nse` 1,556) | 68 |
| MEDIUM | 500–800 lines | 4 (`kerberos-kpasswd-service.nse` 800; `kerberos-time-skew-audit.nse` 796; `kerberos-preauth-required.nse` 786; `kerberos-fast-negotiation.nse` 730) | 126 |
| LOW | 500–800 lines | 5 (`kafka-controller-epoch-leak.nse` 800; `kerberos-realm-discovery.nse` 798; `kerberos-tcp-udp-support.nse` 798; `kerberos-etype-negotiation.nse` 779; `kafka-broker-fingerprint.nse` 753) | 63 |

412 of the 432 scripts in the tree breach the depth rule for their class
(`node tools/syntax-check.js --depth`, exit 1). The twenty that do not are the
scripts rewritten so far; the gate is deliberately failing until the rest catch
up, so the number cannot silently regress.

## Verification layers

1. **Compile** — `tools/syntax-check.js` compiles every `*.nse` and `nselib/*.lua`
   with the real Lua 5.3 compiler (fengari) *and* with luaparse. Exit code 0 is
   required.
2. **Contract** — required NSE fields, legal categories, no placeholder markers,
   LF-only, no tabs, and a functionality check that fails any script which emits
   a result without performing network I/O.
3. **Behaviour** — `tools/nse-sim.js` executes the script inside a Lua 5.3 VM
   with the NSE API shimmed after the published Nmap documentation, and answers
   its traffic from `tools/mocks/*.js`. The mock implements the protocol with an
   independent ASN.1 codec, so an encoder bug in a script cannot be mirrored by
   the mock. The harness also installs a wall-clock watchdog that converts an
   infinite loop into a Lua error with a stack traceback.

Harness contract emulated from <https://nmap.org/nsedoc/lib/nmap.html>:
`socket:receive()` returns `true, data` or `false, err`; `receive_bytes(n)`
returns *everything* currently buffered (which may exceed `n`) or fewer bytes
than requested. Scripts that assume exact framing fail the harness, as they
would fail against a real peer.

## Standing rules

1. Measurements over assertions — no statistic in the documentation is typed by
   hand.
2. No padding — length must come from protocol tables, parsers, retries and
   reporting depth the protocol justifies.
3. No stubs — every `action` must send bytes and derive output from the answer.
4. Read-only probes, with destructive or lockout-prone actions behind explicit
   opt-in and an abort path.
