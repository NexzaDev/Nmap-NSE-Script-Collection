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
| KERBEROS | 🟡 in progress (11 / 16) | 5 CRITICAL/HIGH scripts at spec depth plus 6 MEDIUM/LOW in the 500-800 band; 11 suites, 80 integration scenarios, 0 failed assertions |
| LDAP, SMB, RDP, ICS-SCADA, KUBERNETES, SSH, SNMP, NFS-RPC, … | ⬜ not started | still placeholder scripts; see `docs/AUDIT.md` |

## Completed scripts

`node tools/coverage.js` reports 11 scripts meeting both contracts (depth rule and
a wired integration scenario) out of 432, all of them in KERBEROS.

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
| `KERBEROS/kerberos-kpasswd-service.nse` | 🟡 MEDIUM | 800 | `nselib/kerberos5.lua` | RFC 3244 password service probe on 464 with its own two byte framing; synthetic AP-REQ for `kadmin/changepw` (AP-REP answer = HIGH finding); result-code decoding from the KRB-PRIV reply (success code before authentication = HIGH); version field negotiation (0xff80 vs 0xff81); per-transport measurement; 8 scenarios |

```bash
node tools/syntax-check.js --depth        # exit 1 while any script breaches its class
```

| Class | Contract | Meeting it now | Still to rewrite |
|---|---|---:|---:|
| CRITICAL | ≥ 1,538 lines | 3 (asrep-roasting 1,563; cve-2020-1472-prep 1,656; weak-encryption 1,666) | 94 |
| HIGH | ≥ 1,538 lines | 2 (spn-probe 1,565; user-enum 1,567) | 68 |
| MEDIUM | 500–800 lines | 3 (preauth-required 786; time-skew-audit 796; kpasswd-service 800) | 121 |
| LOW | 500–800 lines | 3 (etype-negotiation 779; realm-discovery 798; tcp-udp-support 798) | 60 |

421 of the 432 scripts in the tree breach the depth rule for their class. The
eleven that do not are the scripts rewritten so far; the gate is deliberately
failing until the rest catch up, so the number cannot silently regress.

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
