# 🔄 Rewrite progress — measured

This file is the running ledger for the rewrite that replaces the 320
placeholder scripts (see `docs/AUDIT.md`) with real implementations, category by
category, in risk order.

Reproduce every number below:

```bash
node tools/syntax-check.js                                   # compile + contract gate
node tools/nse-sim.js tools/tests/kerberos-asrep-roasting.test.js
node tools/nse-sim.js tools/tests/kerberos-user-enum.test.js
node tools/nse-sim.js tools/tests/kerberos-weak-encryption.test.js
node tools/repo-stats.js                                     # line counts per category
```

## Status by category

| Category | Status | Notes |
|---|---|---|
| KERBEROS | 🟡 in progress (3 / 16) | `kerberos-asrep-roasting`, `kerberos-user-enum`, `kerberos-weak-encryption` rewritten and verified; 19 integration scenarios pass |
| LDAP, SMB, RDP, ICS-SCADA, KUBERNETES, SSH, SNMP, NFS-RPC, … | ⬜ not started | still placeholder scripts; see `docs/AUDIT.md` |

## Completed scripts

| Script | Risk | Lines | Shared engine | Verified behaviour |
|---|---|---:|---|---|
| `KERBEROS/kerberos-asrep-roasting.nse` | 🔴 CRITICAL | 1,563 | `nselib/kerberos5.lua` | real AS-REQ → AS-REP/KRB-ERROR exchange; realm-leak retry; KDC error classification; PA-ETYPE-INFO2 policy extraction; lockout abort; UDP→TCP fallback on `KRB_ERR_RESPONSE_TOO_BIG`; crack-cost model; masked hashes by default; probe transcript; detection, verification and remediation guidance |
| `KERBEROS/kerberos-user-enum.nse` | 🟠 HIGH | 1,567 | `nselib/kerberos5.lua` | authoritative KDC error-code decision table; calibrated baselines; confidence model (error code + fingerprint + RTT); pacing, jitter and lockout guard; wordlist support; privileged-name heuristics; log-footprint and lockout-semantics reporting |
| `KERBEROS/kerberos-weak-encryption.nse` | 🔴 CRITICAL | 1,666 | `nselib/kerberos5.lua` | one full AS-REQ negotiation per etype in the catalogue; ACCEPTED/REFUSED/UNDETERMINED classification with evidence; PA-ETYPE-INFO2 and PA-SUPPORTED-ENCTYPES decoding; msDS-SupportedEncryptionTypes mapping; offline attack cost model; platform policy matrix; CVE, detection and verification guidance |

## Depth contract status

```bash
node tools/syntax-check.js --depth        # exit 1 while any script breaches its class
```

| Class | Contract | Meeting it now | Still to rewrite |
|---|---|---:|---:|
| CRITICAL | ≥ 1,538 lines | 2 (asrep-roasting, weak-encryption) | 104 |
| HIGH | ≥ 1,538 lines | 1 (user-enum) | 72 |
| MEDIUM | 500–800 lines | 0 | 130 |
| LOW | 500–800 lines | 0 | 68 |

429 of the 432 scripts in the tree breach the depth rule for their class. The
two that do not are the scripts rewritten so far; the gate is deliberately
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
