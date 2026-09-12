# 🔬 Baseline Audit — measured state of the collection

> **Method.** Every figure in this document is produced by the repository's own
> verification harness, never typed by hand:
>
> ```bash
> node tools/syntax-check.js --json=/tmp/audit.json   # compile + contract checks
> node tools/repo-stats.js                            # per-category line counts
> ```
>
> Audit date: **2026-09-12** — baseline commit `7540170` (`main`), branch
> `arena/01a09679-nmap-nse-script-collection`.

## 1. Verification harness

`tools/syntax-check.js` compiles every `*.nse` file with **two independent
Lua 5.3 front-ends**:

| Stage | Engine | What it proves |
|---|---|---|
| Compile | `fengari` — a faithful JS port of the Lua 5.3 VM, driven through `luaL_loadstring()` | the file is accepted by the *real* Lua 5.3 compiler, exactly as `nmap --script` would load it |
| Parse | `luaparse` (`luaVersion: "5.3"`) | a second, independent grammar implementation agrees |
| Contract | regex/AST checks | required NSE fields (`description`, `author`, `license`, `categories`, `portrule`/`hostrule`, `action`), legal NSE categories, no placeholder markers, LF-only, no tabs, no trailing whitespace |
| Functionality | I/O primitive detection + fabrication detection | the script actually opens sockets / crafts packets, and does not emit canned "AUDITED — check executed successfully" strings |

Exit code is `0` only when every script compiles **and** clears the contract.
This is the CI gate for the whole repository.

## 2. Complaints found in the baseline

| Finding | Measured value |
|---|---:|
| Scripts that compile cleanly (syntax) | 432 / 432 |
| Scripts that perform **real network I/O** | **103 / 432** |
| Scripts that are non-functional stubs (canned output, no I/O) | **329 / 432** |
| Scripts emitting fabricated `"AUDITED - … executed successfully."` results | 320 |
| Categories with **zero** functional scripts | 20 / 27 |
| Scripts < 60 lines ("stub" band) | 331 |
| Scripts 61–300 lines ("shallow" band) | 101 |
| Scripts ≥ 301 lines ("focused"/"deep"/"spec-depth" bands) | **0** |
| Total lines of Lua | 26,617 (measured on this branch) |
| Average lines per script | 42 |

### The depth contract, measured

The repository's stated depth rules (Critical/High ≥ 1,538 lines, Medium/Low
500–800 lines) are now checked by the harness instead of being treated as
aspirations. Each rewritten script declares its class with a machine-readable
marker and `tools/syntax-check.js --depth` (or `NSE_DEPTH_CONTRACT=1`) verifies
the line count against it:

```bash
$ node tools/syntax-check.js --depth --quiet
 depth contract checked : 432 (430 breach(es))
$ echo $?
1
```

| Measurement (baseline commit) | Value |
|---|---:|
| Scripts with ≥ 500 lines | **2 / 432** |
| Scripts with ≥ 1,538 lines | **2 / 432** |
| CRITICAL scripts meeting ≥ 1,538 | 0 / 105 |
| HIGH scripts meeting ≥ 1,538 | 0 / 72 |
| MEDIUM scripts meeting 500–800 | 0 / 130 |
| LOW scripts meeting 500–800 | 0 / 68 |
| Lowest line count in the collection | 19 |
| Highest | 1,566 (the two rewritten KERBEROS scripts) |

The two scripts that satisfy the contract are the KERBEROS scripts rewritten in
this branch; every other script in the collection is below both thresholds, and
430 of 432 breach the rule for their declared class. The gate exits non-zero in
`--depth` mode precisely so this cannot be forgotten: the exit code drops to 0
only when the rewrite reaches the whole collection.

### The dominant defect

320 scripts share a single template whose entire `action` function is:

```lua
action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-auth-option-bypass.nse check executed successfully."
  return out
end
```

Nothing is sent on the wire; the output is a constant. An operator running these
gets a green dashboard and zero signal — the exact failure mode this collection
exists to prevent. `Risk Level`, `Protocol` and `Status` are the only keys ever
produced, and `Status` is identical regardless of what the target actually is.

A further defect affects the 101 "shallow" scripts: their `description` field
promises protocol work that the implementation does not perform (e.g.
`TELNET/telnet-iac-buffer-overflow.nse` advertises IAC buffer-overflow probing
while returning the constant above).

## 3. Per-category baseline

| Category | Scripts | Lines | Avg/script | Network-functional | CRITICAL/HIGH | MEDIUM/LOW | Depth band distribution |
|---|---:|---:|---:|---:|---:|---:|---|
| CLOUD-SSRF | 16 | 320 | 20 | 0 | 10 | 6 | stub:16 |
| DATABASE | 16 | 1230 | 77 | 14 | 6 | 1 | stub:7, shallow:9 |
| DNS | 16 | 1478 | 92 | 10 | 3 | 4 | stub:7, shallow:9 |
| DOCKER | 16 | 1552 | 97 | 14 | 7 | 9 | stub:1, shallow:15 |
| ELASTICSEARCH | 16 | 320 | 20 | 0 | 9 | 7 | stub:16 |
| FTP | 16 | 1220 | 76 | 9 | 4 | 3 | stub:7, shallow:9 |
| GRAPHQL | 16 | 1342 | 84 | 11 | 6 | 10 | shallow:16 |
| HTTP | 16 | 1671 | 104 | 16 | 4 | 2 | stub:5, shallow:11 |
| ICS-SCADA | 16 | 320 | 20 | 0 | 8 | 8 | stub:16 |
| KAFKA-AMQP | 16 | 320 | 20 | 0 | 11 | 5 | stub:16 |
| KERBEROS | 16 | 320 | 20 | 0 | 8 | 8 | stub:16 |
| KUBERNETES | 16 | 320 | 20 | 0 | 8 | 8 | stub:16 |
| LDAP | 16 | 320 | 20 | 0 | 10 | 6 | stub:16 |
| MEMCACHED | 16 | 320 | 20 | 0 | 7 | 9 | stub:16 |
| MQTT | 16 | 1631 | 102 | 13 | 6 | 10 | stub:2, shallow:14 |
| NFS-RPC | 16 | 320 | 20 | 0 | 7 | 9 | stub:16 |
| NTP | 16 | 320 | 20 | 0 | 6 | 10 | stub:16 |
| RDP | 16 | 320 | 20 | 0 | 5 | 11 | stub:16 |
| SIP | 16 | 320 | 20 | 0 | 8 | 8 | stub:16 |
| SMB | 16 | 860 | 54 | 9 | 4 | 3 | stub:7, shallow:9 |
| SMTP | 16 | 320 | 20 | 0 | 6 | 10 | stub:16 |
| SNMP | 16 | 320 | 20 | 0 | 7 | 9 | stub:16 |
| SSH | 16 | 320 | 20 | 0 | 7 | 9 | stub:16 |
| SSL-TLS | 16 | 1499 | 94 | 7 | 4 | 3 | stub:7, shallow:9 |
| TELNET | 16 | 320 | 20 | 0 | 6 | 10 | stub:16 |
| VNC | 16 | 320 | 20 | 0 | 7 | 9 | stub:16 |
| WEBSOCKET | 16 | 320 | 20 | 0 | 5 | 11 | stub:16 |
| **TOTAL** | **432** | **18,243** | **42** | **103** | **179** | **198** | **stub:331, shallow:101** |

## 4. Standing rules for the rewrite

1. **Measurement over assertion.** README line counts are regenerated from the
   tree (`node tools/repo-stats.js`); a claim that is not measured does not ship.
2. **No padding.** A script's length must come from protocol tables, parser
   branches, retry/timeout handling, payload matrices and reporting depth that
   the protocol actually justifies. A script that needs 380 lines gets 380
   lines; it never gets 1,600 lines of filler to satisfy a quota, and it never
   gets a 1,538-line quota ticked with duplicated tables.
3. **No stubs, ever.** Every `action` must send bytes to the target and derive
   its output from the target's response. Canned findings are a hard CI failure.
4. **Safe by construction.** Vulnerability *confirmation* and auditing only:
   bounded probes, no destructive payloads, no exploitation, no post-exploit
   persistence. Every state-changing probe stays behind an explicit
   `--script-args` opt-in.
5. **Honest depth labels.** Each script documents the depth it actually
   reaches: `probe`, `audit`, or `deep-audit` (full protocol state machine +
   signature database + remediation guidance).
