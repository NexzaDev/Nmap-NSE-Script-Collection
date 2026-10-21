# 🔮 GraphQL Security Audits

**16 Nmap NSE scripts** for auditing GraphQL endpoints:

**Covers:**

- Unauthenticated full-schema introspection
- Unauthenticated mutation execution (and GET-delivered mutations that bypass POST-keyed WAF/CDN/CSRF controls)
- Unlimited alias overloading and query depth (including cyclic-type amplification)
- Batched-query DoS
- Error/debug information disclosure (stack traces, file paths, database hints, trace headers)
- Relaxed Content-Type enforcement
- Missing cost/complexity analysis
- "Did you mean" suggestion oracles
- Exposed interactive IDEs (GraphiQL/Playground)
- Active Persisted Queries registry exposure
- Non-standard directive leakage via introspection
- Unauthenticated realtime subscription channels (WebSocket `graphql-transport-ws` + Server-Sent Events) - plus a comprehensive endpoint-discovery map of paths
- Methods
- Transports and IDEs

Every script performs real HTTP/WS requests against a discovered or user-supplied endpoint, parses the GraphQL wire format, and reports evidence-based findings.

All probes are read-only or use dummy/harmless payloads; nothing is mutated on a real target.

**Ports:** any HTTP/HTTPS port serving GraphQL (80, 443, 3000, 4000, 8000, 8080, 8443, 8888, 9000 or matched `http`/`https`/`graphql` service) | **Protocol:** GraphQL over HTTP (JSON bodies, persisted-query extensions, SSE, RFC 6455 WebSocket with graphql-transport-ws/graphql-ws subprotocols) | **Total lines of Lua:** 35,261

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [graphql-alias-overloading](#1-graphql-alias-overloading---unlimited-alias-fan-out) | 🔴 CRITICAL | vuln, safe | 2128 |
| 2 | [graphql-batch-query-abuse](#2-graphql-batch-query-abuse---batched-query-dos) | 🔴 CRITICAL | vuln, safe | 2148 |
| 3 | [graphql-introspection-enabled](#3-graphql-introspection-enabled---unauthenticated-schema-introspection) | 🔴 CRITICAL | vuln, discovery, safe | 2320 |
| 4 | [graphql-unauth-mutation-detection](#4-graphql-unauth-mutation-detection---unauthenticated-mutation-execution) | 🔴 CRITICAL | vuln, discovery, safe | 2180 |
| 5 | [graphql-circular-query-depth](#5-graphql-circular-query-depth---unbounded-depth-and-cyclic-types) | 🟠 HIGH | vuln, safe | 2188 |
| 6 | [graphql-get-mutation-bypass](#6-graphql-get-mutation-bypass---mutations-over-http-get) | 🟠 HIGH | vuln, safe | 2159 |
| 7 | [graphql-content-type-bypass](#7-graphql-content-type-bypass---relaxed-content-type-enforcement) | 🟡 MEDIUM | vuln, safe | 2162 |
| 8 | [graphql-cost-analysis-bypass](#8-graphql-cost-analysis-bypass---missing-complexity-analysis) | 🟡 MEDIUM | vuln, safe | 2166 |
| 9 | [graphql-debug-trace-exposure](#9-graphql-debug-trace-exposure---debug-mode-and-trace-headers) | 🟡 MEDIUM | vuln, discovery, safe | 2298 |
| 10 | [graphql-error-info-disclosure](#10-graphql-error-info-disclosure---errordebug-information-leaks) | 🟡 MEDIUM | vuln, discovery, safe | 2348 |
| 11 | [graphql-field-suggestions](#11-graphql-field-suggestions---did-you-mean-enumeration-oracle) | 🟡 MEDIUM | vuln, discovery, safe | 2144 |
| 12 | [graphql-ide-exposure](#12-graphql-ide-exposure---graphiqlplayground-exposure) | 🟡 MEDIUM | vuln, discovery, safe | 2131 |
| 13 | [graphql-persisted-queries-audit](#13-graphql-persisted-queries-audit---apq-registry-exposure) | 🟡 MEDIUM | vuln, discovery, safe | 2144 |
| 14 | [graphql-schema-directive-leak](#14-graphql-schema-directive-leak---non-standard-directive-leakage) | 🟡 MEDIUM | vuln, discovery, safe | 2230 |
| 15 | [graphql-subscription-websocket](#15-graphql-subscription-websocket---unauthenticated-realtime-channels) | 🟡 MEDIUM | vuln, discovery, safe | 2216 |
| 16 | [graphql-endpoint-discovery](#16-graphql-endpoint-discovery---attack-surface-inventory) | 🟢 LOW | discovery, safe | 2299 |

---

### 1. **graphql-alias-overloading** - Unlimited Alias Fan-out
**Description:** Tests whether the endpoint limits the number of aliases (repeated field selections) in a single operation. Unbounded aliasing lets one request amplify resolver work N-fold behind per-request rate limiters - a classic GraphQL DoS.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Alias-count ladder (10 / 40 / 120 / 150) on a cheap field (`__typename`) and on a typed field (`user`)
- Verdict per level: accepted / limited (with the limiting error code) / rejected
- Unbounded detection: ≥100 aliases accepted with no complexity error
- Amplification note when accepted aliases are unbounded

**How to Execute:**
```bash
nmap -p 8000 --script graphql-alias-overloading target.example.com
nmap -p 8000 --script graphql-alias-overloading --script-args 'graphql-alias-overloading.path=/graphql' target.example.com
```

**Sample Output:**
```
| graphql-alias-overloading:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Alias count is not limited on this endpoint
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=1
|   Findings:
|     [HIGH] Queries with more than 100 aliases are accepted without rejection
|     [MEDIUM] Single request can amplify resolver load N-fold behind a per-request rate limit
```

---

### 2. **graphql-batch-query-abuse** - Batched Query DoS
**Description:** Determines whether the endpoint accepts JSON-array batches of operations, how many it executes in one HTTP request, and whether any size ceiling exists. Batching converts per-request rate limits into per-batch limits and multiplies backend work per request.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Control single query, then batch of 2, then batch of 16 cheap operations
- Response-element counting to measure the actually executed batch size
- States: batched (n executed) / disabled (BATCH_DISABLED) / rejected / single-only
- Implicit-ceiling detection from truncation, amplification note

**How to Execute:**
```bash
nmap -p 8000 --script graphql-batch-query-abuse target.example.com
nmap -p 8000 --script graphql-batch-query-abuse --script-args 'graphql-batch-query-abuse.batch_size=32' target.example.com
```

**Sample Output:**
```
| graphql-batch-query-abuse:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Batched queries are enabled without a visible size limit
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=1 INFO=1
|   Findings:
|     [MEDIUM] The endpoint executes 16 operations in a single HTTP request (batching)
|     [LOW] One request performs 16x the resolver work of a normal query (rate limit amplification)
```

---

### 3. **graphql-introspection-enabled** - Unauthenticated Schema Introspection
**Description:** Detects whether the full GraphQL schema is readable without authentication, and audits what the exposed schema contains: sensitive field names (PII/financial/credential patterns), type/field descriptions that leak internal implementation details, directive lists, and cyclic type references.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, discovery, safe

**What it checks:**
- Full introspection query (`__schema { types, directives }`) over POST and GET
- Sensitive field classification (identifier/financial/contact/biographic/credential/medical patterns)
- Description-text scanning for internal paths, service references and environment hints
- Cyclic type references (resolver-amplification preconditions)
- Introspection-disabled endpoints classified cleanly as NOT VULNERABLE

**How to Execute:**
```bash
# Auto-discover endpoint
nmap -p 8000 --script graphql-introspection-enabled target.example.com

# Pin the endpoint
nmap -p 8000 --script graphql-introspection-enabled --script-args 'graphql-introspection-enabled.path=/api/v1/graphql' target.example.com
```

**Sample Output:**
```
| graphql-introspection-enabled:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Full GraphQL schema introspection enabled without authentication
|   Severity counts: CRITICAL=1 HIGH=2 MEDIUM=2 LOW=1 INFO=1
|   Findings:
|     [CRITICAL] Complete GraphQL schema is readable without credentials (GET/POST /graphql)
|     [HIGH] Schema exposes 11 sensitive fields (PII/financial/credential)
|     [HIGH] Type/field descriptions leak internal implementation details
```

---

### 4. **graphql-unauth-mutation-detection** - Unauthenticated Mutation Execution
**Description:** Probes whether mutation resolvers execute without an authenticated session by submitting a ladder of write operations (register, login, resetPassword, deleteAccount) with dummy credentials, and separates "resolver executed" from "resolver ran but rejected the payload" so a correctly gated API is not flagged.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, discovery, safe

**What it checks:**
- POST mutations with dummy arguments: which execute with data, which return validation errors, which return auth errors
- Execution vs. validation-error classification (auth gate present or absent)
- Mutation-root reachability and operation-name enumeration surface
- 401/403 responses classified as NOT VULNERABLE (gate present)

**How to Execute:**
```bash
nmap -p 8000 --script graphql-unauth-mutation-detection target.example.com
nmap -p 8000 --script graphql-unauth-mutation-detection --script-args 'graphql-unauth-mutation-detection.maxrequests=30' target.example.com
```

**Sample Output:**
```
| graphql-unauth-mutation-detection:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Mutations execute without authentication
|   Severity counts: CRITICAL=2 HIGH=1 MEDIUM=1 LOW=0 INFO=1
|   Findings:
|     [CRITICAL] Account deletion executed without an authenticated session (Mutation.deleteAccount)
|     [CRITICAL] Password reset executed without an authenticated session (Mutation.resetPassword)
|     [HIGH] Write surface has no authentication gate; data integrity is exposed to any client
```

---

### 5. **graphql-circular-query-depth** - Unbounded Depth and Cyclic Types
**Description:** Measures the nesting-depth ceiling with single-object cycle chains, probes list-recursive chains at shallow depth, and cross-checks the schema for cyclic type references. Unbounded depth over cyclic types is a resolver-amplification DoS channel.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Depth ladder (5 / 12 / 25 / 40) over a single-object recursive pair, plus a shallow list-recursive chain
- Verdict per level: accepted / limited (DEPTH_LIMIT_EXCEEDED and friends) / rejected
- Introspection cross-check: cyclic types (A <-> B) reachable at unbounded depth
- Measured ceiling reported when a limit exists

**How to Execute:**
```bash
nmap -p 8000 --script graphql-circular-query-depth target.example.com
```

**Sample Output:**
```
| graphql-circular-query-depth:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - Query depth is not limited on this endpoint
|   Severity counts: CRITICAL=0 HIGH=2 MEDIUM=0 LOW=0 INFO=2
|   Findings:
|     [HIGH] Nested selections beyond depth 20 execute without rejection
|     [HIGH] Recursive schema types are reachable through unbounded depth (cyclic types: Post <-> User, Organization <-> User)
```

---

### 6. **graphql-get-mutation-bypass** - Mutations over HTTP GET
**Description:** Checks whether mutations can be delivered in a GET query string (`?query=mutation {...}`) instead of a POST body. GET-delivered mutations bypass POST-keyed WAF rules, CDN body inspection and CSRF protections that assume write verbs are POST-only.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- POST control mutation (establishes that the resolver runs and how it rejects dummy credentials)
- GET probes with the same mutation in `?query=`
- Execution vs. rejection classification per transport
- 405/MUTATION_VIA_GET_BLOCKED classified as NOT VULNERABLE

**How to Execute:**
```bash
nmap -p 8000 --script graphql-get-mutation-bypass target.example.com
```

**Sample Output:**
```
| graphql-get-mutation-bypass:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - Mutations execute over HTTP GET
|   Severity counts: CRITICAL=1 HIGH=1 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [CRITICAL] Mutation executed via GET query string (1 of 2 GET probes)
|     [HIGH] GET-delivered mutations bypass POST-keyed WAF/CDN/CSRF controls
```

---

### 7. **graphql-content-type-bypass** - Relaxed Content-Type Enforcement
**Description:** Sends the same cheap query under a ladder of Content-Types (application/json, form-urlencoded, text/plain, application/xml, multipart, application/graphql) and records which execute versus which are refused with 415. Servers that parse regardless of the declared type give WAF/CDN rules - which key GraphQL inspection on the header - a blind spot.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, safe

**What it checks:**
- JSON control + five alternative Content-Types, each classified: executed / rejected-415 / rejected-400 / other
- Non-standard types that execute → enforcement-bypass finding
- Form-urlencoded-only acceptance reported as spec-conformant (GraphQL-over-HTTP allows it)

**How to Execute:**
```bash
nmap -p 8000 --script graphql-content-type-bypass target.example.com
```

**Sample Output:**
```
| graphql-content-type-bypass:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Non-standard Content-Types execute GraphQL operations
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=1 INFO=1
|   Content-Type Results:
|     text/plain: executed - HTTP 200 with data
|     application/xml: executed - HTTP 200 with data
```

---

### 8. **graphql-cost-analysis-bypass** - Missing Complexity Analysis
**Description:** Tests whether a unified cost/complexity analyzer exists by probing three delivery shapes at escalating intensity - nesting depth, alias fan-out, and batched deep queries - and builds a coverage matrix. A server that limits only one shape leaves the others as open DoS channels.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, safe

**What it checks:**
- Depth ladder (12 / 25 / 40), alias ladder (40 / 120 / 160), deep query inside a single-element batch
- Per-shape verdict: accepted / limited (with code) / rejected
- Coverage matrix → MEDIUM per uncovered shape, HIGH when no shape is covered at all
- BATCH_DISABLED treated as covered (stricter than per-element analysis)

**How to Execute:**
```bash
nmap -p 8000 --script graphql-cost-analysis-bypass target.example.com
```

**Sample Output:**
```
| graphql-cost-analysis-bypass:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - No cost or complexity analysis detected on this endpoint
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [HIGH] Depth, alias and batch shapes all execute beyond safe ceilings (no cost analysis)
```

---

### 9. **graphql-debug-trace-exposure** - Debug Mode and Trace Headers
**Description:** Triggers error responses and inspects them plus their headers for a non-null `debug` field, stack-trace content, and trace/banner headers (X-Debug, X-GraphQL-Trace, X-Powered-By, Server). Debug mode in production is a reconnaissance gift: framework, version, deployment layout and code paths all appear.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- Three error classes (syntax, unknown field, invalid enum), headers + body captured per probe
- `debug` field presence, debug-text scanning (stacks, paths, DB/env hints, PIDs, spans)
- Trace-header inventory with values; framework fingerprint from every raw response
- CRITICAL when debug payload carries implementation detail, MEDIUM for debug field/trace headers alone

**How to Execute:**
```bash
nmap -p 8000 --script graphql-debug-trace-exposure target.example.com
```

**Sample Output:**
```
| graphql-debug-trace-exposure:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Debug traces with implementation detail exposed in GraphQL errors
|   Severity counts: CRITICAL=1 HIGH=2 MEDIUM=0 LOW=0 INFO=1
|   Findings:
|     [CRITICAL] Error responses carry stack traces and internal paths in the debug field
|     [HIGH] File paths exposed in debug output
|     [HIGH] Database hints exposed in debug output
```

---

### 10. **graphql-error-info-disclosure** - Error/Debug Information Leaks
**Description:** Triggers a battery of error classes (syntax, unknown field, invalid enum, resolver failure, variable errors, introspection-refused) and scans every error object - message, `debug` field, path - plus raw body for stack traces, file paths, database hints, environment hints, PIDs, addresses, span ids and framework fingerprints.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- Six error-probe classes merged into one disclosure report
- Signature scanning: stack traces, `/var/...` paths, DB drivers (psycopg2/sqlalchemy/...), env vars, PIDs, spans
- Framework fingerprinting from error text and headers
- Sanitized-error baseline classified as NOT VULNERABLE

**How to Execute:**
```bash
nmap -p 8000 --script graphql-error-info-disclosure target.example.com
```

**Sample Output:**
```
| graphql-error-info-disclosure:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - GraphQL errors leak implementation detail
|   Severity counts: CRITICAL=2 HIGH=3 MEDIUM=2 LOW=1 INFO=1
|   Findings:
|     [CRITICAL] File system paths are disclosed in GraphQL errors
|     [CRITICAL] Stack traces are included in GraphQL error responses
|     [HIGH] Database driver/connection hints are disclosed (psycopg2, sqlalchemy)
```

---

### 11. **graphql-field-suggestions** - "Did you mean" Enumeration Oracle
**Description:** Submits a ladder of unknown-field queries (noise, near-misses of public fields, non-public name hints) and records which produce "Did you mean ..." suggestions. With introspection disabled, the suggestion engine is often the only oracle that reveals hidden field names.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- Six unknown-field probes: pure noise, three public near-misses, two non-public hints
- Suggestion extraction per error and aggregation of the oracle's output
- MEDIUM when any suggestion oracle exists (wider when non-public hints or noise produce suggestions)

**How to Execute:**
```bash
nmap -p 8000 --script graphql-field-suggestions target.example.com
```

**Sample Output:**
```
| graphql-field-suggestions:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Field suggestion engine is enabled (public name oracle)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Suggestion Probe Results:
|     near-miss: usre: suggested - HTTP 400 - Did you mean -> user
|     near-miss: ordr: suggested - HTTP 400 - Did you mean -> order
```

---

### 12. **graphql-ide-exposure** - GraphiQL/Playground Exposure
**Description:** Walks a list of IDE paths (endpoint path, /, /graphiql, /playground, /apollo, /studio, /devtools, /console, /dev) and fingerprints which interactive GraphQL IDEs are publicly served, including their page titles. IDEs embed the full schema and auto-completion - a ready-made query playground for anyone.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- HTML signature scanning (graphiql / playground / apollo / generic graphql markers)
- IDE fingerprinting per path (GraphiQL, GraphQL Playground, Apollo Sandbox) with page titles
- Console/devtools-like pages flagged at LOW; full inventory of checked paths

**How to Execute:**
```bash
nmap -p 8000 --script graphql-ide-exposure target.example.com
```

**Sample Output:**
```
| graphql-ide-exposure:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Interactive GraphQL IDE exposed: GraphiQL at /graphiql, GraphQL Playground at /playground
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=3 LOW=0 INFO=0
|   IDE Path Inventory:
|     /graphiql: EXPOSED - GraphiQL
|     /playground: EXPOSED - GraphQL Playground
```

---

### 13. **graphql-persisted-queries-audit** - APQ Registry Exposure
**Description:** Audits the Automatic Persisted Queries (APQ) feature: sends a hash-only request (real SHA-256 of a benign probe, no query body) and reads the error code - PersistedQueryNotFound proves an active registry (bypass + enumeration surface), PersistedQueryNotSupported proves the feature is off. Also checks the first-use (hash + query) path.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- Hash-only POST → registry-active / not-supported / unclassifiable
- First-use registration: does hash + query execute (queries become replayable by hash only)
- Inspection-bypass note: hash-only bodies carry no readable query text for WAF patterns
- The exact probe query and SHA-256 hash reported as evidence

**How to Execute:**
```bash
nmap -p 8000 --script graphql-persisted-queries-audit target.example.com
```

**Sample Output:**
```
| graphql-persisted-queries-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Automatic Persisted Queries registry is active (bypass + enumeration surface)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=2 INFO=1
|   Findings:
|     [MEDIUM] The endpoint maintains a persisted-query registry; hash-only requests are accepted
|     [LOW] First-use registration is allowed: a query sent once with its hash becomes replayable
```

---

### 14. **graphql-schema-directive-leak** - Non-standard Directive Leakage
**Description:** Runs a full introspection including the directive list (name, description, locations, argument defaults) and classifies every directive. Beyond the four standard directives (include, skip, deprecated, specifiedBy), custom auth/rate-limit/cache/internal directives - and their free-text descriptions - become a blueprint of platform internals.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- Full directive inventory with per-directive classification (auth / rate / cache / internal / custom / standard)
- Description + default-value scanning for implementation detail (paths, storage hints, framework names)
- HIGH per directive carrying detail, MEDIUM for the non-standard set itself
- Introspection-disabled endpoints → audit limitation (INFO), NOT VULNERABLE

**How to Execute:**
```bash
nmap -p 8000 --script graphql-schema-directive-leak target.example.com
```

**Sample Output:**
```
| graphql-schema-directive-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Non-standard directives leak implementation detail via introspection
|   Severity counts: CRITICAL=0 HIGH=4 MEDIUM=1 LOW=0 INFO=1
|   Findings:
|     [HIGH] Directive @auth (class: auth) exposes implementation detail
|     [HIGH] Directive @rateLimit (class: rate) exposes implementation detail
|     [MEDIUM] 5 non-standard directive(s) are publicly introspectable
```

---

### 15. **graphql-subscription-websocket** - Unauthenticated Realtime Channels
**Description:** Probes both realtime transports: a full RFC 6455 WebSocket upgrade (graphql-transport-ws / graphql-ws subprotocols) with `connection_init` → `subscribe` → event capture, and an SSE request (Accept: text/event-stream) with a subscription query. Records whether live data flows without credentials.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- WS handshake: 101 + Sec-WebSocket-Accept validated against the SHA-1 of the client key, subprotocol echo
- connection_init → connection_ack, subscribe → `next` event with payload excerpt
- SSE: 200 event stream (data excerpt) vs 406 disabled
- States: streaming (MEDIUM), partial handshake (LOW), upgrade refused (NOT VULNERABLE)

**How to Execute:**
```bash
nmap -p 8000 --script graphql-subscription-websocket target.example.com
```

**Sample Output:**
```
| graphql-subscription-websocket:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Unauthenticated realtime subscription stream is open (2 transport(s))
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=2 LOW=1 INFO=1
|   WebSocket Probe:
|     Upgrade: 101 (101 Switching Protocols)
|     Sec-WebSocket-Accept valid: true
|     Negotiated subprotocol: graphql-transport-ws
|     Outcome: streaming - subscribe accepted; next event received without authentication
```

---

### 16. **graphql-endpoint-discovery** - Attack Surface Inventory
**Description:** Comprehensive GraphQL endpoint discovery: probes a 33-path candidate list (standard, versioned, framework-specific, admin and realtime paths), confirms each with `__typename`, and inventories methods (POST/GET), embedded IDEs, the realtime transport surface (WS upgrade + SSE), IDE sibling paths and framework fingerprints. Pure discovery - feeds the other scripts via `--path`.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Per candidate: POST `{"query":"{__typename}"}` → confirmed endpoint? (`__typename` required; error-only 404s excluded)
- Confirmed endpoints: GET with `?query=`, GET with `Accept: text/html` (embedded IDE)
- First endpoint: WS upgrade (subprotocol, accept validation), SSE offer
- IDE paths: /, /graphiql, /playground, /graphql-console, /altair
- Aggregated framework fingerprint (Apollo, Strawberry, Hasura, Yoga, ...)

**How to Execute:**
```bash
nmap -p 8000 --script graphql-endpoint-discovery target.example.com
nmap -p 8000 --script graphql-endpoint-discovery --script-args 'graphql-endpoint-discovery.path=/api/v1/graphql' target.example.com
```

**Sample Output:**
```
| graphql-endpoint-discovery:
|   Risk Level: 🟢 LOW
|   Status: COMPLETED - 5 GraphQL endpoint(s) discovered across 33 path probes
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=0 INFO=11
|   Endpoint Probe Results:
|     /graphql: GraphQL endpoint (POST, GET) __typename=Query + embedded IDE on GET/HTML
|     /api/graphql: GraphQL endpoint (POST, GET) __typename=Query + embedded IDE on GET/HTML
|   Realtime Transport Inventory:
|     WebSocket upgrade @/graphql: accepted (HTTP 101), subprotocol=graphql-transport-ws, Sec-WebSocket-Accept validated
|     SSE subscription @/graphql: offered (HTTP 200 text/event-stream)
```

## 🔒 Safe & Non-Destructive

- All 16 scripts use **read-only** queries or mutations with **dummy credentials** that real resolvers reject; no account state is altered on a correctly configured target.
- The only "write-looking" probes (unauth-mutation, get-mutation-bypass) submit operations with throwaway values and classify resolver execution vs. rejection, so a gated API is reported NOT VULNERABLE instead of flagged.
- Every scan is **budget-bounded** (`maxrequests`, `timeout`, `retries`, `delay` script-args) and delays requests by `delay` seconds.
- WebSocket sessions are closed cleanly (1000 close frame); deep-list recursion is deliberately capped in probe construction to stay inside resource limits.
- Scripts that cannot find an endpoint report per-candidate path probes as INFO findings instead of failing.

## 🧰 Common script-args (all scripts)

| Arg | Default | Meaning |
|-----|---------|---------|
| `<script>.path` | - | exact GraphQL endpoint path (skips candidate discovery) |
| `<script>.paths` | - | CSV list of candidate paths to try in order |
| `<script>.maxrequests` | 12-60 | total request budget for the scan |
| `<script>.timeout` | 8-10 | per-request timeout in seconds |
| `<script>.retries` | 1-2 | transport retries per request |
| `<script>.delay` | 0.2-0.5 | seconds between requests |
| `<script>.useragent` | Mozilla/5.0 (compatible; gql-audit/1.0) | User-Agent for HTTP probes |
| `<script>.batch_size` | 16 | batch operations per request (batch-query-abuse, max 64) |
