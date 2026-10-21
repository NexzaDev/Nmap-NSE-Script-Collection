# 🔌 WebSocket Security Audits

**16 Nmap NSE scripts** for auditing the WebSocket (RFC 6455) attack surface reachable from an HTTP endpoint:

**Covers:**

- A wire layer implementing the full handshake (Sec-WebSocket-Accept derivation, subprotocol and extension negotiation, version ladder) plus frame encode/decode with client masking
- All three length forms
- Control frames and close-code tables; and a transport layer with budgeted sockets
- Frame round-trips
- Poll-endpoint HTTP probes and TLS liveness checks

**The suite covers the class-defining WebSocket findings:**

- Cross-site hijacking (CSWSH) via a three-origin handshake matrix
- Anonymous upgrades with forged credentials
- Cross-user broadcast leakage in chat-style fan-out
- Binary-frame deserialization fingerprints (Java/pickle/MessagePack/BSON/protobuf)
- Client-masking enforcement with degenerate-key probes
- Frame-size ladders against length-form abuse
- Permessage-deflate negotiation memory posture
- Ping/pong DoS discipline
- Auth-ticket channel hygiene
- Cleartext ws:// exposure
- Framework handshakes of socket.io/engine.io
- Rails Action Cable
- Spring STOMP and GraphQL-over-WS. Every payload is inert and masked in output; every probe is a bounded read-only exchange.

**Port:** target HTTP service (any port with `shortport.http`) | **Handshake:** RFC 6455 (version 13) with hybi-era fallbacks | **Protocols:** ws:// and wss:// upgrades, engine.io polling, STOMP, GraphQL-WS | **Total lines of Lua:** 21,544

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [ws-chat-broadcast-leak](#1-ws-chat-broadcast-leak---chat-broadcast-leakage-cross-user-fan-out) | 🔴 CRITICAL | vuln, safe | 1529 |
| 2 | [ws-cross-site-hijacking-cswsh](#2-ws-cross-site-hijacking-cswsh---cross-site-websocket-hijacking-cswsh) | 🔴 CRITICAL | vuln, safe | 1529 |
| 3 | [ws-unauth-connection-check](#3-ws-unauth-connection-check---unauthenticated-upgrade-check) | 🔴 CRITICAL | vuln, safe | 1529 |
| 4 | [ws-binary-frame-deserialization](#4-ws-binary-frame-deserialization---binary-frame-deserialization-exposure) | 🟠 HIGH | vuln, safe | 1546 |
| 5 | [ws-masked-frame-enforcement](#5-ws-masked-frame-enforcement---rfc-6455-client-masking-enforcement) | 🟠 HIGH | defensive, safe | 1547 |
| 6 | [ws-auth-ticket-probe](#6-ws-auth-ticket-probe---websocket-auth-ticket-channels) | 🟡 MEDIUM | discovery, safe | 1257 |
| 7 | [ws-cleartext-transport-warning](#7-ws-cleartext-transport-warning---cleartext-ws-transport-warning) | 🟡 MEDIUM | defensive, safe | 1227 |
| 8 | [ws-graphql-transport-ws](#8-ws-graphql-transport-ws---graphql-over-websocket-transports) | 🟡 MEDIUM | discovery, safe | 1271 |
| 9 | [ws-max-frame-size-dos](#9-ws-max-frame-size-dos---maximum-frame-size--length-form-abuse) | 🟡 MEDIUM | defensive, safe | 1266 |
| 10 | [ws-permessage-deflate-audit](#10-ws-permessage-deflate-audit---permessage-deflate-rfc-7692-audit) | 🟡 MEDIUM | defensive, safe | 1257 |
| 11 | [ws-ping-pong-dos-tolerance](#11-ws-ping-pong-dos-tolerance---pingpong-dos-tolerance) | 🟡 MEDIUM | defensive, safe | 1297 |
| 12 | [ws-spring-stomp-probe](#12-ws-spring-stomp-probe---spring-stomp-over-websocket) | 🟡 MEDIUM | discovery, safe | 1268 |
| 13 | [ws-actioncable-rails-probe](#13-ws-actioncable-rails-probe---rails-action-cable-fingerprint) | 🟢 LOW | discovery, safe | 1250 |
| 14 | [ws-socketio-handshake-probe](#14-ws-socketio-handshake-probe---socketio--engineio-handshake-probe) | 🟢 LOW | discovery, safe | 1253 |
| 15 | [ws-subprotocol-enumeration](#15-ws-subprotocol-enumeration---sec-websocket-protocol-enumeration) | 🟢 LOW | discovery, safe | 1258 |
| 16 | [ws-version-handshake-negotiation](#16-ws-version-handshake-negotiation---sec-websocket-version-negotiation) | 🟢 LOW | discovery, safe | 1260 |

---

### 1. **ws-chat-broadcast-leak** - Chat Broadcast Leakage (Cross-User Fan-Out)
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens the socket requesting the chat subprotocol.
- Sends the probe message set (join, canary text, presence) and records every answer frame with secrets masked.
- Subscribes via the Action Cable identifier shape and captures the confirmation stream.
- Attempts one message addressed to a foreign room.
- Grades broadcast leakage from what actually arrived.
- Why it matters: Chat/broadcast sockets fan out server-pushed state; when fan-out skips per-peer authorization, one anonymous connection receives every user's messages, rooms and sometimes credentials. Cross-room acceptance also proves command forgery is possible.
- Safety: inert canary JSON only, bounded exchange count, masked transcripts, no flooding and no message forgery against real users.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-chat-broadcast-leak target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-chat-broadcast-leak --script-args 'ws-chat-broadcast-leak.timeout=8,ws-chat-broadcast-leak.maxrequests=48,ws-chat-broadcast-leak.wspath=/ws,ws-chat-broadcast-leak.junk_cookie=sid=forged0123456789abcdef,ws-chat-broadcast-leak.room=ChatRoom,ws-chat-broadcast-leak.other_room=AdminRoom' target.corp.example.com
```

**Sample Output:**
```
| ws-chat-broadcast-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - chat socket broadcasts other parties' traffic to an anonymous peer
```

---

### 2. **ws-cross-site-hijacking-cswsh** - Cross-Site WebSocket Hijacking (CSWSH)
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Completes a handshake with a trusted Origin to confirm the path and its negotiated subprotocols/extensions.
- Repeats the identical handshake with an attacker Origin.
- Repeats it with no Origin header at all.
- Sends one harmless {"action":"whoami"} frame over the attacker socket to see whether the session actually reacts.
- Grades CSWSH exposure from the three-way verdict matrix.
- Why it matters: A WebSocket upgrade is a plain GET, so it rides ambient cookies: if Origin is not checked, any web page the victim visits can open the authenticated socket and read or write their live session. CSWSH is the WebSocket twin of CSRF but worse, because the connection stays open and streams data both ways.
- Safety: read-only handshakes plus one inert JSON frame; no destructive payloads, no flooding, credentials never rendered.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-cross-site-hijacking-cswsh target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-cross-site-hijacking-cswsh --script-args 'ws-cross-site-hijacking-cswsh.timeout=8,ws-cross-site-hijacking-cswsh.maxrequests=48,ws-cross-site-hijacking-cswsh.wspath=/ws,ws-cross-site-hijacking-cswsh.trusted_origin=app.target.local,ws-cross-site-hijacking-cswsh.evil_origin=evil.example' target.corp.example.com
```

**Sample Output:**
```
| ws-cross-site-hijacking-cswsh:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - cross-site WebSocket hijacking: attacker Origin upgraded
```

---

### 3. **ws-unauth-connection-check** - Unauthenticated Upgrade Check
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Upgrades with no credentials and records the status/challenge.
- Upgrades with a structurally valid but forged session cookie.
- Upgrades with a syntactically valid random bearer token.
- Upgrades with both forgeries together.
- Builds an authentication-gate matrix and grades exposure.
- Why it matters: The 101 handshake is the only gate many deployments ship; once it is open, every subscription, broadcast and command rides it. forged-but-well-formed credentials that still upgrade usually mean validation is missing entirely, not merely weak.
- Safety: four bounded handshake attempts, random garbage credentials only; nothing is replayed, cracked or flooded.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-unauth-connection-check target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-unauth-connection-check --script-args 'ws-unauth-connection-check.timeout=8,ws-unauth-connection-check.maxrequests=48,ws-unauth-connection-check.wspath=/ws,ws-unauth-connection-check.junk_cookie=sid=forged0123456789abcdef' target.corp.example.com
```

**Sample Output:**
```
| ws-unauth-connection-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - WebSocket upgrades with zero credentials
```

---

### 4. **ws-binary-frame-deserialization** - Binary Frame Deserialization Exposure
**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Opens a socket on the configured path.
- Sends nine one-shot signature probes, each followed to the server close/answer.
- Classifies each reaction (protocol close vs application answer vs reflection).
- Checks the transport posture and grades deserialization exposure.
- Why it matters: Binary WebSocket frames bypass every HTTP-body inspection layer; a deserialization endpoint on a socket is a direct gadget-chain target and typically ends in remote code execution. The probe is purely observational: real gadgets are never constructed, only format fingerprints.
- Safety: tiny inert payloads, one probe per format, bounded exchanges; no polymorphic payloads, no memory stress.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-binary-frame-deserialization target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-binary-frame-deserialization --script-args 'ws-binary-frame-deserialization.timeout=8,ws-binary-frame-deserialization.maxrequests=48,ws-binary-frame-deserialization.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-binary-frame-deserialization:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - binary frames with serializer magic bytes reach application code
```

---

### 5. **ws-masked-frame-enforcement** - RFC 6455 Client-Masking Enforcement
**Risk Level:** 🟠 HIGH | **Category:** defensive, safe

**What it checks:**
- Opens the socket and records the negotiated handshake.
- Sends an unmasked frame - a compliant server closes with 1002.
- Sends a correctly masked frame - must be processed normally.
- Sends a frame masked with 00000000 to test mask quality.
- Builds the four-rule compliance matrix and grades the endpoint.
- Why it matters: Client masking exists to protect intermediaries from proxy/cache poisoning, not confidentiality; servers that accept unmasked or predictable-mask frames silently disable that protection. Enforcement is cheap for the server, so non-compliance usually signals a hand-rolled WebSocket stack.
- Safety: three tiny single frames with bounded waits; the violations are protocol-shape tests, not payload attacks.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-masked-frame-enforcement target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-masked-frame-enforcement --script-args 'ws-masked-frame-enforcement.timeout=8,ws-masked-frame-enforcement.maxrequests=48,ws-masked-frame-enforcement.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-masked-frame-enforcement:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - server processes unmasked client frames (RFC 6455 5.1 violation)
```

---

### 6. **ws-auth-ticket-probe** - WebSocket Auth-Ticket Channels
**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Baseline anonymous upgrade to see the natural gate.
- Upgrade with a random ticket as a query parameter.
- Upgrade with the ticket smuggled as a subprotocol token.
- Upgrade with the ticket as a bearer token.
- Grades channel hygiene and ticket validation.
- Why it matters: One-time ticket schemes silently degrade into static secrets that sit in access logs when they ride the URL. Accepting structurally-valid but unvalidated tickets proves the auth gate is decorative.
- Safety: random single-use probes only; no real tickets are guessed and nothing is replayed.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-auth-ticket-probe target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-auth-ticket-probe --script-args 'ws-auth-ticket-probe.timeout=8,ws-auth-ticket-probe.maxrequests=48,ws-auth-ticket-probe.wspath=/ws,ws-auth-ticket-probe.junk_cookie=sid=forged0123456789abcdef' target.corp.example.com
```

**Sample Output:**
```
| ws-auth-ticket-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - random ticket material accepted on the upgrade
```

---

### 7. **ws-cleartext-transport-warning** - Cleartext ws:// Transport Warning
**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Attempts the plain upgrade and records the result.
- Sends a TLS ClientHello to test for a TLS listener on the port.
- If upgraded, performs one inert frame round-trip to demonstrate plaintext frames.
- Grades no-TLS / mixed / enforced posture.
- Why it matters: ws:// exposes the upgrade request - including ambient cookies and tokens - to every network hop, and frames have no integrity protection whatsoever. Many deployments terminate TLS for HTTP but forget the socket path.
- Safety: one handshake, one ClientHello, one inert frame; no traffic interception beyond the script's own exchange.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-cleartext-transport-warning target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-cleartext-transport-warning --script-args 'ws-cleartext-transport-warning.timeout=8,ws-cleartext-transport-warning.maxrequests=48,ws-cleartext-transport-warning.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-cleartext-transport-warning:
|   Risk Level: 🟡 MEDIUM
|   Status: NOTE - socket upgrades over cleartext while TLS is available on the port
```

---

### 8. **ws-graphql-transport-ws** - GraphQL over WebSocket Transports
**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Upgrades with each subprotocol and records the echoed choice.
- Sends connection_init with a random token payload.
- Classifies ack/error answers per transport.
- Probes the path over plain GET for upgrade-only enforcement.
- Grades transport identity and anonymous-init posture.
- Why it matters: The two transports share a handshake but differ in close-code contracts and security posture; the legacy stack is end-of-life with published DoS advisories. connection_ack for a fabricated token proves anonymous subscriptions even when the HTTP GraphQL endpoint is locked down.
- Safety: two handshakes and one init message each; no subscriptions are created and no queries are executed.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-graphql-transport-ws target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-graphql-transport-ws --script-args 'ws-graphql-transport-ws.timeout=8,ws-graphql-transport-ws.maxrequests=48,ws-graphql-transport-ws.gqlpath=/graphql' target.corp.example.com
```

**Sample Output:**
```
| ws-graphql-transport-ws:
|   Risk Level: 🟡 MEDIUM
|   Status: INFO - GraphQL socket upgraded but connection_init was not acknowledged
```

---

### 9. **ws-max-frame-size-dos** - Maximum Frame Size / Length-Form Abuse
**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Opens a socket on the configured path.
- Sends one frame per ladder step, reading the reaction each time.
- Stops at the first policy close (1009) or echo ceiling.
- Grades the observed limit against the safe-probe ceiling.
- Why it matters: Stacks that allocate from the announced 16/64-bit length before reading the payload can be exhausted by header-only floods. A missing application-level frame limit turns every connected peer into a bandwidth and buffer amplifier.
- Safety: four bounded single frames, each fully consumed; the ladder is rate-limited by the session budget and never floods.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-max-frame-size-dos target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-max-frame-size-dos --script-args 'ws-max-frame-size-dos.timeout=8,ws-max-frame-size-dos.maxrequests=48,ws-max-frame-size-dos.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-max-frame-size-dos:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 256 KiB frames accepted with no visible limit
```

---

### 10. **ws-permessage-deflate-audit** - permessage-deflate (RFC 7692) Audit
**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Offers permessage-deflate in three shapes (default bits, capped bits, no-context-takeover).
- Reads the granted Sec-WebSocket-Extensions for each.
- Computes the memory-per-connection model from the granted window.
- Validates the probe's own DEFLATE assumptions.
- Grades negotiation posture and advice.
- Why it matters: Context takeover keeps a 32 KB LZ77 window per direction per connection; churn-heavy fleets pay hundreds of MB and become trivial memory-DoS targets. Negotiated compression also reintroduces length-oracle (CRIME-like) exposure for any secret flowing through the socket.
- Safety: three ordinary handshakes plus one inert frame; no compression bombs are ever sent.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-permessage-deflate-audit target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-permessage-deflate-audit --script-args 'ws-permessage-deflate-audit.timeout=8,ws-permessage-deflate-audit.maxrequests=48,ws-permessage-deflate-audit.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-permessage-deflate-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE-ISH - compression negotiated with context reset
```

---

### 11. **ws-ping-pong-dos-tolerance** - Ping/Pong DoS Tolerance
**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Baseline ping and pong payload-echo check.
- Maximum-legal control frame check.
- Bounded burst of eight pings counting answered/closed.
- One 200-byte control frame grading violation handling.
- Grades RFC compliance and DoS tolerance.
- Why it matters: Ping floods are the cheapest WebSocket DoS: each probe costs the attacker bytes but buys the server wakeups, timers and queue state. Tolerating oversized control frames signals missing framing validation - the same code path that mis-sizes pings mis-sizes message frames.
- Safety: at most eleven tiny control frames, session-budget limited, zero flood patterns.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-ping-pong-dos-tolerance target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-ping-pong-dos-tolerance --script-args 'ws-ping-pong-dos-tolerance.timeout=8,ws-ping-pong-dos-tolerance.maxrequests=48,ws-ping-pong-dos-tolerance.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-ping-pong-dos-tolerance:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDIT - server answers RFC-violating oversized control frames
```

---

### 12. **ws-spring-stomp-probe** - Spring STOMP over WebSocket
**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Walks the three STOMP subprotocols until one upgrades.
- Sends CONNECT with accept-version 1.2 and a vhost.
- Parses CONNECTED (version, heart-beat, session) or ERROR.
- Grades discovery results and anonymous-access posture.
- Why it matters: STOMP brokers frequently accept anonymous CONNECTs, exposing topic trees, user destinations and message injection to any web page. The CONNECTED frame fingerprints broker topology (simple broker vs RabbitMQ relay) that direct HTTP scans never see.
- Safety: one CONNECT per subprotocol; no SUBSCRIBE, no message injection, no broker writes.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-spring-stomp-probe target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-spring-stomp-probe --script-args 'ws-spring-stomp-probe.timeout=8,ws-spring-stomp-probe.maxrequests=48,ws-spring-stomp-probe.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-spring-stomp-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: INFO - WebSocket upgrade works but no STOMP broker answered
```

---

### 13. **ws-actioncable-rails-probe** - Rails Action Cable Fingerprint
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- GETs the cable path and checks for the welcome envelope.
- Upgrades with a trusted Origin and records the handshake.
- Sends one inert frame and one Action Cable subscribe command.
- Correlates markers (welcome, ping, confirm/reject) with the Rails deployment matrix.
- Why it matters: Action Cable mounts are the WebSocket entry point of every Rails app; identifying them scopes the rest of the audit. confirm vs reject subscription behavior reveals whether channel authorization callbacks are wired at all.
- Safety: two GETs, one upgrade, two inert frames; no channel writes and no broadcast reads are kept beyond masked markers.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-actioncable-rails-probe target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-actioncable-rails-probe --script-args 'ws-actioncable-rails-probe.timeout=8,ws-actioncable-rails-probe.maxrequests=48,ws-actioncable-rails-probe.cablepath=/cable,ws-actioncable-rails-probe.trusted_origin=app.target.local,ws-actioncable-rails-probe.channel=NotificationsChannel' target.corp.example.com
```

**Sample Output:**
```
| ws-actioncable-rails-probe:
|   Risk Level: 🟢 LOW
|   Status: DISCOVERY - Rails Action Cable endpoint identified at /cable
```

---

### 14. **ws-socketio-handshake-probe** - socket.io / engine.io Handshake Probe
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- GETs the polling endpoint and parses sid/upgrades/timers.
- Derives the engine.io version from the open packet.
- Upgrades the sid-bound WebSocket transport.
- Sends 2probe and verifies the 3probe answer.
- Grades deployment markers (CORS, transport mix, timing).
- Why it matters: socket.io is the most deployed Node WebSocket layer and its long-polling endpoint answers plain GET, which makes it a favorite discovery target and CORS-misconfiguration amplifier. The engine.io version decides which reconnect and packet quirks apply during deeper testing.
- Safety: two GETs, one upgrade, one probe frame; no namespace CONNECT, no event emission, nothing joined.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-socketio-handshake-probe target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-socketio-handshake-probe --script-args 'ws-socketio-handshake-probe.timeout=8,ws-socketio-handshake-probe.maxrequests=48,ws-socketio-handshake-probe.siopath=/socket.io/?EIO=4&transport=polling' target.corp.example.com
```

**Sample Output:**
```
| ws-socketio-handshake-probe:
|   Risk Level: 🟢 LOW
|   Status: DISCOVERY - socket.io v0 endpoint with sid lv_V0iMock
```

---

### 15. **ws-subprotocol-enumeration** - Sec-WebSocket-Protocol Enumeration
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Baseline upgrade with no tokens (must answer none).
- One upgrade per known subprotocol token, recording echoes.
- Priority-order probe with the combined accepted list.
- Grades the fingerprint and negotiation correctness.
- Why it matters: The echoed token is an application-layer fingerprint: chat, STOMP, GraphQL and socket.io ecosystems all answer with distinct tokens. Servers that echo unoffered tokens or pick the wrong priority entry break strict clients and hint at hand-rolled negotiation.
- Safety: at most one handshake per token plus one combined, all read-only, session-budget limited.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-subprotocol-enumeration target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-subprotocol-enumeration --script-args 'ws-subprotocol-enumeration.timeout=8,ws-subprotocol-enumeration.maxrequests=48,ws-subprotocol-enumeration.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-subprotocol-enumeration:
|   Risk Level: 🟢 LOW
|   Status: DISCOVERY - server supports WebSocket subprotocols: chat
```

---

### 16. **ws-version-handshake-negotiation** - Sec-WebSocket-Version Negotiation
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Ladder of five handshake variants with different versions.
- Records status, upgrade result and version-error headers.
- Builds the three-rule compliance checklist.
- Grades negotiation posture.
- Why it matters: Version handling is the fastest stack fingerprint: compliant servers answer 426 + Sec-WebSocket-Version for anything but 13, while hand-rolled stacks leak their draft-era lineage. Missing-version tolerance reveals how strictly the upgrade path validates, which correlates with the masking findings.
- Safety: five ordinary handshakes with unusual headers only; nothing is malformed at the frame layer.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script ws-version-handshake-negotiation target.corp.example.com

# Tuned request budget and socket path
nmap -p 80,8080,443 --script ws-version-handshake-negotiation --script-args 'ws-version-handshake-negotiation.timeout=8,ws-version-handshake-negotiation.maxrequests=48,ws-version-handshake-negotiation.wspath=/ws' target.corp.example.com
```

**Sample Output:**
```
| ws-version-handshake-negotiation:
|   Risk Level: 🟢 LOW
|   Status: DISCOVERY - RFC 6455 (version 13) WebSocket handshake confirmed
```

