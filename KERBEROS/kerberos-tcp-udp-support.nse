local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- Message construction and transport come from the shared Kerberos engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Measures how a KDC behaves on each of its two transports, and what that costs.

Kerberos runs on UDP/88 and TCP/88. RFC 4120 section 7.2.2 makes both
mandatory and defines the difference: UDP is one datagram per request, TCP
carries a four byte big-endian length prefix per message and the connection can
carry several exchanges. A KDC reachable on one transport only still
authenticates small requests, and then fails in ways that are hard to attribute:

  * UDP filtered, TCP open: every exchange pays the datagram timeout first.
  * UDP open, TCP filtered: a ticket that does not fit a datagram cannot be
    delivered, because KRB_ERR_RESPONSE_TOO_BIG (52) has no TCP fallback.
    Tickets carry a PAC that grows with group membership, so this breaks
    privileged accounts first.
  * TCP that frames incorrectly, or a KDC that closes the connection after one
    message, breaks clients that pipeline or reuse it.

The script measures each of those: per-transport answer, response size, round
trip, the length prefix the KDC sends, the number of messages one connection
carries, and the too-big fallback when the peer produces it.

References:
  * RFC 4120 section 7.2.2 - TCP and UDP transport, the length prefix and the
    KRB_ERR_RESPONSE_TOO_BIG (52) fallback
  * RFC 4120 section 7.2.1 - the KDC's UDP answer size constraints
  * RFC 4120 section 5.4.1 - the AS-REQ used as the probe message
  * Microsoft, 'Kerberos protocol and troubleshooting': udp/tcp 88 on domain
    controllers and the effect of a blocked transport on authentication
]]

---
-- @usage
-- nmap -p 88 --script kerberos-tcp-udp-support <target>
--
-- @args kerberos.realm        Realm in uppercase DNS form. Discovered with a
--                             foreign realm probe when omitted.
-- @args kerberos.principal    Principal to probe with (default: a synthetic
--                             name - a refusal is an answer too).
-- @args kerberos.kdc-port     KDC port (default 88).
-- @args kerberos.timeout-ms   Per-request timeout, 500-60000.
-- @args kerberos.retries      Transport retries (default 1).
-- @args kerberos.tcp-messages Messages to send on one TCP connection
--                             (default 2, maximum 5).
-- @args kerberos.verbose      "true" adds the wire transcript.
--
-- @output
-- 88/tcp open  kerberos-sec
-- | kerberos-tcp-udp-support:
-- |   Realm: EXAMPLE.COM
-- |   Transport measurements:
-- |     UDP  answered  KRB-ERROR 6 (104 bytes, 3 ms)
-- |     TCP  answered  KRB-ERROR 6 (108 bytes with prefix, 2 ms)
-- |   TCP framing: length prefix correct on every message
-- |_  Risk Level: INFO
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

local SCRIPT_RISK = "LOW"
local SCRIPT_VERSION = "2.0.0"

if not ok or type(krb5) ~= "table" then
  action = function()
    return "\n  The Kerberos engine (nselib/kerberos5.lua) is not installed.\n"
      .. "  Install it next to this script and re-run the scan.\n"
  end
  return
end

local krb = krb5.krb
local transport = krb5.transport
local timeutil = krb5.timeutil
local decoder = krb5.decoder
local NT = krb5.NT

-- 1. Knowledge base

local KB = {}

KB.ANSWER_MEANINGS = {
  no_answer = "nothing came back on this transport within the timeout",
  malformed = "the answer could not be decoded as a Kerberos message",
}

KB.REMEDIATION = {
  {
    title = "Keep both transports reachable",
    steps = {
      "Open UDP/88 and TCP/88 from every client subnet to every KDC. A domain controller answers on both by design, so a filtered transport is always a network rule, not a service setting.",
      "Where a firewall must choose one, keep TCP: it carries every answer, including the ones a datagram cannot hold.",
      "After changing a rule, re-run this script from the same subnet: the measurement is per-path, not per-controller.",
    },
  },
  {
    title = "Watch the ticket size",
    steps = {
      "A ticket's size grows with the PAC, which grows with group membership, so the accounts that break first on a UDP-only path are the privileged ones and the failure looks like a permissions problem.",
      "Record the largest answer seen in a baseline; a jump after a group restructuring is the warning that some path will hit the datagram limit.",
    },
  },
}

KB.VERIFICATION = {
  "Confirm the ports on the controller: Test-NetConnection <dc> -Port 88 -InformationLevel Detailed and the same for the UDP path from each subnet, or the firewall's hit counters.",
  "Watch the KDC side: event 4768 (AS-REQ) and 4769 (TGS-REQ) record the client address, so a subnet whose requests arrive over TCP only is visible there.",
}

KB.REFERENCES = {
  "RFC 4120 section 7.2.2 - TCP and UDP transports and the length prefix",
  "RFC 4120 section 7.2.1 - constraints on a KDC's UDP answers",
  "RFC 4120 section 7.5.1 - KRB_ERR_RESPONSE_TOO_BIG (52)",
  "RFC 4120 section 5.4.1 - the AS-REQ message used as the probe",
  "Microsoft, 'Kerberos protocol and troubleshooting' - required ports and the effect of a blocked transport",
}

-- 2. Configuration

local config = {}

local function arg_string(name)
  local value = stdnse.get_script_args("kerberos." .. name)
  if value == nil then
    return nil
  end
  if type(value) == "table" then
    value = value[1]
  end
  value = tostring(value)
  if #value == 0 then
    return nil
  end
  return value
end

local function arg_int(name, default, minimum, maximum)
  local value = tonumber(arg_string(name))
  if value == nil then
    return default
  end
  value = math.floor(value)
  if value < minimum then
    return minimum
  end
  if value > maximum then
    return maximum
  end
  return value
end

local function arg_bool(name, default)
  local value = arg_string(name)
  if value == nil then
    return default
  end
  value = string.lower(value)
  if value == "true" or value == "yes" or value == "1" or value == "on" then
    return true
  end
  if value == "false" or value == "no" or value == "0" or value == "off" then
    return false
  end
  return default
end

function config.load(host)
  local cfg = {}
  cfg.realm = arg_string("realm")
  if cfg.realm then
    cfg.realm = string.upper(cfg.realm)
  end
  cfg.principal = arg_string("principal") or "nmap-transport-probe"
  cfg.kdc_port = arg_int("kdc-port", 88, 1, 65535)
  cfg.retries = arg_int("retries", 1, 0, 5)
  cfg.tcp_messages = arg_int("tcp-messages", 2, 1, 5)
  cfg.timeout_ms = arg_int("timeout-ms", nil, 500, 60000)
  if not cfg.timeout_ms then
    cfg.timeout_ms = stdnse.get_timeout(host, 3000, 10000) or 3000
  end
  cfg.verbose = arg_bool("verbose", false)
  return cfg
end

-- 3. Realm resolution

local realm = {}

-- The realm is only needed to make the probe message realistic; the transports
-- answer foreign realms too (with KDC_ERR_WRONG_REALM), so a failure to resolve
-- it degrades the report but does not stop the measurement.
function realm.resolve(host, port, cfg)
  local function ask(candidate)
    local record = transport.as_req(host, port, {
      realm = candidate,
      cname = cfg.principal,
      cname_type = NT.PRINCIPAL,
      etypes = { 18, 17, 23 },
      kdc_options = 0,
      till = timeutil.os_utc(3600),
      nonce = math.random(1, 2147483000),
    }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = "auto", delay_ms = 0 })
    return record
  end

  if cfg.realm then
    local record = ask(cfg.realm)
    if record.kind then
      return cfg.realm, "kerberos.realm script argument"
    end
  end
  local record = ask("NMAP-INVALID-INVALID.REALM")
  if record.kind == "krb_error" and record.krb_error and record.krb_error.code == 68
    and record.krb_error.realm and #record.krb_error.realm > 0 then
    return string.upper(record.krb_error.realm), "KDC_ERR_WRONG_REALM leak from a deliberately foreign realm"
  end
  local record2 = ask(cfg.realm or "NMAP-INVALID-INVALID.REALM")
  if record2.kind then
    return cfg.realm, "the KDC answered the probe, so the supplied realm is in use"
  end
  return nil, "not determined"
end

-- 4. Wire measurements

local wire = {}

function wire.build(host, cfg, realm_name)
  return krb.build_as_req({
    realm = realm_name or "NMAP-INVALID-INVALID.REALM",
    cname = cfg.principal,
    cname_type = NT.PRINCIPAL,
    etypes = { 18, 17, 23 },
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  })
end

-- Decode an answer the same way the engine does, but keep the classification
-- local so the report can say which transport produced it.
function wire.classify(data)
  if not data or #data == 0 then
    return { kind = "no_answer", label = "no answer", detail = KB.ANSWER_MEANINGS.no_answer }
  end
  if not krb.is_kerberos_message(data) then
    return {
      kind = "malformed",
      label = "malformed",
      detail = string.format("%s (%d bytes)", KB.ANSWER_MEANINGS.malformed, #data),
    }
  end
  local root = decoder.parse(data)
  if not root then
    return { kind = "malformed", label = "malformed", detail = KB.ANSWER_MEANINGS.malformed }
  end
  local as_rep = krb.parse_as_rep(root)
  if as_rep then
    return {
      kind = "as_rep",
      label = "AS-REP",
      detail = string.format("the KDC issued a ticket encrypted with etype %s", tostring(as_rep.enc_part and as_rep.enc_part.etype)),
      etype = as_rep.enc_part and as_rep.enc_part.etype,
    }
  end
  local err = krb.parse_krb_error(root)
  if err then
    return {
      kind = "krb_error",
      label = err.code_name or "KRB-ERROR",
      detail = string.format("KRB-ERROR %d %s", err.code or -1, tostring(err.code_name)),
      code = err.code,
      code_name = err.code_name,
      realm = err.realm,
    }
  end
  return { kind = "malformed", label = "malformed", detail = "the answer is Kerberos-shaped but not a known message" }
end

-- A single datagram exchange: one send, one receive, the round trip measured
-- around them.
function wire.udp(host, port, cfg, message)
  local result = { transport = "udp" }
  local sock = nmap.new_socket("udp")
  sock:set_timeout(cfg.timeout_ms)
  local connected, connect_err = sock:connect(host, port)
  if not connected then
    result.ok = false
    result.error = tostring(connect_err)
    sock:close()
    return result
  end
  local started = nmap.clock_ms()
  local sent, send_err = sock:send(message)
  if not sent then
    result.ok = false
    result.error = tostring(send_err)
    sock:close()
    return result
  end
  result.request_bytes = #message
  local status, data = sock:receive()
  result.rtt_ms = nmap.clock_ms() - started
  sock:close()
  if not status or not data then
    result.ok = false
    result.error = tostring(data or "timeout")
    result.answer = wire.classify(nil)
    return result
  end
  result.ok = true
  result.answer_bytes = #data
  result.answer = wire.classify(data)
  return result
end

-- One TCP connection carrying several messages, each with the length prefix
-- RFC 4120 requires. The framing is verified on the way out and on the way
-- back: a prefix that does not match its frame is a protocol defect, not a
-- slow server.
function wire.tcp(host, port, cfg, message, count)
  local result = { transport = "tcp", messages = {} }
  local sock = nmap.new_socket("tcp")
  sock:set_timeout(cfg.timeout_ms)
  local connected, connect_err = sock:connect(host, port)
  if not connected then
    result.ok = false
    result.error = tostring(connect_err)
    sock:close()
    return result
  end

  local total = 0
  for index = 1, count do
    local prefix = string.char(
      math.floor(#message / 16777216) % 256,
      math.floor(#message / 65536) % 256,
      math.floor(#message / 256) % 256,
      #message % 256)
    local started = nmap.clock_ms()
    local sent, send_err = sock:send(prefix .. message)
    if not sent then
      result.messages[index] = { ok = false, error = tostring(send_err) }
      break
    end
    local status, data = sock:receive_bytes(#message + 4)
    local entry = { rtt_ms = nmap.clock_ms() - started }
    if not status or not data or #data == 0 then
      entry.ok = false
      entry.error = tostring(data or "timeout")
      result.messages[index] = entry
      break
    end
    entry.ok = true
    entry.raw_bytes = #data
    local declared = nil
    if #data >= 4 then
      declared = string.byte(data, 1) * 16777216 + string.byte(data, 2) * 65536
        + string.byte(data, 3) * 256 + string.byte(data, 4)
    end
    entry.declared = declared
    entry.prefix_ok = (declared ~= nil and declared == #data - 4)
    entry.answer = wire.classify(string.sub(data, 5))
    entry.answer_bytes = #data - 4
    result.messages[index] = entry
    total = total + #data
  end
  result.ok = true
  result.answer_bytes = total
  result.answered = 0
  for _, entry in ipairs(result.messages) do
    if entry.ok then
      result.answered = result.answered + 1
      -- The row for this transport is built from the first message that was
      -- answered, so the report speaks about a completed exchange rather than
      -- about a connection that was merely opened.
      result.answer = result.answer or entry.answer
      result.rtt_ms = result.rtt_ms or entry.rtt_ms
    end
  end
  sock:close()
  return result
end

-- The engine has its own transport layer, so the report can also state what a
-- normal client using it observes. This is the path every other Kerberos
-- script in this repository takes.
function wire.engine_probe(host, port, cfg, realm_name, mode)
  local record = transport.as_req(host, port, {
    realm = realm_name or "NMAP-INVALID-INVALID.REALM",
    cname = cfg.principal,
    cname_type = NT.PRINCIPAL,
    etypes = { 18, 17, 23 },
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = mode, delay_ms = 0 })
  return {
    transport = mode,
    kind = record.kind,
    label = record.kind == "as_rep" and "AS-REP" or (record.krb_error and record.krb_error.code_name) or "no answer",
    rtt_ms = record.rtt_ms,
    attempts = record.attempts,
    used = record.transport,
    error = record.error,
    record = record,
  }
end


-- 5. Analysis

local analysis = {}

-- One row per transport, built only from what was measured: the answer, its
-- size, the round trip, and whether the engine's own client layer agreed.
function analysis.transport_row(measurement, engine)
  local row = {
    id = measurement.transport,
    label = measurement.transport == "udp" and "UDP/88" or "TCP/88",
    answered = measurement.ok and measurement.answer and measurement.answer.kind ~= "no_answer",
    answer = measurement.answer,
    rtt_ms = measurement.rtt_ms,
    bytes = measurement.answer_bytes,
    error = measurement.error,
    engine = engine,
  }
  if not row.answered then
    row.summary = string.format("no answer (%s)", tostring(measurement.error or "timeout"))
  else
    row.summary = string.format("%s, %d bytes in %s ms", measurement.answer.label,
      measurement.answer_bytes or 0, tostring(measurement.rtt_ms or "?"))
  end
  if engine then
    row.engine_summary = string.format("the engine's %s client saw %s after %d attempt(s) in %s ms",
      engine.transport, tostring(engine.label), engine.attempts or 1, tostring(engine.rtt_ms or "?"))
  end
  return row
end

function analysis.evaluate(cfg, realm_result, udp, tcp, engine_udp, engine_tcp)
  local out = {
    rows = {},
    observations = {},
    framing = nil,
    reused = nil,
    fallback = nil,
  }

  out.rows[1] = analysis.transport_row(udp, engine_udp)
  out.rows[2] = analysis.transport_row(tcp, engine_tcp)

  -- Framing: every TCP message the KDC sent must carry a prefix that matches
  -- the bytes that followed it.
  local examined, bad = 0, 0
  for _, entry in ipairs(tcp.messages or {}) do
    if entry.ok and entry.declared then
      examined = examined + 1
      if entry.prefix_ok == false then
        bad = bad + 1
      end
    end
  end
  if examined > 0 then
    out.framing = {
      examined = examined,
      bad = bad,
      ok = bad == 0,
      detail = bad == 0
        and string.format("the length prefix matched the frame on all %d message(s)", examined)
        or string.format("%d of %d message(s) carried a prefix that did not match the frame", bad, examined),
    }
  else
    out.framing = { examined = 0, ok = nil, detail = "no TCP answer was received, so the framing could not be examined" }
  end

  -- Connection reuse: the mock is asked for cfg.tcp_messages exchanges on one
  -- connection; the count that came back is the observation.
  out.reused = {
    requested = cfg.tcp_messages,
    answered = tcp.answered or 0,
    detail = string.format("%d of %d message(s) were answered on a single connection",
      tcp.answered or 0, cfg.tcp_messages),
  }

  -- The response-too-big fallback: a KDC that cannot fit its answer into a
  -- datagram should say so with error 52, and the same exchange must succeed
  -- over TCP.
  local udp_code = udp.answer and udp.answer.code or nil
  local tcp_ok = out.rows[2].answered
  if udp_code == 52 then
    out.fallback = {
      triggered = true,
      ok = tcp_ok == true,
      detail = tcp_ok
        and "the KDC answered KRB_ERR_RESPONSE_TOO_BIG over UDP and the same exchange completed over TCP"
        or "the KDC answered KRB_ERR_RESPONSE_TOO_BIG over UDP and the TCP path did not answer, so a client cannot obtain the ticket at all",
    }
  else
    out.fallback = {
      triggered = false,
      ok = nil,
      detail = "the KDC did not need to signal a datagram that was too large; the fallback path was not exercised",
    }
  end

  if out.rows[1].answered and out.rows[2].answered then
    local a = out.rows[1].answer and out.rows[1].answer.kind
    local b = out.rows[2].answer and out.rows[2].answer.kind
    if a ~= b then
      out.observations[#out.observations + 1] = string.format(
        "the transports disagreed: UDP answered %s while TCP answered %s for the same request",
        tostring(out.rows[1].answer and out.rows[1].answer.label), tostring(out.rows[2].answer and out.rows[2].answer.label))
    end
    local ua = out.rows[1].answer and out.rows[1].answer.code
    local ta = out.rows[2].answer and out.rows[2].answer.code
    if ua and ta and ua ~= ta then
      out.observations[#out.observations + 1] = string.format(
        "the transports returned different error codes (%d over UDP, %d over TCP), which usually means two different servers or a middlebox rewrite",
        ua, ta)
    end
  end
  return out
end

-- 6. Reporting

local RISK_LABEL = {
  CRITICAL = "\240\159\148\180 CRITICAL",
  HIGH = "\240\159\159\160 HIGH",
  MEDIUM = "\240\159\159\161 MEDIUM",
  LOW = "\240\159\159\162 LOW",
  INFO = "\226\154\170 INFO",
  INCONCLUSIVE = "\226\154\170 INCONCLUSIVE",
}

local report = {}

local SEVERITY_ORDER = { CRITICAL = 5, HIGH = 4, MEDIUM = 3, LOW = 2, INFO = 1 }

function report.findings(evaluation, cfg)
  local list = {}
  local function add(finding)
    list[#list + 1] = finding
  end

  local udp, tcp = evaluation.rows[1], evaluation.rows[2]

  if udp.answered and not tcp.answered then
    add({
      id = "TCP-TRANSPORT-BLOCKED",
      severity = "MEDIUM",
      title = "The KDC answers UDP but not TCP",
      evidence = {
        string.format("UDP: %s", udp.summary),
        string.format("TCP: %s", tcp.summary),
      },
      impact =
        "RFC 4120 requires both transports. A client that receives KRB_ERR_RESPONSE_TOO_BIG has no way to obtain the ticket, so authentication fails for exactly the accounts whose tickets are large - the privileged ones - and succeeds for everyone else.",
      remediation =
        "Open TCP/88 from the client subnets to the controller. Verify with a real account from the affected subnet after the change.",
    })
  elseif tcp.answered and not udp.answered then
    add({
      id = "UDP-TRANSPORT-BLOCKED",
      severity = "LOW",
      title = "The KDC answers TCP but not UDP",
      evidence = {
        string.format("TCP: %s", tcp.summary),
        string.format("UDP: %s", udp.summary),
      },
      impact =
        "Authentication still completes, because clients retry over TCP, but every exchange pays the datagram timeout first. The delay is usually misattributed to the directory service.",
      remediation =
        "Open UDP/88 again, or configure the clients to prefer TCP so that the retry is not needed on every request.",
    })
  elseif not udp.answered and not tcp.answered then
    add({
      id = "KDC-TRANSPORTS-UNREACHABLE",
      severity = "MEDIUM",
      title = "Neither transport answered the probe",
      evidence = {
        string.format("UDP: %s", udp.summary),
        string.format("TCP: %s", tcp.summary),
      },
      impact =
        "No Kerberos exchange could be completed, so this target is either not a KDC, filtered, or listening on a non-standard port.",
      remediation =
        "Confirm the port with kerberos.kdc-port and the realm with kerberos.realm, then re-run from the same subnet.",
    })
  end

  if evaluation.framing and evaluation.framing.ok == false then
    add({
      id = "TCP-FRAMING-DEFECT",
      severity = "HIGH",
      title = "A TCP answer carried a length prefix that did not match its frame",
      evidence = { evaluation.framing.detail },
      impact =
        "RFC 4120 section 7.2.2 requires the four byte prefix. A client that trusts it reads the wrong number of bytes and either desynchronises or fails with a decode error, which is indistinguishable from a corrupted ticket.",
      remediation =
        "Capture the exchange on both sides and check whether a middlebox rewrites the stream. If the prefix is wrong at the source, the KDC implementation or the load balancer in front of it is at fault.",
    })
  elseif evaluation.framing and evaluation.framing.ok then
    add({
      id = "TCP-FRAMING-OK",
      severity = "INFO",
      title = "TCP length framing is correct",
      evidence = { evaluation.framing.detail },
      impact = "A client can trust the prefix and read exactly one message at a time.",
      remediation = "No action required.",
    })
  end

  if evaluation.fallback and evaluation.fallback.triggered then
    add({
      id = evaluation.fallback.ok and "UDP-TOO-BIG-FALLBACK" or "UDP-TOO-BIG-NO-FALLBACK",
      severity = evaluation.fallback.ok and "INFO" or "HIGH",
      title = evaluation.fallback.ok
        and "The datagram-too-large fallback works end to end"
        or "A datagram that was too large had no TCP fallback",
      evidence = { evaluation.fallback.detail },
      impact = evaluation.fallback.ok
        and "The KDC signalled KRB_ERR_RESPONSE_TOO_BIG and the same exchange completed over TCP, which is the behaviour RFC 4120 assumes."
        or "A client cannot obtain this ticket on either transport, so the authentication it belongs to fails.",
      remediation = evaluation.fallback.ok
        and "No action required."
        or "Restore TCP/88 to the controller and re-run; this is a hard failure for the affected accounts.",
    })
  end

  if evaluation.reused and evaluation.reused.answered ~= evaluation.reused.requested then
    if evaluation.reused.answered > 0 then
      add({
        id = "TCP-CONNECTION-REUSE-LIMITED",
        severity = "LOW",
        title = string.format("Only %d of %d messages were answered on one TCP connection",
          evaluation.reused.answered, evaluation.reused.requested),
        evidence = { evaluation.reused.detail },
        impact =
          "A client that pipelines requests loses the remainder of the connection. It can recover by reconnecting, so the symptom is extra latency rather than a failure.",
        remediation =
          "Check the load balancer's idle timeout and connection limits in front of the KDC.",
      })
    end
  elseif evaluation.reused and evaluation.reused.answered == evaluation.reused.requested then
    add({
      id = "TCP-CONNECTION-REUSE",
      severity = "INFO",
      title = "One TCP connection carried several exchanges",
      evidence = { evaluation.reused.detail },
      impact = "Connection reuse works, which is what keeps repeated authentication cheap.",
      remediation = "No action required.",
    })
  end

  for _, observation in ipairs(evaluation.observations) do
    add({
      id = "TRANSPORT-DISAGREEMENT",
      severity = "LOW",
      title = "The two transports did not agree",
      evidence = { observation },
      impact =
        "Kerberos assumes either transport reaches the same KDC. A disagreement means a middlebox or a second service is answering one of them, and the client's behaviour then depends on which transport it happened to use.",
      remediation = "Identify what answers the divergent transport and remove it, or document the intentional split.",
    })
  end

  if #list == 0 then
    add({
      id = "NO-FINDINGS",
      severity = "INFO",
      title = "Both transports answered consistently",
      evidence = {
        string.format("UDP: %s", udp.summary),
        string.format("TCP: %s", tcp.summary),
      },
      impact = "The target behaves as RFC 4120 requires on both transports.",
      remediation = "No action required.",
    })
  end
  return list
end

function report.build(host, port, cfg, realm_result, evaluation)
  local out = stdnse.output_table()
  out["Script version"] = SCRIPT_VERSION
  out["Engine version"] = string.format("kerberos5.lua %s", tostring(krb5.VERSION))
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm_result.realm or "not determined"
  out["Realm source"] = realm_result.source
  out["Target"] = string.format("%s (%s)", tostring(host.name or host.ip or "target"),
    tostring(port.number) .. "/" .. tostring(port.protocol or "tcp"))

  local measurements = {}
  for _, row in ipairs(evaluation.rows) do
    measurements[#measurements + 1] = string.format("%-6s %-12s %s", row.label,
      row.answered and "answered" or "unanswered", row.summary)
    if row.engine_summary then
      measurements[#measurements + 1] = string.format("%-6s %-12s %s", "", "", row.engine_summary)
    end
  end
  out["Transport measurements"] = measurements

  out["Transport contract"] = "UDP/88 carries one datagram per request; TCP/88 prefixes every message with four big-endian length bytes (RFC 4120 7.2.2)"
  out["TCP framing"] = evaluation.framing and evaluation.framing.detail or "not measured"
  out["TCP connection reuse"] = evaluation.reused and evaluation.reused.detail or "not measured"
  out["Datagram fallback"] = evaluation.fallback and evaluation.fallback.detail or "not measured"

  if #evaluation.observations > 0 then
    out["Observations"] = evaluation.observations
  end

  local findings = report.findings(evaluation, cfg)
  table.sort(findings, function(a, b)
    local sa, sb = SEVERITY_ORDER[a.severity] or 0, SEVERITY_ORDER[b.severity] or 0
    if sa == sb then
      return tostring(a.id) < tostring(b.id)
    end
    return sa > sb
  end)
  local lines = {}
  local worst = "INFO"
  for index, finding in ipairs(findings) do
    lines[#lines + 1] = string.format("[%d] %s (%s) - %s", index, finding.severity, finding.id, finding.title)
    for _, item in ipairs(finding.evidence or {}) do
      lines[#lines + 1] = "      evidence: " .. tostring(item)
    end
    lines[#lines + 1] = "      impact: " .. tostring(finding.impact)
    lines[#lines + 1] = "      remediation: " .. tostring(finding.remediation)
    if (SEVERITY_ORDER[finding.severity] or 0) > (SEVERITY_ORDER[worst] or 0) then
      worst = finding.severity
    end
  end
  out["Findings"] = lines

  local remediation = {}
  for _, group in ipairs(KB.REMEDIATION) do
    remediation[#remediation + 1] = "== " .. group.title .. " =="
    for _, step in ipairs(group.steps) do
      remediation[#remediation + 1] = "  " .. step
    end
  end
  out["Remediation"] = remediation
  out["Independent verification"] = KB.VERIFICATION
  out["References"] = KB.REFERENCES

  if cfg.verbose then
    local transcript = {}
    transcript[#transcript + 1] = string.format("target %s port %d timeout %d ms retries %d",
      tostring(host.ip), cfg.kdc_port, cfg.timeout_ms, cfg.retries)
    transcript[#transcript + 1] = string.format("realm: %s (%s)", tostring(realm_result.realm), tostring(realm_result.source))
    for _, row in ipairs(evaluation.rows) do
      transcript[#transcript + 1] = string.format("%s: %s", row.label, row.summary)
      if row.engine then
        transcript[#transcript + 1] = string.format("%s engine layer: %s (attempts %d)",
          row.label, tostring(row.engine.label), row.engine.attempts or 1)
      end
    end
    out["Protocol transcript"] = transcript
  end

  if worst == "INFO" and not (evaluation.rows[1].answered or evaluation.rows[2].answered) then
    worst = "INCONCLUSIVE"
  end
  out["Risk Level"] = RISK_LABEL[worst] or worst
  return out
end

-- 7. Action

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local realm_name, realm_source = realm.resolve(host, effective_port, cfg)
  local realm_result = { realm = realm_name, source = realm_source }

  local message = wire.build(host, cfg, realm_name)
  local udp = wire.udp(host, effective_port, cfg, message)
  local tcp = wire.tcp(host, effective_port, cfg, message, cfg.tcp_messages)
  local engine_udp = wire.engine_probe(host, effective_port, cfg, realm_name, "udp")
  local engine_tcp = wire.engine_probe(host, effective_port, cfg, realm_name, "tcp")

  local evaluation = analysis.evaluate(cfg, realm_result, udp, tcp, engine_udp, engine_tcp)
  return report.build(host, port, cfg, realm_result, evaluation)
end
