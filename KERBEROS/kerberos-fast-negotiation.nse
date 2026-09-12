local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- Message construction, KRB-ERROR decoding and transport come from the engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Measures whether a KDC implements Kerberos FAST (RFC 6113) and how strongly.

FAST, the Flexible Authentication Secure Tunneling framework, wraps the
pre-authentication exchange in an encrypted tunnel (an "armor"). It exists
because a plain AS-REQ is a plaintext message: an observer sees which account is
authenticating and which encryption types it offers, and an attacker who can
answer for the KDC can mount a downgrade. Two security properties come out of
it: pre-authentication is no longer readable or alterable in flight, and the
KDC can demand a channel binding that ties the request to the machine it came
from (the "armor key"), which is what makes the exchange resistant to relay.

The framework is negotiated, which makes it observable without credentials. A
KDC that implements FAST advertises PA-FX-FAST (136) and usually PA-FX-COOKIE
(133) in the padata of its KDC_ERR_PREAUTH_REQUIRED answer; a KDC that requires
armoring withholds the etype information (PA-ETYPE-INFO2, 18) from a request
that is not armored, so a client learns nothing until it tunnels. A KDC that
does not implement FAST answers a request that carries PA-FX-FAST with
KDC_ERR_PADATA_TYPE_NOSUPP (16).

The script sends three AS-REQs: a plain one to read the advertised padata, one
that carries a deliberately unarmored PA-FX-FAST padata to see how the KDC
treats the negotiation, and one for a name that cannot exist as a control. It
then reports one of four verdicts - not supported, supported, required, or
inconsistent - with the padata types each answer actually carried.

The unarmored FAST padata is sent on purpose: it asks the KDC to begin the
negotiation without a key to tunnel under, so the answer describes the policy
rather than completing an authentication. No credential is used or requested.
]]

---
-- @usage
-- nmap -p 88 --script kerberos-fast-negotiation --script-args 'kerberos.realm=EXAMPLE.COM' <target>
--
-- @args kerberos.realm        Realm in uppercase DNS form; discovered with a
--                             foreign realm probe when omitted.
-- @args kerberos.principal    Account name used for the probes. A name that
--                             exists produces the richest answer (default
--                             "krbtgt", which every realm has).
-- @args kerberos.kdc-port     KDC port (default 88).
-- @args kerberos.timeout-ms   Per-request timeout, 500-60000.
-- @args kerberos.retries      Transport retries (default 1).
-- @args kerberos.transport    "auto" (default), "udp" or "tcp".
-- @args kerberos.delay-ms     Spacing between the probes (default 150 ms).
-- @args kerberos.verbose      "true" adds the per-probe transcript.
--
-- @output
-- 88/tcp open  kerberos-sec
-- | kerberos-fast-negotiation:
-- |   Realm: EXAMPLE.COM
-- |   FAST verdict: required (armor must be used before the KDC discloses anything)
-- |   Advertised padata: 18 PA-ETYPE-INFO2, 133 PA-FX-COOKIE, 136 PA-FX-FAST, 165 PA-SUPPORTED-ENCTYPES
-- |   PA-FX-FAST probe: KRB-ERROR 25 (NEEDED_PREAUTH) without etype information
-- |_  Risk Level: INFO
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

local SCRIPT_RISK = "MEDIUM"
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
local NT = krb5.NT

-- 1. Knowledge base

local KB = {}

-- The padata types this check reads or sends, with the role each one plays in
-- the negotiation.
KB.PADATA = {
  [2] = { name = "PA-ENC-TIMESTAMP", role = "the encrypted timestamp a client would send once it knows the salt; absent from every probe here because no password is used" },
  [11] = { name = "PA-ETYPE-INFO", role = "the older form of the salt disclosure" },
  [18] = { name = "PA-ETYPE-INFO2", role = "the salt and s2kparams a password guess needs; a KDC that requires FAST withholds it from an unarmored request" },
  [19] = { name = "PA-ETYPE-INFO2-ENC", role = "the pre-encrypted form of the salt disclosure" },
  [133] = { name = "PA-FX-COOKIE", role = "a stateless cookie the KDC issues so a repeated request can be answered without server state; part of RFC 6113" },
  [134] = { name = "PA-AUTHENTICATION-SET", role = "the set of armor types the KDC will accept" },
  [135] = { name = "PA-AUTH-SET-SELECTED", role = "the armor type the client selected" },
  [136] = { name = "PA-FX-FAST", role = "the FAST request and response container; its presence in a NEEDED_PREAUTH answer is the advertisement this check reads" },
  [137] = { name = "PA-FX-ERROR", role = "a FAST-level error, carried instead of a plain KRB-ERROR inside an armored exchange" },
  [138] = { name = "PA-ENCRYPTED-CHALLENGE", role = "the encrypted challenge that binds an armored request to a key the client holds" },
  [165] = { name = "PA-SUPPORTED-ENCTYPES", role = "the encryption type bitmask the KDC accepts on this account" },
}

KB.VERDICTS = {
  {
    id = "not-supported",
    severity = "LOW",
    statement = "the KDC does not implement FAST: PA-FX-FAST was absent from the advertisement and the request that carried it was refused as an unsupported padata type",
    implication = "Pre-authentication travels in the clear and can be observed or modified in flight. A client cannot ask for an armored exchange, so the KDC cannot offer the anti-relay property either.",
    action = "Plan the upgrade before the realm is raised to a functional level that requires FAST; the negotiation is per-KDC, so mixed forests report mixed verdicts.",
  },
  {
    id = "supported",
    severity = "INFO",
    statement = "the KDC advertises PA-FX-FAST and continues the negotiation when a client asks for it, while still disclosing the etype information",
    implication = "Clients that support FAST can use it, and clients that do not still authenticate. The realm is compatible but a misconfigured client can be downgraded without changing the KDC's answer.",
    action = "Enable the client-side requirement (on Windows, the FAST policy in Credential Protection settings) so the protection is used rather than offered.",
  },
  {
    id = "required",
    severity = "INFO",
    statement = "the KDC advertises PA-FX-FAST and withholds the etype information from an unarmored request, so the client must tunnel before it learns anything",
    implication = "Pre-authentication cannot be observed or downgraded, and the KDC forces the armor key. This is the hardened negotiation state; it also means an old client that cannot armor will fail to authenticate, which is intentional.",
    action = "No action required. Keep the client population in mind: a failure that appears here is a client that needs an update, not a KDC defect.",
  },
  {
    id = "inconsistent",
    severity = "MEDIUM",
    statement = "the KDC's answers disagree: FAST was advertised in one answer but refused in another, or a request that asked for FAST was answered with a plain ticket",
    implication = "An answer that ignores the requested protection is a downgrade. A middlebox or a second service that terminates part of the traffic can produce the same pattern, so the finding is about the endpoint as much as the KDC.",
    action = "Decide which behaviour is intended, then capture both exchanges from the client's segment and compare them with the KDC's own view.",
  },
}

KB.REMEDIATION = {
  {
    title = "Read the verdict before changing anything",
    steps = {
      "not-supported and inconsistent are findings about the negotiation; required and supported are inventory facts.",
      "The negotiation is per-KDC: collect the verdict from every controller in the forest before deciding on a policy.",
      "Re-run after a patch level change: FAST implementation arrived with the same updates that hardened the realm's crypto policy.",
    },
  },
  {
    title = "Make the protection be used, not merely offered",
    steps = {
      "On Windows clients, Credential Protection (the FAST policy) is what turns an offered armor into a required one; a client that ignores it keeps sending the plaintext pre-authentication the KDC would have accepted.",
      "Check both sides after the change: the client's own logs (event 4776 and the Kerberos operational log) and this script's verdict from the client's subnet.",
      "A domain that mandates FAST must also keep its time in order, because the armored exchange has the same clock tolerance as the rest of Kerberos.",
    },
  },
  {
    title = "Do not let the negotiation be rewritten in flight",
    steps = {
      "Send the probe from the client segment as well as from the scanner: the inconsistency verdict is produced by something between the client and the KDC.",
      "TLS or IPsec in front of 88 is not a substitute: an intermediary that terminates the connection is exactly what the armor key is designed to detect.",
      "Record the KDC's answer in a baseline, so the next run can tell a configuration change from a network change.",
    },
  },
}

KB.VERIFICATION = {
  "Confirm the advertisement: the KRB-ERROR 25 answer to a plain AS-REQ contains PA-FX-FAST (136) when the KDC implements RFC 6113, and the padata list is printed in this report.",
  "Confirm the requirement: with armoring required, the same answer carries no PA-ETYPE-INFO2 (18) entry, so a client that cannot armor never learns the salt.",
  "Confirm on the client: a Windows client with Credential Protection enabled produces a TGS-REQ with PA-FX-FAST and an armored AS exchange in a capture; a client without it does not.",
}

KB.REFERENCES = {
  "RFC 6113 - A Generalized Framework for Kerberos Pre-Authentication: the armor, PA-FX-FAST, PA-FX-COOKIE and the PA-AUTHENTICATION-SET negotiation, sections 5 and 8",
  "RFC 4120 section 7.5.1 - KDC_ERR_PREAUTH_REQUIRED (25) and KDC_ERR_PADATA_TYPE_NOSUPP (16), the two answers this check reads",
  "RFC 4120 section 5.4.1 - the AS-REQ, whose optional padata field carries the FAST request",
  "Microsoft, 'Credential Protection' and MS-KILE: the client-side policy that requires armoring and the padata that implement it",
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
  cfg.principal = arg_string("principal") or "krbtgt"
  cfg.kdc_port = arg_int("kdc-port", 88, 1, 65535)
  cfg.retries = arg_int("retries", 1, 0, 5)
  cfg.delay_ms = arg_int("delay-ms", 150, 0, 5000)
  cfg.timeout_ms = arg_int("timeout-ms", nil, 500, 60000)
  if not cfg.timeout_ms then
    cfg.timeout_ms = stdnse.get_timeout(host, 3000, 10000) or 3000
  end
  local mode = arg_string("transport")
  if mode then
    mode = string.lower(mode)
    if mode ~= "udp" and mode ~= "tcp" then
      mode = "auto"
    end
  else
    mode = "auto"
  end
  cfg.transport = mode
  cfg.verbose = arg_bool("verbose", false)
  return cfg
end

-- 3. Realm resolution

local realm = {}

-- A request for a realm this KDC does not serve is answered with
-- KDC_ERR_WRONG_REALM and the realm it does serve.
function realm.resolve(host, port, cfg)
  if cfg.realm then
    return cfg.realm, "kerberos.realm script argument"
  end
  local synthetic = "NMAP-NONEXISTENT.INVALID"
  local record = transport.as_req(host, port, {
    realm = synthetic,
    cname = "fast-probe",
    cname_type = NT.PRINCIPAL,
    etypes = { 23, 18, 17 },
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
  })
  if record.kind == "krb_error" and record.krb_error and record.krb_error.realm then
    return string.upper(record.krb_error.realm), "KDC_ERR_WRONG_REALM answered for a foreign realm"
  end
  local name = host.name or host.targetname
  if name then
    return string.upper(string.match(name, "%.(.+)$") or name),
      "derived from the target name; verify it before trusting the verdict"
  end
  return nil, "not determined"
end

-- 4. Wire

local wire = {}

-- A PA-FX-FAST padata value. RFC 6113 section 5.4.2 defines the container as a
-- CHOICE whose armored form is [1]; this probe sends the empty SEQUENCE, which
-- announces FAST without a key to tunnel under. The KDC's answer to that is
-- exactly the policy this script measures.
function wire.fast_padata_value()
  return krb5.der.sequence()
end

-- The PA-DATA entry the AS-REQ carries. The engine builds the wrapper, so the
-- probe cannot disagree with what the engine's parser would accept.
function wire.fast_entry()
  return krb.padata(136, wire.fast_padata_value())
end

-- Send one AS-REQ, optionally carrying the FAST padata entry.
function wire.request(host, port, cfg, realm_name, name, with_fast)
  local opts = {
    realm = realm_name,
    cname = name,
    cname_type = NT.PRINCIPAL,
    etypes = { 23, 18, 17 },
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }
  if with_fast then
    opts.padata = { wire.fast_entry() }
  end
  local record = transport.as_req(host, port, opts, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
    delay_ms = cfg.delay_ms,
  })
  record.requested_cname = name
  record.requested_realm = realm_name
  record.carried_fast = with_fast and true or false
  return record
end

-- Read the padata types out of an answer. The e-data of a KRB-ERROR holds a
-- METHOD-DATA sequence; an AS-REP can hold padata directly.
function wire.padata_types(record)
  local types = {}
  local blob
  if record.kind == "krb_error" and record.krb_error then
    blob = record.krb_error.e_data
  elseif record.kind == "as_rep" and record.as_rep then
    blob = record.as_rep.padata
    if type(blob) == "table" then
      for _, entry in ipairs(blob) do
        types[#types + 1] = entry.type or entry
      end
      return types
    end
  end
  if type(blob) ~= "string" or #blob == 0 then
    return types
  end
  for _, entry in ipairs(krb.parse_method_data(blob)) do
    types[#types + 1] = entry.type
  end
  return types
end

function wire.has_type(types, wanted)
  for _, value in ipairs(types) do
    if value == wanted then
      return true
    end
  end
  return false
end

function wire.describe_types(types)
  local out = {}
  for _, value in ipairs(types) do
    local entry = KB.PADATA[value]
    out[#out + 1] = string.format("%d %s", value, entry and entry.name or "unlisted padata type")
  end
  return out
end

-- 5. Probes

local probe = {}

-- Turn one answer into the facts the verdict is built from: what kind of
-- message it is, which padata it carried and whether it disclosed the salt.
function probe.classify(record, cfg)
  local row = {
    label = record.carried_fast and "AS-REQ with PA-FX-FAST (136)" or "plain AS-REQ",
    carried_fast = record.carried_fast,
    request_bytes = record.request_bytes,
    response_bytes = record.response_bytes,
    rtt_ms = record.rtt_ms,
    transport = record.transport,
    attempts = record.attempts,
    padata = wire.padata_types(record),
  }
  if record.kind == "krb_error" and record.krb_error then
    row.kind = "krb_error"
    row.error_code = record.krb_error.code
    row.error_name = record.krb_error.code_name
  elseif record.kind == "as_rep" then
    row.kind = "as_rep"
  else
    row.kind = "no-answer"
  end
  row.advertises_fast = wire.has_type(row.padata, 136)
  row.carries_cookie = wire.has_type(row.padata, 133)
  row.discloses_salt = wire.has_type(row.padata, 18) or wire.has_type(row.padata, 11)
  row.padata_names = wire.describe_types(row.padata)
  if row.kind == "no-answer" then
    row.detail = string.format("no answer after %d attempt(s) (%s)", record.attempts or 1,
      tostring(record.error or "timeout"))
  elseif row.kind == "as_rep" then
    row.detail = string.format("AS-REP issued (%s bytes)", tostring(record.response_bytes))
  else
    row.detail = string.format("%s (code %d) with %d padata entr(y/ies)",
      tostring(row.error_name), tostring(row.error_code), #row.padata)
  end
  return row
end

-- The three measurements, in the order they are sent. The control probe uses a
-- name that cannot exist, so an unexpected answer from it says the KDC answers
-- uniformly and the padata reading has to be qualified.
function probe.run(host, port, cfg, realm_name)
  local baseline = probe.classify(wire.request(host, port, cfg, realm_name, cfg.principal, false), cfg)
  local fast = probe.classify(wire.request(host, port, cfg, realm_name, cfg.principal, true), cfg)
  local control_name = string.format("nmap-nonexistent-%d", math.random(100000, 999999))
  local control = probe.classify(wire.request(host, port, cfg, realm_name, control_name, false), cfg)
  control.control_name = control_name
  return baseline, fast, control
end

-- 6. Analysis

local analysis = {}

-- The verdict table. Each entry states the condition that selects it, so the
-- report can show the reasoning instead of only the label.
function analysis.decide(baseline, fast, control)
  if baseline.kind == "no-answer" and fast.kind == "no-answer" then
    return "unreachable", "neither probe was answered"
  end

  -- A request that asked for protection and received a ticket was downgraded:
  -- RFC 6113 has the KDC process the FAST container, not ignore it.
  if fast.kind == "as_rep" then
    return "inconsistent", "the AS-REQ carried PA-FX-FAST and the KDC answered with a plain AS-REP, so the requested protection was ignored"
  end

  -- KDC_ERR_PADATA_TYPE_NOSUPP (16) is the KDC saying it has no PA-FX-FAST
  -- handler at all, which is the clearest possible statement of no support.
  if fast.error_code == 16 then
    return "not-supported", "the KDC answered KDC_ERR_PADATA_TYPE_NOSUPP (16) to a request that carried PA-FX-FAST"
  end

  local advertised = baseline.advertises_fast or fast.advertises_fast
  if not advertised then
    return "not-supported", "PA-FX-FAST (136) appeared in no answer, so the KDC does not advertise RFC 6113"
  end

  -- Advertised, and the unarmored request was answered without the salt: the
  -- KDC is withholding information until the client tunnels.
  if fast.kind == "krb_error" and not fast.discloses_salt and baseline.advertises_fast then
    return "required", "the KDC advertises PA-FX-FAST and withheld PA-ETYPE-INFO2 from the unarmored request"
  end

  if advertised then
    return "supported", "the KDC advertises PA-FX-FAST and answered the unarmored request without demanding armor"
  end
  return "supported", "PA-FX-FAST was advertised"
end

function analysis.evaluate(baseline, fast, control)
  local verdict, reason = analysis.decide(baseline, fast, control)
  local out = {
    verdict = verdict,
    reason = reason,
    baseline = baseline,
    fast = fast,
    control = control,
    answered = 0,
    uniform = false,
  }
  for _, row in ipairs({ baseline, fast, control }) do
    if row.kind ~= "no-answer" then
      out.answered = out.answered + 1
    end
  end
  -- The control tells the report whether padata readings can be trusted: a KDC
  -- that answers a name it does not have exactly like a name it does have is
  -- not telling the client anything about the account.
  if control.kind ~= "no-answer" and baseline.kind ~= "no-answer" then
    out.uniform = (control.kind == baseline.kind) and (control.error_code == baseline.error_code)
      and (#control.padata == #baseline.padata)
  end
  return out
end

-- 7. Reporting

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

local VERDICT_BY_ID = {}
for _, entry in ipairs(KB.VERDICTS) do
  VERDICT_BY_ID[entry.id] = entry
end

function report.findings(evaluation, cfg)
  local list = {}
  local function add(finding)
    list[#list + 1] = finding
  end

  if evaluation.answered == 0 then
    add({
      id = "KDC-UNREACHABLE",
      severity = "MEDIUM",
      title = "No AS-REQ received an answer",
      evidence = {
        string.format("timeout %d ms, transport %s, retries %d", cfg.timeout_ms, cfg.transport, cfg.retries),
        string.format("baseline: %s", tostring(evaluation.baseline.detail)),
      },
      impact = "The FAST policy of this KDC is unknown, and the report makes no claim about it.",
      remediation = "Confirm that UDP/88 and TCP/88 reach the controller, then re-run with kerberos.verbose=true.",
    })
    return list
  end

  local entry = VERDICT_BY_ID[evaluation.verdict]
  if entry then
    add({
      id = "FAST-" .. string.upper(evaluation.verdict),
      severity = entry.severity,
      title = string.format("FAST is %s on this KDC", evaluation.verdict == "not-supported" and "not implemented" or evaluation.verdict),
      evidence = {
        string.format("verdict: %s", entry.statement),
        string.format("reason: %s", evaluation.reason),
        string.format("baseline padata: %s", #evaluation.baseline.padata_names > 0
          and table.concat(evaluation.baseline.padata_names, ", ") or "none"),
        string.format("PA-FX-FAST probe: %s", tostring(evaluation.fast.detail)),
      },
      impact = entry.implication,
      remediation = entry.action,
    })
  end

  if evaluation.verdict == "inconsistent" then
    add({
      id = "FAST-DOWNGRADE",
      severity = "MEDIUM",
      title = "A request that asked for FAST was answered as if it had not",
      evidence = {
        string.format("probe: %s", tostring(evaluation.fast.detail)),
        string.format("baseline advertised PA-FX-FAST: %s", tostring(evaluation.baseline.advertises_fast)),
      },
      impact = "If the KDC advertises FAST and then ignores the request for it, a client cannot tell whether the answer came from the KDC or from something on the path that stripped the padata. The armor key exists precisely to make that distinction.",
      remediation = "Capture the exchange at the client and at the controller and compare the padata. If they differ, a middlebox is rewriting the request; if they are identical, the KDC's own handling is at fault.",
    })
  end

  if evaluation.baseline.advertises_fast and not evaluation.baseline.carries_cookie
    and not evaluation.fast.carries_cookie then
    add({
      id = "FAST-NO-COOKIE",
      severity = "LOW",
      title = "The KDC advertises PA-FX-FAST but never sends PA-FX-COOKIE",
      evidence = { "neither the advertisement nor the negotiation answer carried padata 133" },
      impact = "Without a cookie the KDC must keep per-request state while the negotiation runs, and RFC 6113 section 5.4.3 expects the cookie to be offered. A stateless KDC is harder to exhaust, so the difference matters on a busy controller.",
      remediation = "Confirm that the implementation and its patch level support RFC 6113 section 5.4.3; a KDC that advertises 136 without 133 is an implementation detail worth recording in the baseline.",
    })
  elseif evaluation.baseline.carries_cookie then
    add({
      id = "FAST-COOKIE",
      severity = "INFO",
      title = "PA-FX-COOKIE was offered with the advertisement",
      evidence = { string.format("padata: %s", table.concat(evaluation.baseline.padata_names, ", ")) },
      impact = "The KDC can answer a repeated negotiation without server state, which is what the cookie is for.",
      remediation = "No action required.",
    })
  end

  if evaluation.uniform then
    add({
      id = "FAST-CONTROL-UNIFORM",
      severity = "LOW",
      title = "The control name received the same answer as the real principal",
      evidence = {
        string.format("control %s: %s", tostring(evaluation.control.control_name), tostring(evaluation.control.detail)),
        string.format("baseline %s: %s", tostring(cfg.principal), tostring(evaluation.baseline.detail)),
      },
      impact = "Padata that a KDC sends for every name, including names it does not have, describes the realm's policy rather than the account's. The FAST advertisement is a realm property, so the verdict stands, but an account-specific reading from the same answer would not.",
      remediation = "Use a principal that is known to exist when the question is about an account rather than about the realm.",
    })
  end

  if #list == 0 then
    add({
      id = "NO-FINDINGS",
      severity = "INFO",
      title = "The FAST negotiation answered consistently",
      evidence = { string.format("verdict: %s", tostring(evaluation.reason)) },
      impact = "The KDC's behaviour matches the verdict, with no contradiction between the answers.",
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
  out["Probed principal"] = cfg.principal
  out["Target"] = string.format("%s (%s)", tostring(host.name or host.ip or "target"),
    tostring(port.number) .. "/" .. tostring(port.protocol or "tcp"))

  local entry = VERDICT_BY_ID[evaluation.verdict]
  out["FAST verdict"] = string.format("%s - %s", evaluation.verdict,
    entry and entry.statement or "the negotiation could not be classified")
  out["Verdict reason"] = evaluation.reason
  out["Advertised padata"] = #evaluation.baseline.padata_names > 0
    and evaluation.baseline.padata_names or "none in the baseline answer"

  local probes = {}
  for _, row in ipairs({ evaluation.baseline, evaluation.fast, evaluation.control }) do
    probes[#probes + 1] = string.format("%-34s %-10s %s", row.label, row.kind, tostring(row.detail))
    if #row.padata_names > 0 then
      probes[#probes + 1] = string.format("%-34s %-10s %s", "", "", table.concat(row.padata_names, ", "))
    end
  end
  out["Probes"] = probes
  out["PA-FX-FAST advertisement"] = evaluation.baseline.advertises_fast
    and "PA-FX-FAST (136) present: the KDC implements RFC 6113"
    or "PA-FX-FAST (136) absent from the baseline answer"
  out["Salt disclosure"] = evaluation.fast.discloses_salt
    and "the unarmored request still received PA-ETYPE-INFO2, so armoring is optional"
    or "the unarmored request received no etype information"
  out["Control probe"] = string.format("%s -> %s (uniform answers: %s)",
    tostring(evaluation.control.control_name), tostring(evaluation.control.detail), tostring(evaluation.uniform))

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

  local padata = {}
  for code, item in pairs(KB.PADATA) do
    padata[#padata + 1] = string.format("%d %s - %s", code, item.name, item.role)
  end
  table.sort(padata)
  out["Padata types read"] = padata

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
    transcript[#transcript + 1] = string.format("realm %s from %s; timeout %d ms; retries %d; transport %s",
      tostring(realm_result.realm), tostring(realm_result.source), cfg.timeout_ms, cfg.retries, cfg.transport)
    for _, row in ipairs({ evaluation.baseline, evaluation.fast, evaluation.control }) do
      transcript[#transcript + 1] = string.format("%-34s request=%s bytes answer=%s bytes rtt=%s ms carried PA-FX-FAST=%s",
        row.label, tostring(row.request_bytes), tostring(row.response_bytes), tostring(row.rtt_ms),
        tostring(row.carried_fast))
      if #row.padata > 0 then
        transcript[#transcript + 1] = string.format("%-34s padata: %s", "", table.concat(row.padata_names, ", "))
      end
    end
    out["Protocol transcript"] = transcript
  end

  if evaluation.verdict == "unreachable" then
    worst = "INCONCLUSIVE"
  end
  out["Risk Level"] = RISK_LABEL[worst] or worst
  return out
end

-- 8. Action

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local realm_name, realm_source = realm.resolve(host, effective_port, cfg)
  local realm_result = { realm = realm_name, source = realm_source }

  local baseline, fast, control = probe.run(host, effective_port, cfg, realm_name)
  local evaluation = analysis.evaluate(baseline, fast, control)
  return report.build(host, port, cfg, realm_result, evaluation)
end
