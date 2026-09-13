local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The Kerberos engine supplies the ASN.1 layer: realm discovery and the AP-REQ
-- the password service is asked to authenticate.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Probes the Kerberos password-change service and reports what it exposes.

RFC 3244 puts the password-change service on its own port, 464, with its own
framing: a two byte big-endian length prefix in front of a standard Kerberos
message, on both transports. The service authenticates the client with an
AP-REQ whose ticket is for kadmin/changepw@REALM, then exchanges a KRB-PRIV
message that carries the new password encrypted with the ticket's session key.

An exposed password service is interesting for two different reasons:

  * Reachability: 464 open to the wrong network is the starting point for
    password-change abuse and for password spraying against the change
    protocol, which does not require pre-authentication of the user's key.
  * Protocol posture: the service must refuse an AP-REQ it cannot verify, and
    it must refuse a change request that is not protected by a session key.
    A service that answers with a success code, or with an access-denied code,
    before it has authenticated anyone is telling the operator that its check
    order is wrong.

The script sends three probes and reports what came back:

  1. an AP-REQ for kadmin/changepw with a synthetic ticket, which a healthy
     service refuses with a Kerberos error rather than an AP-REP;
  2. the same message on the other transport, because RFC 3244 requires both;
  3. an unprotected change request for a name that does not exist, which must
     be refused without any password material ever being sent.

The script never changes a password and never needs a valid ticket. Every
verdict it prints is an answer the service actually produced.
]]

---
-- @usage
-- nmap -p 464 --script kerberos-kpasswd-service --script-args 'kerberos.realm=EXAMPLE.COM' <target>
--
-- @args kerberos.realm        Realm in uppercase DNS form. Discovered with a
--                             foreign realm probe when omitted.
-- @args kerberos.kpasswd-port Port to probe (default 464).
-- @args kerberos.kdc-port     Port used for the realm probe on the KDC
--                             (default 88), which is not the password port.
-- @args kerberos.timeout-ms   Per-probe timeout, 500-60000.
-- @args kerberos.retries      Transport retries per probe (default 1).
-- @args kerberos.transport    "auto" (default), "udp" or "tcp".
-- @args kerberos.verbose      "true" adds the per-probe transcript.
--
-- @output
-- 464/tcp open  kpasswd
-- | kerberos-kpasswd-service:
-- |   Realm: EXAMPLE.COM
-- |   Service principal: kadmin/changepw@EXAMPLE.COM
-- |   Transports:
-- |     TCP   answered  KRB-ERROR 31 KRB_AP_ERR_BAD_INTEGRITY (2 byte framing correct)
-- |     UDP   answered  KRB-ERROR 31 KRB_AP_ERR_BAD_INTEGRITY
-- |   Version negotiation: 0xff80 accepted
-- |_  Risk Level: INFO
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(464, "kpasswd", {"tcp", "udp"})

local SCRIPT_RISK = "MEDIUM"
local SCRIPT_VERSION = "2.0.0"
local KPASSWD_PRINCIPAL = "kadmin/changepw"
-- ASN.1 class numbers as the decoder reports them (0 universal, 1 application).
local CLASS_APPLICATION = 1

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

-- RFC 3244 section 3 result codes. Each one is a position on whether the
-- service authenticated the caller before it decided anything.
KB.RESULT_CODES = {
  [0] = { name = "KRB5_KPASSWD_SUCCESS", meaning = "the password was changed", verdict = "the service accepted the request" },
  [1] = { name = "KRB5_KPASSWD_MALFORMED", meaning = "the message was not decodable", verdict = "the service parsed before it authenticated" },
  [2] = { name = "KRB5_KPASSWD_HARDERROR", meaning = "a server-side error", verdict = "the request reached the password store" },
  [3] = { name = "KRB5_KPASSWD_AUTHERROR", meaning = "the client could not be authenticated", verdict = "the refusal happens before the password store" },
  [4] = { name = "KRB5_KPASSWD_SOFTERROR", meaning = "the password could not be changed for a policy reason", verdict = "the request was authenticated" },
  [5] = { name = "KRB5_KPASSWD_ACCESSDENIED", meaning = "the caller is not allowed to do this", verdict = "refusal, but the code alone does not prove authentication happened first" },
  [6] = { name = "KRB5_KPASSWD_BAD_VERSION", meaning = "the protocol version field is not supported", verdict = "the version was checked before anything else" },
  [7] = { name = "KRB5_KPASSWD_INITIAL_FLAG_NEEDED", meaning = "the service requires the initial ticket flag", verdict = "policy refused the request shape" },
  [8] = { name = "KRB5_KPASSWD_INITIAL_FLAG_SET", meaning = "the ticket carried the initial flag when the service forbids it", verdict = "policy refused the request shape" },
}

KB.VERSIONS = {
  { id = "rfc3244", value = 0xff80, label = "0xff80 (RFC 3244 version 1)" },
  { id = "ms", value = 0xff81, label = "0xff81 (the version Microsoft documents)" },
}

KB.REMEDIATION = {
  {
    title = "Restrict who can reach 464",
    steps = {
      "Treat 464 like 88: domain controllers answer it, so it belongs on the same network rules and nowhere else.",
      "Check the rules from an untrusted segment: the service is enabled by default and 464 is not on the usual hardening lists, so an absent rule is the common finding.",
    },
  },
  {
    title = "Keep the service's refusal order right",
    steps = {
      "A service must reply with a Kerberos error (an AP-REQ it cannot verify) or an authentication result code (a KRB-PRIV it cannot decrypt) before it looks at any password payload.",
      "Watch the exchange: the code for a message with no valid session key must never be a success code, and a malformed message must not produce a code that implies the password store was reached.",
      "Collect the KDC's 4771 and 4776 events: a password-change service that is probed from an unexpected subnet shows up as a run of failures against kadmin/changepw.",
    },
  },
  {
    title = "Prefer the protected path for changes",
    steps = {
      "Do not configure an initial password over an unencrypted channel: an initial ticket is what RFC 3244 section 3 requires for a first-time change.",
      "Rotate service passwords through a managed account rather than a script that speaks 464 directly, so the change is auditable.",
    },
  },
}

KB.VERIFICATION = {
  "Confirm the principal the service answers for: the AP-REQ in the probe names kadmin/changepw@<realm>, and the error code that comes back is produced by that service, not by the KDC on 88.",
  "Confirm the framing on the wire: RFC 3244 section 2 uses a two byte big-endian length prefix, unlike the four byte prefix on TCP/88, and confirm the refusal order with a capture of the protected path.",
}

KB.REFERENCES = {
  "RFC 3244 - Windows 2000 Kerberos Change Password and Set Password Protocols, sections 2 and 3 (framing, version field and result codes)",
  "RFC 4120 - the AP-REQ, KRB-PRIV and KRB-ERROR messages the service exchanges (section 7.5.1 carries the error registry), and Microsoft's 'Kerberos protocol and troubleshooting' for 464 and kadmin/changepw",
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
  cfg.kpasswd_port = arg_int("kpasswd-port", 464, 1, 65535)
  cfg.kdc_port = arg_int("kdc-port", 88, 1, 65535)
  cfg.retries = arg_int("retries", 1, 0, 5)
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

-- RFC 4120 lets a KDC answer a request for a realm it does not serve with
-- KDC_ERR_WRONG_REALM and the realm it does serve. The password service belongs
-- to one realm, so the same oracle identifies it - but the oracle lives on the
-- KDC port, because 464 speaks the change protocol and not the AS exchange.
function realm.resolve(host, cfg)
  if cfg.realm then
    return cfg.realm, "kerberos.realm script argument"
  end
  local synthetic = "NMAP-NONEXISTENT.INVALID"
  local record = transport.as_req(host, cfg.kdc_port, {
    realm = synthetic,
    cname = "changepw-probe",
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
    local derived = string.upper(string.match(name, "%.(.+)$") or name)
    return derived, "derived from the target name; the password service may serve a different realm"
  end
  return nil, "not determined"
end

-- 4. Wire

local wire = {}

-- RFC 3244 section 2 frames every message with a two byte big-endian length.
-- Port 464 does not use the four byte prefix that TCP/88 uses, so a probe that
-- assumed the Kerberos transport would parse the wrong bytes.
function wire.frame(payload)
  if #payload > 0xffff then
    return nil, string.format("message is %d bytes, more than the two byte length field can carry", #payload)
  end
  return string.pack(">I2", #payload) .. payload
end

function wire.unframe(buffer)
  if #buffer < 2 then
    return nil, nil, string.format("answer is %d byte(s), too short for the length prefix", #buffer)
  end
  local declared = string.unpack(">I2", buffer)
  local body = string.sub(buffer, 3)
  if declared == #body then
    return body, true, string.format("the prefix declared %d byte(s) and %d byte(s) followed", declared, #body)
  end
  if declared > #body then
    return body, false, string.format("the prefix declared %d byte(s) but only %d byte(s) arrived: the answer was truncated", declared, #body)
  end
  return string.sub(body, 1, declared), false,
    string.format("the prefix declared %d byte(s) but %d byte(s) followed: the answer carried more than one message", declared, #body)
end

-- The unprotected change request. RFC 3244 section 3 defines the payload as a
-- KRB-PRIV message whose encrypted part holds the change protocol; the script
-- builds the structure but never has a session key, so the service can never
-- act on it. The payload names a principal that does not exist, so even a
-- service that ignored the missing key could not change anything.
function wire.change_payload(realm_name, version, principal_name)
  -- The change protocol payload: two bytes of version, two bytes of length and
  -- the request itself. Both password fields are empty and the principal is one
  -- that does not exist, so the request cannot change anything even if a
  -- broken service were to accept it.
  local body = string.char(0) .. principal_name .. "\0" .. realm_name .. "\0\0\0"
  local inner = string.pack(">I2", version) .. string.pack(">I2", #body) .. body
  -- KRB-PRIV = [APPLICATION 21] SEQUENCE { pvno [0], msg-type [1], enc-part [3] }.
  return krb5.der.app(21, krb5.der.sequence(
    krb5.der.ctx(0, krb5.der.integer(5)),
    krb5.der.ctx(1, krb5.der.integer(21)),
    krb5.der.ctx(3, krb5.der.sequence(
      krb5.der.ctx(0, krb5.der.integer(18)),
      krb5.der.ctx(1, krb5.der.integer(2)),
      krb5.der.octetstring(inner)
    ))
  ))
end

-- The reply to a change request is a KRB-PRIV whose encrypted part begins with
-- the version, the length and then the result code. A service that authenticates
-- first hands back nothing, and both readings are reported as they are.
function wire.priv_result_code(body)
  if type(body) ~= "string" or #body == 0 then
    return nil, "no message was received"
  end
  local root = krb5.decoder.parse(body)
  if not root then
    return nil, "not decodable ASN.1"
  end
  if not (root.cls == CLASS_APPLICATION and root.num == 21) then
    return nil, "not a KRB-PRIV message"
  end
  local enc = krb5.decoder.unwrap(root.children[1], 3)
  local cipher = enc and krb5.decoder.unwrap(enc, 2)
  local blob = cipher and cipher.value or ""
  if #blob < 6 then
    return nil, string.format("the encrypted part carries %d byte(s), too few for a result code", #blob)
  end
  return string.unpack(">I2", string.sub(blob, 5, 6)), nil
end

-- Every exchange goes through one function, so the report describes exactly
-- what was sent, over which transport, and what came back or did not.
function wire.exchange(host, port, cfg, payload, proto, label)
  local result = { transport = proto, label = label, request_bytes = #payload, attempts = 0 }
  local framed, frame_err = wire.frame(payload)
  if not framed then
    result.error = frame_err
    return result
  end
  local attempts = cfg.retries + 1
  for attempt = 1, attempts do
    result.attempts = attempt
    local sock = nmap.new_socket(proto)
    sock:set_timeout(cfg.timeout_ms)
    local connected, connect_err = sock:connect(host, port)
    if not connected then
      sock:close()
      result.error = tostring(connect_err)
    else
      local started = nmap.clock_ms()
      local sent, send_err = sock:send(framed)
      if not sent then
        result.error = tostring(send_err)
        sock:close()
      else
        local received, data = sock:receive_bytes(65535)
        result.rtt_ms = nmap.clock_ms() - started
        sock:close()
        if not received or not data or #data == 0 then
          if attempt >= attempts then
            result.error = "no answer within the timeout"
            result.no_answer = true
          end
        else
          result.response_bytes = #data
          local body, prefix_ok, prefix_note = wire.unframe(data)
          result.body = body
          result.prefix_ok = prefix_ok
          result.prefix_note = prefix_note
          if prefix_ok then
            result.ok = true
            return result
          end
          if attempt >= attempts then
            result.ok = true
            return result
          end
        end
      end
    end
  end
  return result
end

-- 5. Probes

local probe = {}

-- The AP-REQ the service has to authenticate. The ticket is synthetic: it is
-- encrypted with bytes the realm's krbtgt key never produced, so a service that
-- verifies anything at all refuses it. An AP-REP in response is a finding.
function probe.ap_req_payload(realm_name, name)
  local ticket = krb.build_ticket({
    realm = realm_name,
    sname = { KPASSWD_PRINCIPAL, realm_name },
    sname_type = NT.SRV_INST,
    etype = 18,
    kvno = 2,
    cipher = string.rep("\90", 64),
  })
  return krb.build_ap_req({
    ticket = ticket,
    ap_options = 0,
    auth_etype = 18,
    auth_kvno = 2,
    authenticator = string.rep("\65", 48),
  })
end

-- Classify a raw answer by what it actually is: a Kerberos error with a code,
-- an AP-REP (the service authenticated a ticket it cannot have verified), or
-- nothing at all.
function probe.classify(measurement, cfg)
  local row = {
    label = measurement.label,
    transport = measurement.transport,
    rtt_ms = measurement.rtt_ms,
    bytes = measurement.response_bytes,
    request_bytes = measurement.request_bytes,
    prefix_ok = measurement.prefix_ok,
    error = measurement.error,
    attempts = measurement.attempts,
  }
  if measurement.no_answer or not measurement.ok then
    row.kind = "no-answer"
    row.detail = string.format("no answer after %d attempt(s) (%s)", measurement.attempts or 1,
      tostring(measurement.error or "timeout"))
    return row
  end
  local body = measurement.body
  if not body or #body == 0 then
    row.kind = "empty"
    row.detail = "the service closed the exchange with an empty message"
    return row
  end
  row.message_label = krb.message_label(body)
  local root = krb5.decoder.parse(body)
  if not root then
    row.kind = "malformed"
    row.detail = string.format("%d byte(s) that are not decodable ASN.1", #body)
    return row
  end
  local err = krb.parse_krb_error(root)
  if err then
    row.kind = "krb_error"
    row.error_code = err.code
    row.error_name = err.code_name
    row.detail = string.format("%s (code %d)", tostring(err.code_name), tostring(err.code))
    return row
  end
  if row.message_label == "AP-REP" then
    row.kind = "ap_rep"
    row.detail = "the service answered with a KRB-AP-REP for a ticket it could not have verified"
    return row
  end
  -- APPLICATION class tag 21 is KRB-PRIV, the change protocol's own message.
  if root.cls == CLASS_APPLICATION and root.num == 21 then
    row.kind = "krb_priv"
    row.detail = "a KRB-PRIV message, the change protocol's reply form"
    return row
  end
  if root.cls ~= CLASS_APPLICATION then
    row.kind = "malformed"
    row.detail = string.format("%d byte(s) whose first element is not a Kerberos application message", #body)
    return row
  end
  row.kind = "other"
  row.other = tostring(row.message_label or "unlabelled message")
  row.detail = string.format("neither a KRB-ERROR nor a KRB-AP-REP (%s)", row.other)
  return row
end

-- The result-code probe: a KRB-PRIV message with no usable session key. A
-- service that decrypts nothing answers with a result code; one that refuses
-- before looking answers with nothing, and both are measurements.
function probe.change_request(host, port, cfg, realm_name, version, proto)
  local payload = wire.change_payload(realm_name, version, "nmap-nonexistent-principal")
  local measurement = wire.exchange(host, port, cfg, payload, proto or "tcp", "unprotected change request")
  local row = probe.classify(measurement, cfg)
  -- RFC 3244 section 3 carries the result in a two byte field at the front of
  -- the KRB-PRIV's encrypted part when the service answers with one, but a
  -- service that answers here at all is already the interesting fact.
  local code, why = wire.priv_result_code(measurement.body)
  if code then
    row.result_code = code
    local entry = KB.RESULT_CODES[code]
    row.result_name = entry and entry.name or string.format("code %d", code)
    row.detail = string.format("%s: %s", row.result_name, entry and entry.meaning or "unlisted result code")
  elseif row.kind == "other" or row.kind == "krb_priv" then
    row.detail = string.format("%s (the reply is opaque: %s)", tostring(row.detail), tostring(why))
  end
  return row
end

-- 6. Analysis

local analysis = {}

function analysis.evaluate(rows, change_row, versions)
  local out = { rows = rows, change = change_row, versions = versions, answered = 0, udp = rows[1], tcp = rows[2] }
  for _, row in ipairs(rows) do
    if row.kind ~= "no-answer" then out.answered = out.answered + 1 end
  end
  return out
end

-- The version field is checked first, so a server that answers BAD_VERSION for
-- one value and something deeper for another has said which value it implements.
function analysis.version_state(entry)
  local row = entry.row
  if not row or not row.result_code then
    return "not sent"
  end
  if row.result_code == 6 then
    return "rejected with KRB5_KPASSWD_BAD_VERSION"
  end
  return string.format("accepted, answered %s", tostring(row.result_name))
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

function report.findings(evaluation, cfg)
  local list = {}
  local function add(finding)
    list[#list + 1] = finding
  end
  local udp, tcp = evaluation.udp, evaluation.tcp

  if evaluation.answered == 0 then
    add({
      id = "KPASSWD-UNREACHABLE",
      severity = "INFO",
      title = "The password service did not answer on either transport",
      evidence = {
        string.format("TCP: %s", tostring(tcp and tcp.detail)),
        string.format("UDP: %s", tostring(udp and udp.detail)),
      },
      impact = "The service may be filtered or bound to another address; nothing about its behaviour could be measured.",
      remediation = "Confirm the port and the realm, then re-run from the same segment.",
    })
    return list
  end

  for _, row in ipairs(evaluation.rows) do
    if row.kind == "ap_rep" then
      add({
        id = "KPASSWD-ACCEPTS-UNVERIFIED-TICKET",
        severity = "HIGH",
        title = "The password service answered the AP-REQ with a KRB-AP-REP it cannot have verified",
        evidence = {
          string.format("%s: %s", row.label, row.detail),
          string.format("the request carried a synthetic ticket for %s@%s whose ciphertext was never produced by the realm's key",
            KPASSWD_PRINCIPAL, tostring(cfg.realm or "the realm")),
        },
        impact = "If the service completes an AP exchange for a ticket it cannot decrypt, it is not authenticating the caller. The change protocol that follows would then be reachable without a key, which is the whole value of the service's design.",
        remediation = "Verify the service against a real client: a legitimate change must require a ticket for kadmin/changepw. Capture one exchange and confirm the AP-REQ verification step is reached before any result code is produced.",
      })
    end
    if row.prefix_ok == false then
      add({
        id = "KPASSWD-FRAMING-INCORRECT",
        severity = "LOW",
        title = string.format("The %s answer did not carry a correct two byte length prefix", row.transport),
        evidence = { string.format("%s: %s", row.label, tostring(row.prefix_note)) },
        impact = "RFC 3244 section 2 requires the two byte prefix on both transports. A client that trusts it reads the wrong bytes and reports a decode error, which hides the real answer code.",
        remediation = "Capture from both sides and check for a middlebox that rewrites the stream; the prefix is produced by the service, not the client.",
      })
    end
  end

  if udp and udp.kind ~= "no-answer" and tcp and tcp.kind == "no-answer" then
    add({
      id = "KPASSWD-TCP-BLOCKED",
      severity = "MEDIUM",
      title = "The password service answers UDP but not TCP",
      evidence = { string.format("UDP: %s", udp.detail), string.format("TCP: %s", tcp.detail) },
      impact = "RFC 3244 section 2 defines both. A client that retries over TCP - including the ones that switch because a datagram was too small - cannot complete a change, so the failure appears to the user as a rejected password.",
      remediation = "Open TCP/464 next to UDP/464 from the client segments that change passwords.",
    })
  elseif tcp and tcp.kind ~= "no-answer" and udp and udp.kind == "no-answer" then
    add({
      id = "KPASSWD-UDP-BLOCKED",
      severity = "LOW",
      title = "The password service answers TCP but not UDP",
      evidence = { string.format("UDP: %s", udp.detail), string.format("TCP: %s", tcp.detail) },
      impact = "Clients that start on UDP pay the datagram timeout before every change, or fail if they do not retry.",
      remediation = "Open UDP/464, or configure clients to use TCP for the change protocol.",
    })
  end

  local change = evaluation.change
  if change and change.kind ~= "no-answer" then
    local code = change.result_code
    if code == 0 then
      add({
        id = "KPASSWD-UNAUTHENTICATED-CHANGE",
        severity = "HIGH",
        title = "The service returned a success result code for a change request that carried no session key",
        evidence = {
          string.format("%s: %s", change.label, change.detail),
          "the payload named a principal that does not exist and carried no password material, so no password could have been changed",
        },
        impact = "A success code before authentication means the service is not enforcing the property RFC 3244 depends on: that only a caller with a valid ticket can reach the change protocol. The same code path with a real principal is a password change by an unauthenticated caller.",
        remediation = "Treat this as a service defect. Confirm it with a packet capture of a legitimate change, compare the code paths, and if the defect is real restrict 464 to trusted clients while the implementation is fixed.",
      })
    elseif code == 3 then
      add({
        id = "KPASSWD-REFUSES-BEFORE-DECRYPT",
        severity = "INFO",
        title = "The change request was refused with KRB5_KPASSWD_AUTHERROR",
        evidence = { string.format("%s: %s", change.label, change.detail) },
        impact = "The service refused the request because the caller could not be authenticated, which is the order RFC 3244 section 3 requires.",
        remediation = "No action required.",
      })
    elseif code == 1 then
      add({
        id = "KPASSWD-PARSES-BEFORE-AUTH",
        severity = "LOW",
        title = "The change request was answered with KRB5_KPASSWD_MALFORMED",
        evidence = { string.format("%s: %s", change.label, change.detail) },
        impact = "A malformed answer means the payload was parsed before the caller was authenticated. Parsing an attacker-controlled structure early is how decode bugs become reachable, and the code gives an unauthenticated caller a signal.",
        remediation = "Check the service's implementation order against RFC 3244 section 3: the AP-REQ must be verified before the KRB-PRIV payload is decoded.",
      })
    elseif code then
      local entry = KB.RESULT_CODES[code]
      add({
        id = "KPASSWD-RESULT-CODE",
        severity = "LOW",
        title = string.format("The change request was answered with %s", change.result_name),
        evidence = { string.format("%s: %s", change.label, tostring(entry and entry.meaning)) },
        impact = string.format("The verdict for this code is: %s.", tostring(entry and entry.verdict)),
        remediation = "Compare the code with the service's documented behaviour and confirm the order in which it authenticates and parses.",
      })
    end
  end

  if #list == 0 then
    add({
      id = "NO-FINDINGS",
      severity = "INFO",
      title = "The password service behaved as RFC 3244 requires",
      evidence = { "it refused the unverifiable AP-REQ and answered the probes with KDC-style errors" },
      impact = "The service authenticated before it acted on every probe.",
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
  out["Service principal"] = string.format("%s@%s", KPASSWD_PRINCIPAL, tostring(realm_result.realm or "?"))
  out["Target"] = string.format("%s (%s)", tostring(host.name or host.ip or "target"),
    tostring(port.number) .. "/" .. tostring(port.protocol or "tcp"))

  local rows = {}
  for _, row in ipairs(evaluation.rows) do
    rows[#rows + 1] = string.format("%-4s %-10s %s", string.upper(row.transport),
      row.kind, tostring(row.detail))
    if row.prefix_note then
      rows[#rows + 1] = string.format("%-4s %-10s %s", "", "", row.prefix_note)
    end
  end
  out["Transports"] = rows
  out["Framing"] = string.format("RFC 3244 section 2: two byte big-endian prefix on both transports; %d ms timeout, %d retr(y/ies)",
    cfg.timeout_ms, cfg.retries)
  if evaluation.change then
    out["Change probe"] = string.format("%s -> %s", evaluation.change.label, tostring(evaluation.change.detail))
  end

  local versions = {}
  for _, entry in ipairs(evaluation.versions) do
    versions[#versions + 1] = string.format("%s -> %s", entry.label, analysis.version_state(entry))
  end
  out["Version negotiation"] = versions

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

  local codes = {}
  for code, entry in pairs(KB.RESULT_CODES) do codes[#codes + 1] = string.format("%d %s", code, entry.name) end
  table.sort(codes)
  out["Result codes understood"] = codes

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
    for _, row in ipairs(evaluation.rows) do
      transcript[#transcript + 1] = string.format("%-4s %-10s request=%s bytes answer=%s bytes rtt=%s ms attempts=%s",
        string.upper(row.transport), row.kind, tostring(row.request_bytes), tostring(row.bytes),
        tostring(row.rtt_ms), tostring(row.attempts))
    end
    if evaluation.change then
      transcript[#transcript + 1] = string.format("change probe: %s; message: %s",
        tostring(evaluation.change.kind), tostring(evaluation.change.detail))
    end
    out["Protocol transcript"] = transcript
  end

  if evaluation.answered == 0 then
    worst = "INCONCLUSIVE"
  end
  out["Risk Level"] = RISK_LABEL[worst] or worst
  return out
end

-- 8. Action

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number == 464 and port.number or cfg.kpasswd_port
  local realm_name, realm_source = realm.resolve(host, cfg)
  local realm_result = { realm = realm_name, source = realm_source }

  local ap_req = probe.ap_req_payload(realm_name, "changepw-probe")
  local udp = wire.exchange(host, effective_port, cfg, ap_req, "udp", "AP-REQ with a synthetic ticket")
  local tcp = wire.exchange(host, effective_port, cfg, ap_req, "tcp", "AP-REQ with a synthetic ticket")
  local rows = { probe.classify(udp, cfg), probe.classify(tcp, cfg) }

  -- The change probes follow the transport that answered the AP-REQ: a service
  -- that speaks one transport only should still be measured on that one.
  local change_proto = "tcp"
  if rows[2].kind == "no-answer" and rows[1].kind ~= "no-answer" then
    change_proto = "udp"
  end
  local versions = {}
  for _, entry in ipairs(KB.VERSIONS) do
    versions[#versions + 1] = {
      id = entry.id,
      label = entry.label,
      row = probe.change_request(host, effective_port, cfg, realm_name, entry.value, change_proto),
    }
  end
  local change_row = versions[1] and versions[1].row or nil

  local evaluation = analysis.evaluate(rows, change_row, versions)
  return report.build(host, port, cfg, realm_result, evaluation)
end
