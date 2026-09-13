local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The wire engine owns framing, version negotiation and the SASL exchange.
local ok, kafka = pcall(require, "kafka")
-- The listener probe answers one question with a real ClientHello: is this port
-- speaking TLS, or is it a plaintext protocol that merely shares the port with
-- the encrypted listener Kafka deployments usually run?
local has_tls, tlsprobe = pcall(require, "tlsprobe")
-- Findings are published through Nmap's vulnerability machinery when it is
-- available; both the class-based Nmap API and the test harness's stand-in are
-- supported by the adapter below.
local has_vulns, vulns_lib = pcall(require, "vulns")

local SCRIPT_NAME = "kafka-plain-auth-over-cleartext"
local SCRIPT_RISK = "MEDIUM"
local SCRIPT_VERSION = "2.0.0"

description = [[
Determines whether a Kafka listener accepts SASL/PLAIN credentials over a
connection that is not protected by TLS, and shows what an observer receives.

PLAIN (RFC 4616) puts the password on the wire inside the SaslAuthenticate
payload: a zero byte, the username, a zero byte, the password. That is safe on a
SASL_SSL listener and a disclosure on a SASL_PLAINTEXT one, where anything that
can see the stream reads the password as the client types it.

The two questions are answered separately. A real TLS ClientHello goes first: a TLS
listener answers with a handshake record or an alert naming the reason it refused,
and a plaintext listener cannot produce either, so the transport is classified from
bytes rather than from a port number. SaslHandshake then reads the offered
mechanisms and one SaslAuthenticate carries the token, whose length and structure
the report states while the password stays unprinted and the identity is a
generated sentinel rather than a real account.

The same run reports whether Metadata is answered without a SASL exchange, whether
connections.max.reauth.ms is configured and which listener settings DescribeConfigs
exposes. It is read-only: ApiVersions, Metadata, DescribeConfigs, SaslHandshake and
at most one SaslAuthenticate.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-plain-auth-over-cleartext <target>
-- nmap -p 9094 --script kafka-plain-auth-over-cleartext --script-args kafka.user=svc-audit <target>
-- @args kafka.timeout      Per-request timeout in milliseconds (default 5000).
-- @args kafka.client-id    Client id used in every request header.
-- @args kafka.user         Username to attempt with; a generated probe name is
--                          used otherwise, so a real account is never locked out.
-- @args kafka.password     Password for kafka.user; a generated sentinel is used
--                          otherwise, so no credential that matters is spent.
-- @args kafka.mechanism    Mechanism to attempt (default "PLAIN").
-- @args kafka.tls-probe    "true" (default) sends the ClientHello first.
-- @args kafka.verbose      "true" adds the per-stage transcript.

local function vuln_publisher(host, port)
  if not has_vulns or type(vulns_lib) ~= "table" then return nil end
  local ok_pub, publisher = pcall(function()
    if type(vulns_lib.Report) == "table" and type(vulns_lib.Report.new) == "function" then
      local report = vulns_lib.Report:new(SCRIPT_NAME, host, port)
      return function(id, title, detail)
        report:add(id, title, { format = function() return detail end })
      end
    end
    if type(vulns_lib.Report) == "function" then
      local report = vulns_lib.Report(host, port)
      return function(id, title, detail)
        report.add(host, port, id, title, { format = function() return detail end })
      end
    end
    return nil
  end)
  if ok_pub and type(publisher) == "function" then return publisher end
  return nil
end

local function publish_findings(host, port, list)
  local publish = vuln_publisher(host, port)
  if not publish then return end
  for _, item in ipairs(list) do
    if item.severity == "CRITICAL" or item.severity == "HIGH" or item.severity == "MEDIUM" then
      publish(item.id, item.title, item.detail)
    end
  end
end

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service({9092, 9093, 9094, 9095, 19092, 29092}, "kafka", {"tcp"})

-- 1. Configuration

local function arg_string(name, default, max_length)
  local raw = nmap.registry.args and nmap.registry.args[name]
  if raw == nil then return default end
  raw = tostring(raw)
  if max_length and #raw > max_length then raw = string.sub(raw, 1, max_length) end
  return raw
end

local function arg_number(name, default, minimum, maximum)
  local raw = nmap.registry.args and nmap.registry.args[name]
  local value = raw ~= nil and tonumber(raw) or nil
  if not value then return default end
  return math.max(minimum, math.min(maximum, math.floor(value)))
end

local function arg_bool(name, default)
  local raw = nmap.registry.args and nmap.registry.args[name]
  if raw == nil then return default end
  raw = string.lower(tostring(raw))
  return raw == "1" or raw == "true" or raw == "yes" or raw == "on"
end

-- The generated identity is deliberately invalid, so a scan cannot lock an
-- account out and cannot be mistaken for a login by an operator reading the
-- broker log. The sentinel secret is long enough to be visible on the wire and
-- obviously not a credential when it appears in a report.
local function read_config()
  local supplied_user = arg_string("kafka.user", nil, 128)
  local supplied_password = arg_string("kafka.password", nil, 256)
  return {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000), client_id = arg_string("kafka.client-id", "nmap-kafka-plain-audit", 120),
    mechanism = string.upper(arg_string("kafka.mechanism", "PLAIN", 32)), tls_probe = arg_bool("kafka.tls-probe", true),
    verbose = arg_bool("kafka.verbose", false), user = supplied_user or string.format("nmap-plain-probe-%06d", math.random(0, 999999)),
    password = supplied_password or string.format("nmap-sentinel-%d-%06d-not-a-credential", os.time() % 1000000, math.random(0, 999999)),
    user_supplied = supplied_user ~= nil, password_supplied = supplied_password ~= nil, config_probe = arg_bool("kafka.config-probe", true), }
end

-- 2. Formatting helpers

local function fmt_bool(value)
  if value == nil then return "unknown" end
  return value and "yes" or "no"
end

local function plural(count, singular, plural_form)
  count = tonumber(count) or 0
  return string.format("%d %s", count, count == 1 and singular or (plural_form or (singular .. "s")))
end

local function num_text(value)
  if value == nil then return "n/a" end
  if type(value) ~= "number" then return tostring(value) end
  if value == math.floor(value) and math.abs(value) < 1e15 then
    return string.format(value < 0 and "-%d" or "%d", math.abs(value))
  end
  return string.format("%.3f", value)
end

local function fmt_list(values, limit, empty_text)
  if not values or #values == 0 then return empty_text or "none" end
  local out = {}
  for index = 1, math.min(#values, limit or 6) do out[#out + 1] = tostring(values[index]) end
  if #values > (limit or 6) then out[#out + 1] = string.format("(+%d more)", #values - (limit or 6)) end
  return table.concat(out, ", ")
end

local function finding(id, title, severity, detail, evidence, remediation)
  return { id = id, title = title, severity = severity, detail = detail, evidence = evidence or {}, remediation = remediation or {} }
end

local function worst(list, default)
  local level, text = -1, default
  for _, item in ipairs(list) do
    local value = kafka.SEVERITY_ORDER[item.severity]
    if value and value > level then level, text = value, item.severity end
  end
  return text
end

-- A one-line tally of what the run produced, so the headline states the shape of
-- the result rather than a single word.
local function severity_summary(list)
  local parts = {}
  for _, severity in ipairs({ "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }) do
    local count = 0
    for _, item in ipairs(list) do if item.severity == severity then count = count + 1 end end
    if count > 0 then parts[#parts + 1] = string.format("%s x%d", severity, count) end
  end
  return #parts > 0 and table.concat(parts, ", ") or "no findings"
end

-- The credential is reported by shape, never by value, so the report shows that
-- a credential crossed the wire without becoming a second copy of it.
local function masked_token_summary(user, password)
  return string.format("\\0%s\\0<password: %d byte(s), not printed>", tostring(user), #password)
end

-- Declared here because the analysis quotes it; the tables are filled in below.
local KB = {}

-- 3. Connection wrapper

local Wire = {}
Wire.__index = Wire

function Wire.new(host, port, cfg, client_id)
  local self = setmetatable({}, Wire)
  self.cfg = cfg
  self.host = host
  self.port = port
  self.stages = {}
  self.failures = {}
  self.connection = kafka.new_connection(host.ip or host.name or "target", port.number, {
    timeout_ms = cfg.timeout, client_id = client_id or cfg.client_id, })
  return self
end

function Wire:stage(name, detail, ok)
  self.stages[#self.stages + 1] = { name = name, detail = detail, ok = ok ~= false }
  return self
end

function Wire:fail(stage, reason)
  self.failures[#self.failures + 1] = { stage = stage, reason = tostring(reason) }
  self:stage(stage, tostring(reason), false)
  return self
end

function Wire:close()
  if self.connection and self.connection.close then self.connection:close() end
  return self
end

function Wire:call(stage, fn)
  local ok_call, result, err = pcall(fn)
  local error_text = (not ok_call) and ("probe error: " .. tostring(result))
    or ((not result) and (err or "no response") or nil)
  if error_text then
    self:fail(stage, error_text)
    return { ok = false, error = error_text, stage = stage }
  end
  self:stage(stage, "answered")
  return result
end

function Wire:version(key, preference)
  if self.connection.versions and next(self.connection.versions) ~= nil then
    return kafka.version_for(self.connection, key, preference)
  end
  return preference
end

-- 4. Probes

local probe = {}

-- The listener classification is the first thing the report needs, because every
-- later statement depends on it: PLAIN over TLS is a configuration choice, PLAIN
-- over a plaintext socket is a disclosure.
function probe.listener(host, port, cfg)
  if not has_tls or type(tlsprobe) ~= "table" then
    return { kind = "unavailable",
      summary = "the TLS probe module (nselib/tlsprobe.lua) is not installed, so the transport " .. "could not be classified and no claim is made about encryption" }
  end
  if not cfg.tls_probe then
    return { kind = "skipped", summary = "the TLS probe is disabled (kafka.tls-probe=false)" }
  end
  local result = tlsprobe.probe(host.ip or host.name or "target", port.number, {
    timeout_ms = math.min(cfg.timeout, 5000), hostname = host.name or host.targetname, read_bytes = 4096, })
  local out = { kind = result.kind, summary = result.summary }
  for _, key in ipairs({ "bytes", "record_type", "record_type_name", "alert_name", "alert_level_name", "handshake_name", "negotiated_version_text", "cipher_suite_name",
    "cipher_strength", "cipher_note", "alpn", "preview", "hello_bytes", "truncated" }) do
    out[key] = result[key]
  end
  if result.kind == "tls-server-hello" or result.kind == "tls-alert" or result.kind == "tls-record" then
    out.encrypted, out.transport_source = true, "tls-reply"
    out.protocol_name = "SASL_SSL"
  elseif result.kind == "not-tls" then
    -- Something answered and it was not a TLS record, so the listener is
    -- plaintext; the protocol probe says which plaintext protocol answered.
    out.encrypted, out.transport_source = false, "non-tls-reply"
    out.protocol_name = "SASL_PLAINTEXT"
    out.needs_protocol_confirmation = true
  elseif result.kind == "silent" or result.kind == "empty" then
    -- Silence alone proves nothing: a plaintext Kafka listener reads the first
    -- four bytes of the hello as a ~369 MB frame length and waits, so it looks
    -- exactly like a filtered port. The protocol exchange decides which it is.
    out.transport_source = "hello-unanswered"
    out.needs_protocol_confirmation = true
  end
  return out
end

function probe.negotiate(w)
  local result = w:call("api_versions", function() return kafka.negotiate(w.connection, {}) end)
  if not result.ok then return { answered = false, error = result.error } end
  local version = result.value or {}
  w:stage("api_versions", string.format("%s advertised", plural(version.count or 0, "API")))
  return { answered = true, count = version.count, error_name = version.error_name, error_code = version.error_code, throttle_ms = version.throttle_ms }
end

function probe.metadata(w)
  local version = w:version(3, 12)
  if not version then return { answered = false, error = "the broker does not advertise Metadata" } end
  local result = w:call("metadata", function()
    return kafka.metadata(w.connection, nil, { version = version, auto_create = false })
  end)
  if not result.ok then return { answered = false, error = result.error, version = version } end
  local topics = result.topics or {}; local first = topics[1] or {}
  return { answered = true, version = version, topic_count = #topics, error_code = first.error_code, error_name = first.error_name, error_message = first.error_message }
end

-- The handshake is the only way to read the mechanism list: an unknown name is
-- answered with UNSUPPORTED_SASL_MECHANISM and, in the same record, the offer.
function probe.mechanisms(w, requested)
  local result = kafka.sasl_handshake(w.connection, requested or "NMAP-PROBE", {})
  if not result.ok then
    w:fail("sasl_handshake", tostring(result.error))
    return { answered = false, error = result.error, version = result.version }
  end
  w:stage("sasl_handshake", string.format("error %s, %s offered", tostring(result.error_name), plural(#(result.mechanisms or {}), "mechanism")))
  return { answered = true, version = result.version, error_code = result.error_code,
    error_name = result.error_name, mechanisms = result.mechanisms or {}, requested = requested }
end

-- One authentication attempt; the token is built by the engine, not reimplemented here.
function probe.authenticate(w, mechanism, user, password)
  local out = { mechanism = mechanism, attempt_user = user, password_bytes = #(password or "") }
  if mechanism ~= "PLAIN" then
    out.unsupported_by_script = true
    out.status = "not-attempted"
    out.reason = string.format("this script performs the PLAIN exchange only; %s was left to "
      .. "kafka-sasl-mechanism-audit.nse, which implements the full exchange", mechanism)
    return out
  end
  local attempt = kafka.sasl_auth_plain(w.connection, user, password, {})
  if not attempt.ok then
    w:fail("sasl_plain", tostring(attempt.error))
    out.status = "error"
    out.error = attempt.error
    return out
  end
  out.offered = attempt.offered
  out.status = attempt.status
  local handshake = attempt.handshake or {}
  out.handshake_error, out.handshake_error_code = handshake.error_name, handshake.error_code
  local auth = attempt.authenticate or {}
  out.error_code = auth.error_code or handshake.error_code
  out.error_name = auth.error_name or handshake.error_name
  out.error_message = auth.error_message
  out.auth_bytes = #(auth.auth_bytes or "")
  out.session_lifetime_ms = auth.session_lifetime_ms
  out.version = auth.version
  w:stage("sasl_plain", string.format("%s (%s)", tostring(out.status), tostring(out.error_name or "-")))
  return out
end

function probe.describe_configs(w)
  local version = w:version(32, 4)
  if not version then return { skipped = "the broker does not advertise DescribeConfigs" } end
  local result = w:call("describe_configs", function()
    return kafka.describe_configs(w.connection, { { type = 4, name = "" } }, { version = version })
  end)
  if not result.ok then return { answered = false, error = result.error, version = version } end
  local by_name = {}
  for _, row in ipairs(result.results or {}) do
    for _, config in ipairs(row.configs or {}) do by_name[config.name] = config end
  end
  local rows = {}
  for _, name in ipairs({ "sasl.enabled.mechanisms", "sasl.mechanism.inter.broker.protocol", "listener.security.protocol.map", "listeners", "ssl.keystore.location",
    "connections.max.reauth.ms", "authorizer.class.name", "allow.everyone.if.no.acl.found" }) do
    if by_name[name] then
      rows[#rows + 1] = { name = name, value = by_name[name].value, source = by_name[name].source, sensitive = by_name[name].is_sensitive }
    end
  end
  w:stage("describe_configs", string.format("%s matched", plural(#rows, "setting")))
  return { answered = true, version = version, results = result.results or {}, by_name = by_name, rows = rows }
end

-- 5. Analysis

local analysis = {}

-- What a passive observer receives: the token by shape, the password by length.
function analysis.observer_view(cfg, auth)
  local rows = {
    { field = "mechanism", value = cfg.mechanism, note = "sent in the clear at the start of the exchange" },
    { field = "SaslAuthenticate payload", value = masked_token_summary(cfg.user, cfg.password),
      note = string.format("%d byte(s): a zero byte, the username, a zero byte, the password", #kafka.sasl.plain_token(cfg.user, cfg.password)) },
    { field = "password", value = string.format("%d byte(s), never printed", #cfg.password), note = "anyone reading the stream reads the password itself, not a hash of it" },
}
  if auth and (auth.accepted or auth.status == "refused") then
    rows[#rows + 1] = { field = "result", value = auth.accepted and "the broker accepted the credential on this channel"
        or "the broker refused the credential", note = auth.accepted and "a captured copy is replayable until the credential is rotated"
        or "the transport is still cleartext: a real client's valid credential is disclosed the same way" }
  end
  return rows
end

function analysis.sasl(auth, mechanisms)
  local list = mechanisms and mechanisms.mechanisms or {}
  local offered, out = {}, { offered = list, count = #list }
  for _, name in ipairs(list) do offered[string.upper(tostring(name))] = true end
  for _, key in ipairs({ "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "GSSAPI", "OAUTHBEARER", "EXTERNAL" }) do
    out[string.lower(string.gsub(key, "%W", "_")) .. "_offered"] = offered[key] == true
  end
  out.scram_offered = out.scram_sha_256_offered or out.scram_sha_512_offered
  out.handshake_answered = mechanisms and mechanisms.answered and true or false
  out.handshake_error = mechanisms and mechanisms.error
  if auth then
    out.attempted = true
    out.status = auth.status
    out.accepted = auth.status == "accepted"
    out.refused = auth.status == "refused"
    out.error_name, out.error_message = auth.error_name, auth.error_message
    out.mechanism_not_offered = auth.status == "mechanism-not-offered"
    out.unsupported_by_script = auth.unsupported_by_script
  end
  return out
end

-- The configuration section decides whether the transport choice was deliberate.
function analysis.configuration(configs)
  local out = { rows = configs.rows or {}, answered = configs.answered and true or false, skipped = configs.skipped }
  if not out.answered then return out end
  local by_name = configs.by_name or {}
  local function value(name)
    local entry = by_name[name]
    if not entry or entry.value == nil then return nil end
    return tostring(entry.value)
  end
  out.mechanisms_setting, out.protocol_map = value("sasl.enabled.mechanisms"), value("listener.security.protocol.map")
  out.listeners, out.authorizer = value("listeners"), value("authorizer.class.name")
  out.allow_everyone = value("allow.everyone.if.no.acl.found")
  out.reauth_ms = tonumber(value("connections.max.reauth.ms") or "")
  local function contains(text, needle)
    return text ~= nil and string.find(string.upper(text), needle, 1, true) ~= nil
  end
  out.configured_plain, out.configured_scram = contains(out.mechanisms_setting, "PLAIN"), contains(out.mechanisms_setting, "SCRAM")
  out.has_sasl_ssl = contains(out.protocol_map, "SASL_SSL")
  out.has_sasl_plaintext = contains(out.protocol_map, "SASL_PLAINTEXT")
  return out
end

-- The verdict combines the transport with the mechanism: the same PLAIN offer is
-- a disclosure on one listener and a hardening note on the other.
function analysis.verdict(listener, sasl, protocol_answered)
  local out = { exposure = "none", reason = "no cleartext credential path was demonstrated" }
  if listener.kind == "unavailable" or listener.kind == "skipped" then
    out.transport_known = false
    out.reason = "the transport could not be classified, so the credential path is unproven"
  elseif listener.encrypted == nil and not protocol_answered then
    out.transport_known = false
    out.exposure = "transport-unknown"
    out.reason = "the listener answered neither the ClientHello nor a Kafka request: a filtered port, "
      .. "a closed listener and a load balancer that drops unknown bytes all look the same from here"
  elseif listener.encrypted == nil then
    -- The hello went unanswered, but the Kafka protocol answered on the same port
    -- and a TLS listener cannot do both. That is real evidence of a plaintext
    -- listener, and it is the weakest evidence this script acts on.
    out.transport_known, out.cleartext = true, true
    out.transport_source, out.protocol_name = "protocol-exchange", "SASL_PLAINTEXT"
    out.cleartext_by_protocol = true
    if not sasl.plain_offered then
      out.exposure = sasl.attempted and "cleartext-other-mechanism" or "cleartext-no-sasl"
    else
      out.exposure = sasl.accepted and "cleartext-accepted" or "cleartext-offered"
    end
    out.reason = "the ClientHello went unanswered while the Kafka protocol answered on the same port, "
      .. "which a TLS listener cannot do (" .. KB.protocol_note("SASL_PLAINTEXT") .. ")"
  elseif listener.encrypted then
    out.transport_known = true
    out.exposure = sasl.plain_offered and "encrypted-plain" or "none"
    out.reason = "the listener answered the ClientHello with TLS, so the PLAIN token is inside the "
      .. "encrypted record layer"
  elseif not sasl.plain_offered then
    out.transport_known, out.cleartext = true, true
    out.exposure = sasl.attempted and "cleartext-other-mechanism" or "cleartext-no-sasl"
    out.protocol_name = "SASL_PLAINTEXT"
    out.reason = sasl.attempted and "the listener is not encrypted and PLAIN is not among its mechanisms"
      or "the listener is not encrypted and no mechanism list was readable from it"
  else
    out.transport_known, out.cleartext = true, true
    out.exposure = sasl.accepted and "cleartext-accepted" or "cleartext-offered"
    out.reason = sasl.accepted and "the listener is not encrypted and the PLAIN exchange was accepted"
      or "the listener is not encrypted and PLAIN is offered, so every client that authenticates from "
        .. "off-host sends its password in the clear"
  end
  return out
end

-- 6. Knowledge base

-- The four listener protocols and what each one protects.
KB.TRANSPORT = {
  { protocol = "PLAINTEXT", encrypted = false, authenticated = false, note = "neither the credential nor the records are protected" },
  { protocol = "SSL", encrypted = true, authenticated = false, note = "records are protected; no principal for an ACL to name" },
  { protocol = "SASL_PLAINTEXT", encrypted = false, authenticated = true, note = "the principal is authenticated, the credential is readable on the path" },
  { protocol = "SASL_SSL", encrypted = true, authenticated = true, note = "the intended production combination" }, }

-- Which protocol a listener is running, as far as the evidence goes. The name is
-- what the verdict reason and the report quote, so the table is used rather than
-- printed beside the answer.
function KB.protocol_note(name)
  for _, entry in ipairs(KB.TRANSPORT) do
    if entry.protocol == name then return entry.protocol .. ": " .. entry.note end
  end
  return "unknown listener protocol"
end

KB.REMEDIATION = {
  { step = "Move the listener to SASL_SSL, keeping a plaintext variant only on a loopback or "
      .. "container-internal endpoint (listener.security.protocol.map).",
    why = "SASL_PLAINTEXT authenticates the client and publishes the credential; the fix is the " .. "transport, not the mechanism." },
  { step = "Remove PLAIN from sasl.enabled.mechanisms on every reachable listener and use a mechanism "
      .. "that sends a proof instead of the password.", why = "A captured proof cannot be replayed; a captured password can, until it is rotated." },
  { step = "Set connections.max.reauth.ms so sessions have to re-authenticate.", why = "Without it a session outlives the revocation of the credential it was opened with." },
  { step = "Rotate every credential that has been sent over a cleartext listener, starting with the " .. "ones this script was told to use.",
    why = "The exposure is retrospective: whatever recorded the path already has the password." },
  { step = "Alert on SaslAuthenticate failures and on successful logins from unexpected addresses.",
    why = "A credential read off the wire is used from somewhere else, and the login is the first " .. "visible sign." }, }

KB.VERIFICATION = {
  "kafka-configs.sh --describe --entity-type brokers --entity-name <id>  (protocol map, enabled " .. "mechanisms, connections.max.reauth.ms)",
  "grep -E 'SASL|authentication' <broker server.log>  (is this audit's attempt logged and "
    .. "attributed, and does anything else authenticate from an unexpected address?)", }

KB.METHOD_LIMITS = {
  "The transport classification uses one ClientHello. A TLS listener that requires a client certificate "
    .. "or a specific cipher refuses it with an alert, which is reported as TLS plus the refusal reason.",
  "A plaintext listener that answers the hello with bytes shaped like a TLS record would be misread; the "
    .. "report prints the record type and length it parsed, so the classification can be checked.",
  "One authentication attempt is sent: not enough to trip a lockout policy, but visible in the broker "
    .. "log. An accepted sentinel means the broker accepts an identity it does not know. Non-PLAIN "
    .. "exchanges are left to kafka-sasl-mechanism-audit.nse, which implements the SCRAM exchange.", }

KB.RISK_RUBRIC = {
  { severity = "MEDIUM", condition = "a cleartext listener offers PLAIN, or the supplied credential " .. "was accepted on one" },
  { severity = "LOW", condition = "PLAIN is offered on an encrypted listener, or re-authentication is " .. "not configured" },
  { severity = "INFO", condition = "the listener is encrypted and only stronger mechanisms are " .. "offered, or nothing answered" }, }

-- 6. Findings

local findings = {}

function findings.evaluate(listener, sasl, meta, configs, verdict, cfg)
  local list = {}
  local function add(id, title, severity, detail, evidence, ...)
    list[#list + 1] = finding(id, title, severity, detail, evidence, { ... })
  end
  local cleartext = verdict.exposure == "cleartext-offered" or verdict.exposure == "cleartext-accepted"
  if cleartext then
    local evidence = { "listener: " .. tostring(listener.summary), "mechanisms offered: " .. fmt_list(sasl.offered, 8),
      string.format("PLAIN attempt for %s: %s (%s)", cfg.user, tostring(sasl.status), tostring(sasl.error_name or "-")),
      "what crossed the wire: " .. masked_token_summary(cfg.user, cfg.password) }
    if configs.protocol_map then
      evidence[#evidence + 1] = "listener.security.protocol.map=" .. tostring(configs.protocol_map)
    end
    if configs.mechanisms_setting then
      evidence[#evidence + 1] = "sasl.enabled.mechanisms=" .. tostring(configs.mechanisms_setting)
    end
    add("KAFKA-PLAIN-CREDENTIALS-OVER-CLEARTEXT", "SASL/PLAIN credentials cross an unencrypted listener", "MEDIUM",
      string.format("The listener did not answer the %s byte TLS ClientHello with a TLS record and it "
        .. "offers PLAIN, so SaslAuthenticate carries the username and the password in the clear. %s "
        .. "Every client that authenticates from off-host publishes its credential to every hop on the "
        .. "path, and the records it then produces are readable on the same path.", num_text(listener.hello_bytes or 0), verdict.reason),
      evidence, KB.REMEDIATION[1], KB.REMEDIATION[2], KB.REMEDIATION[4])
  elseif verdict.exposure == "cleartext-other-mechanism" then
    add("KAFKA-CLEARTEXT-LISTENER-NO-PLAIN", "The listener is unencrypted but does not offer PLAIN",
      "LOW", string.format("The listener did not answer the TLS ClientHello with a TLS record and its "
        .. "mechanism list is %s. Those mechanisms do not send the password, but every record and every "
        .. "session is still unencrypted. %s", fmt_list(sasl.offered, 6), tostring(verdict.reason)),
      { "mechanisms: " .. fmt_list(sasl.offered, 8), tostring(listener.summary) }, KB.REMEDIATION[1])
  elseif verdict.exposure == "transport-unknown" then
    add("KAFKA-TRANSPORT-UNCLASSIFIED", "The listener transport could not be classified", "INFO",
      "No TLS record and no application data answered the ClientHello. An unencrypted listener that "
        .. "ignores unknown bytes, a filtered port and a broker behind a load balancer all look the "
        .. "same from here, so this run makes no claim about the transport.", { tostring(listener.summary) }, KB.REMEDIATION[1])
  elseif verdict.exposure == "cleartext-no-sasl" then
    add("KAFKA-CLEARTEXT-UNKNOWN-MECHANISMS", "The listener is unencrypted and no mechanism list was readable", "LOW",
      "The listener is unencrypted but reading the offered mechanisms failed, so the credential path "
        .. "could not be established even though the transport could.", { tostring(listener.summary) }, KB.REMEDIATION[1], KB.REMEDIATION[2])
  elseif sasl.plain_offered then
    add("KAFKA-PLAIN-OFFERED", "The listener offers SASL/PLAIN", "LOW", "PLAIN is in the mechanism list. The transport answered the ClientHello with TLS, so the credential "
        .. "stays inside the encrypted record layer; the offer is still worth removing where a mechanism "
        .. "that proves knowledge of the password is available.", { "mechanisms: " .. fmt_list(sasl.offered, 8) }, KB.REMEDIATION[2])
  end

  if sasl.accepted and not cfg.user_supplied then
    add("KAFKA-SENTINEL-CREDENTIAL-ACCEPTED", "The broker accepted a generated probe credential",
      "MEDIUM", string.format("The PLAIN attempt for the generated identity %s was accepted. That "
        .. "credential was created for this run, so either the broker accepts any password for that name "
        .. "or it authenticated an identity it does not know.", cfg.user),
      { string.format("%s accepted a %d byte generated password", cfg.user, #cfg.password) }, KB.REMEDIATION[5], KB.REMEDIATION[2])
  elseif sasl.accepted then
    add("KAFKA-SUPPLIED-CREDENTIAL-ACCEPTED", "The supplied credential was accepted on this listener",
      "INFO", string.format("The credential given in kafka.user/kafka.password authenticated. %s",
        cleartext and "It was sent over an unencrypted listener, so the finding above applies to it."
          or "The listener is encrypted, so the exchange was protected."), { "user " .. cfg.user .. " authenticated" }, KB.REMEDIATION[4])
  end

  if meta.answered and (meta.topic_count or 0) > 0 then
    add("KAFKA-ANONYMOUS-METADATA-DESPITE-SASL", "Metadata is answered without a SASL exchange",
      "MEDIUM", string.format("The broker returned %s on a listener that offers %s. Metadata is the API "
        .. "every client calls first, and answering it before authentication tells an unauthenticated "
        .. "caller the client id, the listener names and, depending on the ACL mode, the topic inventory.",
        plural(meta.topic_count, "topic"), fmt_list(sasl.offered, 4)), { string.format("Metadata v%s: %s", num_text(meta.version), plural(meta.topic_count, "topic")) },
      KB.REMEDIATION[1], KB.REMEDIATION[2])
  end

  if configs.answered and configs.reauth_ms == nil then
    add("KAFKA-REAUTH-NOT-CONFIGURED", "connections.max.reauth.ms is not set", "LOW",
      "Sessions are never asked to re-authenticate, so a session opened with a credential that is later "
        .. "revoked keeps working, and one opened with a captured credential survives the rotation that "
        .. "was meant to stop it.", { "connections.max.reauth.ms was absent from the broker configuration" }, KB.REMEDIATION[3], KB.REMEDIATION[5])
  end

  if #list == 0 then
    add("KAFKA-PLAIN-AUDIT-INCONCLUSIVE", listener.encrypted and "No cleartext credential path was demonstrated"
        or "The credential path could not be established", listener.encrypted and "NONE" or "INFO", tostring(verdict.reason),
      { tostring(listener.summary), "mechanisms read: " .. fmt_list(sasl.offered, 6) }, KB.REMEDIATION[1])
  end
  return list
end

-- 7. Report

local report = {}

function report.listener_section(listener)
  local lines = { tostring(listener.summary), "Encrypted: " .. (listener.encrypted == nil and "unknown" or fmt_bool(listener.encrypted)) }
  local function push(text) lines[#lines + 1] = text end
  if listener.hello_bytes then push(string.format("ClientHello sent: %d byte(s)", listener.hello_bytes)) end
  if listener.record_type_name then
    push(string.format("Reply: %s record, %s byte(s)%s", tostring(listener.record_type_name), num_text(listener.bytes), listener.truncated and " (truncated)" or ""))
  end
  if listener.alert_name then
    push(string.format("Alert: %s (%s): the listener speaks TLS and refused the hello", tostring(listener.alert_name), tostring(listener.alert_level_name)))
  end
  if listener.handshake_name and listener.handshake_name ~= "server_hello" then
    push("Handshake record: " .. tostring(listener.handshake_name))
  end
  if listener.negotiated_version_text then
    push("Negotiated version: " .. tostring(listener.negotiated_version_text))
  end
  if listener.cipher_suite_name then
    push(string.format("Cipher suite: %s (%s%s)", tostring(listener.cipher_suite_name),
      tostring(listener.cipher_strength), listener.cipher_note and (", " .. listener.cipher_note) or ""))
  end
  if listener.preview then
    push("First bytes of the reply: " .. (string.gsub(listener.preview, ".", function(char) return string.format("%02x ", string.byte(char)) end)))
  end
  if listener.transport_source == "non-tls-reply" then
    push("The hello was answered by something that is not a TLS record, so the listener is classified "
      .. "as plaintext; the protocol probe below says which protocol answered.")
  elseif listener.transport_source == "hello-unanswered" then
    push("The hello went unanswered, which on its own proves nothing: a plaintext Kafka listener reads "
      .. "its first four bytes as a frame length and waits. The protocol probe below decides.")
  end
  return lines
end

function report.sasl_section(sasl, cfg)
  local lines = { "Mechanisms offered: " .. fmt_list(sasl.offered, 10), string.format("PLAIN: %s, SCRAM: %s, GSSAPI: %s, OAUTHBEARER: %s", fmt_bool(sasl.plain_offered),
      fmt_bool(sasl.scram_offered), fmt_bool(sasl.gssapi_offered), fmt_bool(sasl.oauthbearer_offered)) }
  if sasl.attempted then
    lines[#lines + 1] = string.format("%s attempt for %s: %s (%s, %s)", cfg.mechanism, cfg.user,
      tostring(sasl.status), tostring(sasl.error_name or "no code"), sasl.error_message and tostring(sasl.error_message) or "no message")
  else
    lines[#lines + 1] = string.format("Mechanism %s: %s", cfg.mechanism, sasl.unsupported_by_script and "this script performs the PLAIN exchange only"
      or (sasl.handshake_answered and "no attempt was made"
      or ("not attempted: reading the offered mechanisms failed ("
        .. tostring(sasl.handshake_error or "no response") .. ")")))
  end
  lines[#lines + 1] = string.format("Identity: %s user, %s password", cfg.user_supplied and "operator supplied" or "generated probe",
    cfg.password_supplied and "operator supplied" or "generated sentinel")
  return lines
end

function report.observer_section(view)
  local lines = { string.format("%-26s %s", "Field", "What an observer receives") }
  for _, row in ipairs(view) do
    lines[#lines + 1] = string.format("%-26s %s", tostring(row.field), tostring(row.value))
    lines[#lines + 1] = "    " .. tostring(row.note)
  end
  return lines
end

function report.config_section(configs)
  if configs.skipped then return { "Configuration was not read: " .. tostring(configs.skipped) } end
  if not configs.answered then
    return { string.format("DescribeConfigs was not answered (%s).", tostring(configs.error or "no response")) }
  end
  local lines = {}
  for _, row in ipairs(configs.rows) do
    lines[#lines + 1] = string.format("%-34s %-40s %s", tostring(row.name), row.sensitive and "(sensitive)" or tostring(row.value), tostring(row.source or "-"))
  end
  if #configs.rows == 0 then lines[#lines + 1] = "None of the settings this script looks for were in it." end
  return lines
end

function report.finding_section(list)
  if #list == 0 then return { "No finding." } end
  local lines = {}
  for index, item in ipairs(list) do
    lines[#lines + 1] = string.format("%d. [%s] %s (%s)", index, item.severity, item.title, item.id)
    lines[#lines + 1] = "   " .. item.detail
    for _, line in ipairs(item.evidence) do lines[#lines + 1] = "   evidence: " .. line end
    for _, step in ipairs(item.remediation) do
      lines[#lines + 1] = "   fix: " .. (type(step) == "table" and step.step or tostring(step))
      if type(step) == "table" and step.why then lines[#lines + 1] = "        why: " .. step.why end
    end
  end
  return lines
end

function report.build(cfg, host, port, listener, sasl, meta, configs, verdict, view, list, w)
  local out = stdnse.output_table()
  out["Target"] = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id %s, mechanism %s, timeout %dms", cfg.client_id, cfg.mechanism, cfg.timeout), string.format("Probe identity %s (%s), password %s", cfg.user,
      cfg.user_supplied and "supplied by the operator" or "generated for this run", cfg.password_supplied and "supplied by the operator" or "generated sentinel"),
    string.format("Transport verdict: %s (%s evidence) - %s", tostring(verdict.exposure),
      tostring(verdict.transport_source or listener.transport_source or "no"), tostring(verdict.reason)),
    "Listener protocol: " .. KB.protocol_note(verdict.protocol_name or listener.protocol_name), }
  out["Listener transport"] = report.listener_section(listener)
  out["SASL"] = report.sasl_section(sasl, cfg)
  out["What an observer receives"] = report.observer_section(view)
  out["Protocol probe"] = {
    string.format("ApiVersions: %s", meta.negotiated and meta.negotiated.answered
      and plural(meta.negotiated.count or 0, "API") or tostring(meta.negotiated_error or "not answered")),
    string.format("Metadata: %s", meta.answered and plural(meta.topic_count or 0, "topic")
      or tostring(meta.error or "not answered")), }
  out["Configuration"] = report.config_section(configs)
  out["Findings"] = report.finding_section(list)
  out["Verification"] = KB.VERIFICATION
  out["Method limits and rubric"] = KB.METHOD_LIMITS
  for _, entry in ipairs(KB.RISK_RUBRIC) do
    out["Method limits and rubric"][#out["Method limits and rubric"] + 1] =
      "Rubric - " .. entry.severity .. ": " .. entry.condition
  end
  out["Finding summary"] = severity_summary(list)
  out["Risk Level"] = worst(list, "NONE")
  if cfg.verbose then
    local transcript = {}
    for _, stage in ipairs(w.stages) do
      transcript[#transcript + 1] = string.format("%s: %s", stage.name, tostring(stage.detail or ""))
    end
    out["Probe transcript"] = transcript
  end

  return out
end

-- 8. Orchestration

local function unreachable_report(cfg, host, port, listener, reason)
  return {
    ["Risk Level"] = "UNKNOWN", Target = { string.format("Endpoint: %s:%d/tcp", host.ip or "target", port.number),
      string.format("Client id %s, mechanism %s", cfg.client_id, cfg.mechanism), "No Kafka response was received: " .. tostring(reason) },
    ["Listener transport"] = report.listener_section(listener), ["Method limits"] = { "The listener did not answer, so nothing is claimed about its transport, "
      .. "its mechanisms or the credentials it accepts." }, }
end

action = function(host, port)
  local cfg = read_config()
  local listener = probe.listener(host, port, cfg)
  local w = Wire.new(host, port, cfg)
  if not w.connection.sock then
    return {
      ["Risk Level"] = "UNKNOWN", Target = { string.format("Endpoint: %s:%d/tcp", host.ip or "target", port.number),
        "Transport failure: " .. tostring(w.connection.last_error) }, ["Listener transport"] = report.listener_section(listener),
      ["Method limits"] = { "The TCP connection failed, so no request was sent and no claim is made " .. "about the listener." }, }
  end

  local meta = {}
  meta.negotiated = probe.negotiate(w)
  meta.negotiated_error = meta.negotiated.answered and nil or meta.negotiated.error
  local sasl_probe = probe.mechanisms(w, cfg.mechanism)
  local auth = sasl_probe.answered and probe.authenticate(w, cfg.mechanism, cfg.user, cfg.password) or nil
  local metadata = probe.metadata(w)
  local configs = cfg.config_probe and probe.describe_configs(w)
    or { skipped = "the configuration probe is disabled (kafka.config-probe=false)" }
  w:close()

  if not meta.negotiated.answered and not sasl_probe.answered and not metadata.answered then
    return unreachable_report(cfg, host, port, listener, meta.negotiated_error or metadata.error
      or "the port accepted the connection and then stopped answering")
  end

  local sasl = analysis.sasl(auth, sasl_probe)
  local configuration = analysis.configuration(configs)
  local verdict = analysis.verdict(listener, sasl, meta.negotiated.answered or metadata.answered)
  local view = analysis.observer_view(cfg, sasl)
  local list = findings.evaluate(listener, sasl, metadata, configuration, verdict, cfg)

  local result = report.build(cfg, host, port, listener, sasl, { answered = metadata.answered, topic_count = metadata.topic_count, version = metadata.version,
      error = metadata.error, negotiated = meta.negotiated, negotiated_error = meta.negotiated_error }, configuration, verdict, view, list, w)
  publish_findings(host, port, list)
  return result
end
