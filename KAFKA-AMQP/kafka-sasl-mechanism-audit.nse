local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The wire engine owns framing, version negotiation and the SCRAM maths.
local ok, kafka = pcall(require, "kafka")
local has_vulns, vulns_lib = pcall(require, "vulns")

local SCRIPT_NAME = "kafka-sasl-mechanism-audit"
local SCRIPT_RISK = "MEDIUM"
local SCRIPT_VERSION = "2.0.0"

description = [[
Audits the SASL mechanisms a Kafka listener offers and reads what the SCRAM
exchange itself gives away.

The mechanism list is only the beginning: two listeners that both offer
SCRAM-SHA-256 can still differ in the part of the exchange that matters, because
the server's first message carries the salt it holds for the account and the
iteration count it wants, and those two values decide how expensive an offline
attack on a captured exchange is.

The script reads that message - the same bytes a broker sends every client - for
several names, without a password. It compares the salt across names, checks that
it is stable for the same name, grades the iteration count, and finishes the
exchange with a deliberately wrong proof for a name that cannot exist and for
each candidate account it was given. When those two are answered with different
tokens ("no such user" versus "wrong password"), the exchange is an
account-enumeration oracle and the report says so, with both tokens as evidence.

Read-only throughout: SaslHandshake and SaslAuthenticate, nothing sent after a
successful authentication, and a wrong password only for names the operator
supplied or names generated for the run.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-sasl-mechanism-audit <target>
-- nmap -p 9092 --script kafka-sasl-mechanism-audit --script-args kafka.names=svc-etl,svc-audit <target>
--
-- @args kafka.timeout       Per-request timeout in milliseconds (default 5000).
-- @args kafka.client-id     Client id used in every request header.
-- @args kafka.mechanism     SCRAM mechanism to audit: "auto" (default) prefers SHA-512, then SHA-256, then SHA-1.
-- @args kafka.user          An account name to test. A wrong password is sent
--                           for it, which is what the enumeration test needs.
-- @args kafka.password      Password for kafka.user. When it is supplied the run
--                           also reports whether the full exchange succeeds.
-- @args kafka.names         Comma separated candidate accounts to test for
--                           existence through the exchange's error tokens.
-- @args kafka.iterations-min Iteration floor the run grades against (default 4096).
-- @args kafka.verbose       "true" adds the per-stage transcript.

local function vuln_publisher(host, port)
  if not has_vulns or type(vulns_lib) ~= "table" then return nil end
  local ok_pub, publisher = pcall(function()
    if type(vulns_lib.Report) == "table" and type(vulns_lib.Report.new) == "function" then
      local report = vulns_lib.Report:new(SCRIPT_NAME, host, port)
      return function(id, title, detail) report:add(id, title, { format = function() return detail end }) end
    end
    if type(vulns_lib.Report) == "function" then
      local report = vulns_lib.Report(host, port)
      return function(id, title, detail) report.add(host, port, id, title, { format = function() return detail end }) end
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

----------------------------------------------------------------------------
-- 1. Configuration
----------------------------------------------------------------------------

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

local function arg_list(name, limit)
  local raw = arg_string(name, nil, 512)
  if not raw then return {} end
  local list = {}
  for item in string.gmatch(raw, "([^,]+)") do
    local cleaned = string.gsub(item, "%s", "")
    if #cleaned > 0 and #list < (limit or 16) then list[#list + 1] = cleaned end
  end
  return list
end

-- The probe identity is generated, so a scan cannot lock an account out and
-- cannot be mistaken for a login by whoever reads the broker log.
local function read_config()
  local supplied_user = arg_string("kafka.user", nil, 128)
  local supplied_password = arg_string("kafka.password", nil, 256)
  local names = arg_list("kafka.names", 8)
  if supplied_user then table.insert(names, 1, supplied_user) end
  return {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000), client_id = arg_string("kafka.client-id", "nmap-kafka-sasl-audit", 120),
    requested = string.upper(arg_string("kafka.mechanism", "AUTO", 32)), user = supplied_user,
    password = supplied_password, password_supplied = supplied_password ~= nil, names = names,
    iterations_min = arg_number("kafka.iterations-min", 4096, 1, 10000000), verbose = arg_bool("kafka.verbose", false), }
end

-- A name that cannot exist: the run's baseline for every comparison.
local function impossible_name()
  return string.format("nmap-absent-%06d", math.random(0, 999999))
end

----------------------------------------------------------------------------
-- 2. Formatting helpers
----------------------------------------------------------------------------

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

local function hex_bytes(data, limit)
  if not data or #data == 0 then return "(empty)" end
  local parts = {}
  for index = 1, math.min(#data, limit or 8) do
    parts[#parts + 1] = string.format("%02x", string.byte(data, index))
  end
  if #data > (limit or 8) then parts[#parts + 1] = ".." end
  return table.concat(parts)
end

local function finding(id, title, severity, detail, evidence, remediation)
  return { id = id, title = title, severity = severity, detail = detail, evidence = evidence or {}, remediation = remediation or {} }
end

-- A one-line tally of what the run produced.
local function severity_summary(list)
  local parts = {}
  for _, severity in ipairs({ "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }) do
    local count = 0
    for _, item in ipairs(list) do if item.severity == severity then count = count + 1 end end
    if count > 0 then parts[#parts + 1] = string.format("%s x%d", severity, count) end
  end
  return #parts > 0 and table.concat(parts, ", ") or "no findings"
end

local function worst(list, default)
  local level, text = -1, default
  for _, item in ipairs(list) do
    local value = kafka.SEVERITY_ORDER[item.severity]
    if value and value > level then level, text = value, item.severity end
  end
  return text
end

-- A salt is not a secret - it travels on the wire - but the report describes it by
-- length and fingerprint so a reader can compare two runs without the salt being
-- mistaken for a credential.
local function salt_summary(salt, salt_b64)
  if not salt then return "not present in the server-first message" end
  return string.format("%d byte(s), fingerprint %s, base64 %s", #salt, hex_bytes(salt, 6), salt_b64 and string.sub(salt_b64, 1, 12) or "-")
end

----------------------------------------------------------------------------
-- 3. Connection wrapper
----------------------------------------------------------------------------

local Wire = {}
Wire.__index = Wire

function Wire.new(host, port, cfg, trace)
  local self = setmetatable({}, Wire)
  self.cfg = cfg
  self.trace = trace or { stages = {}, failures = {} }
  self.stages, self.failures = self.trace.stages, self.trace.failures
  self.connection = kafka.new_connection(host.ip or host.name or "target", port.number, {
    timeout_ms = cfg.timeout, client_id = cfg.client_id, })
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
  if not ok_call then
    self:fail(stage, "probe error: " .. tostring(result))
    return { ok = false, error = "probe error: " .. tostring(result) }
  end
  if not result then
    self:fail(stage, err or "no response")
    return { ok = false, error = err or "no response" }
  end
  self:stage(stage, "answered")
  return { ok = true, value = result }
end

----------------------------------------------------------------------------
-- 4. Probes
----------------------------------------------------------------------------

local probe = {}

-- The catalogue comes from the handshake: an unknown mechanism name is answered
-- with UNSUPPORTED_SASL_MECHANISM and the list the broker does offer, in one
-- record and without authenticating anything.
function probe.mechanisms(w)
  local result = kafka.sasl_handshake(w.connection, "NMAP-PROBE", {})
  if not result.ok then
    w:fail("sasl_handshake", tostring(result.error))
    return { answered = false, error = "the SaslHandshake was not answered ("
      .. tostring(result.error) .. ")" }
  end
  w:stage("sasl_handshake", string.format("error %s, %s offered", tostring(result.error_name), plural(#(result.mechanisms or {}), "mechanism")))
  return { answered = true, version = result.version, error_code = result.error_code,
    error_name = result.error_name, mechanisms = result.mechanisms or {} }
end

-- Which SCRAM variant the run audits. The preference is deliberate: the strongest
-- offered mechanism is the one whose parameters decide the real attack cost.
local function choose_mechanism(offered, requested)
  local function has(name)
    for _, item in ipairs(offered or {}) do
      if string.upper(item) == name then return true end
    end
    return false
  end
  if requested ~= "AUTO" then
    return requested, has(requested)
  end
  for _, name in ipairs({ "SCRAM-SHA-512", "SCRAM-SHA-256", "SCRAM-SHA-1" }) do
    if has(name) then return name, true end
  end
  return nil, false
end

-- The server-first message, read for one name. Nothing is derived from a
-- password here: the salt and the iteration count are the server's answer to any
-- client that asks, so this works for names that have no account at all.
function probe.scram_first(w, mechanism, user, index)
  local nonce = string.format("nmapNse%06dNonce%d", math.random(0, 999999), index or 1)
  local result = w:call("scram_first_" .. tostring(index or 1), function()
    return kafka.sasl_scram_first(w.connection, mechanism, user, { nonce = nonce })
  end)
  if not result.ok then return { user = user, ok = false, error = result.error } end
  local out = result.value
  out.user = user
  local stage = "scram_first_" .. tostring(index or 1)
  local detail = out.status == "server-first"
    and string.format("%s: i=%s salt=%s", user, tostring(out.iterations), out.salt and (#out.salt .. "B") or "none")
    or string.format("%s: %s (%s)", user, tostring(out.status), tostring(out.error_name or "-"))
  w:stage(stage, detail)
  return out
end

-- The whole exchange, with whatever password the caller passes. The failing
-- second step is where an enumeration oracle becomes visible: the token the
-- server sends back for an unknown name and for a wrong password is the evidence.
function probe.scram_complete(w, mechanism, user, password, index, opts)
  local result = w:call("scram_complete_" .. tostring(index or 1), function()
    return kafka.sasl_auth_scram(w.connection, mechanism, user, password, opts or {})
  end)
  if not result.ok then return { user = user, ok = false, error = result.error } end
  local out = result.value
  out.user = user
  local second = out.second or {}
  out.failure_token = second.auth_bytes
  out.failure_message = second.error_message
  w:stage("scram_complete_" .. tostring(index or 1), string.format("%s: %s%s", user,
    tostring(out.status), out.failure_token and (" [" .. tostring(out.failure_token) .. "]") or ""))
  return out
end

----------------------------------------------------------------------------
-- 5. Analysis
----------------------------------------------------------------------------

local analysis = {}

-- What each mechanism means for the credential path. A catalogue turn "PLAIN,
-- SCRAM-SHA-256" into a statement about what crosses the wire and what an
-- attacker who captures it can do with it.
local KB = {}

KB.MECHANISM_CLASSES = {
  { name = "PLAIN", class = "password", proof = false,
    note = "RFC 4616: username and password inside the token, protected by nothing but the transport" },
  { name = "SCRAM-SHA-256", class = "proof", proof = true,
    note = "RFC 7677: the password is never sent; the client proves it with PBKDF2 over a server salt" },
  { name = "SCRAM-SHA-512", class = "proof", proof = true, note = "RFC 7677 with SHA-512; the same exchange with a wider hash" },
  { name = "SCRAM-SHA-1", class = "proof", proof = true, deprecated = true,
    note = "RFC 5802 with SHA-1; the exchange is sound but the hash is retired" }, { name = "GSSAPI", class = "delegated", proof = true,
    note = "Kerberos: the credential never reaches the broker, the ticket does" }, { name = "OAUTHBEARER", class = "delegated", proof = true,
    note = "RFC 7628: a bearer token is presented, so the token is the credential" }, { name = "EXTERNAL", class = "delegated", proof = true,
    note = "the identity comes from the TLS client certificate, so the transport is the credential" }, }

function KB.classify(name)
  for _, entry in ipairs(KB.MECHANISM_CLASSES) do
    if entry.name == name then return entry end
  end
  return { name = name, class = "unknown", proof = false, known = false, note = "not one of the mechanisms this script knows; treated as opaque" }
end

-- Iteration guidance. The floor is the reason the count matters: a captured
-- exchange is only as expensive as the PBKDF2 work the server asked for.
KB.ITERATION_GUIDANCE = {
  { floor = 4096, verdict = "minimum", note = "the RFC 5802 floor: an attack on a weak password is still cheap at this count" },
  { floor = 10000, verdict = "acceptable", note = "a deployment that has moved past the floor" },
  { floor = 100000, verdict = "strong", note = "an offline attack on a captured exchange becomes expensive per password" },
}

KB.REMEDIATION = {
  { step = "Answer an unknown account and a wrong password with the same token, message and timing; RFC 5802 section 7 requires it.",
    why = "The token the second step returns enumerates accounts, one request each, without a password guess." },
  { step = "Store a random salt per account, generated when the credential is enrolled.",
    why = "A shared salt lets one precomputation serve every account in the deployment." },
  { step = "Raise the iteration count as far as the client fleet can afford, and re-enrol credentials when it changes.",
    why = "The count is the only knob that makes an offline attack on a captured exchange expensive." },
  { step = "Keep the mechanism list to what the deployment uses, and review it when a client library is added.",
    why = "Every mechanism left enabled is one a client can be downgraded into." },
  { step = "Remove PLAIN from sasl.enabled.mechanisms wherever a proof-based mechanism is available.",
    why = "PLAIN publishes the password to every hop that can see the stream." },
  { step = "Retire SCRAM-SHA-1 in favour of SCRAM-SHA-256 or SCRAM-SHA-512.",
    why = "The exchange is the right one, but SHA-1 is retired and the guarantee is that of the weakest accepted mechanism." },
}

KB.VERIFICATION = {
  "kafka-configs.sh --describe --entity-type brokers --entity-name <id>  (sasl.enabled.mechanisms)",
  "one login with a client configured for the scheme (kafka-console-consumer with sasl.mechanism=SCRAM-SHA-512), then compare the values it used against a capture of that login",
  "grep -E 'SASL|SCRAM' <broker server.log>  (confirm this audit's attempts are logged and read the error text an unknown account produces)",
}

KB.METHOD_LIMITS = {
  "One SaslHandshake reads the catalogue, three server-first messages read the salt and iteration parameters (two names that cannot exist and one repeat), and one exchange is completed per candidate name, capped at four.",
  "The completion probes send a well-formed proof derived at one iteration rather than at the broker's advertised count: the answer to a wrong proof does not depend on what the client paid, so the audit stays cheap against a broker that asks for 100000 rounds. The account whose credential the operator supplied is derived for real.",
  "A failed authentication is sent for every candidate name, which a lockout policy counts: candidate names come from kafka.names or kafka.user and never from a wordlist built by the script.",
  "The audit grades what the server sends; it does not attack PBKDF2, and a salt that looks strong here does not make a weak account password safe anywhere else.",
  "Uniform answers are reported as uniform for the names tested: two names answering alike is evidence, not proof, and an account whose password happens to be the tested one looks identical to an account that does not exist.",
  "Mechanisms outside the catalogue are printed as opaque rather than guessed at.",
}

KB.RISK_RUBRIC = {
  { severity = "MEDIUM", condition = "the exchange distinguishes an unknown account from a wrong password, every account shares one salt, or the only mechanism offered sends the password" },
  { severity = "LOW", condition = "iterations below the floor, SCRAM-SHA-1 still offered, or a salt that changes between two exchanges for the same account" },
  { severity = "INFO", condition = "the catalogue and parameters were read without a defect, or nothing answered" },
}

function KB.iteration_verdict(iterations)
  local best = "below the RFC 5802 floor"
  for _, entry in ipairs(KB.ITERATION_GUIDANCE) do
    if iterations and iterations >= entry.floor then best = entry.verdict end
  end
  return best
end

local function catalogue(offered)
  local rows, classes = {}, {}
  for _, name in ipairs(offered or {}) do
    local entry = KB.classify(string.upper(name))
    rows[#rows + 1] = entry
    classes[entry.class] = (classes[entry.class] or 0) + 1
  end
  local out = { rows = rows, counts = classes, count = #rows }
  for _, name in ipairs({ "PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512", "GSSAPI", "OAUTHBEARER", "EXTERNAL" }) do
    local offered_flag = false
    for _, row in ipairs(rows) do
      if row.name == name then offered_flag = true end
    end
    out[string.lower(string.gsub(name, "%W", "_")) .. "_offered"] = offered_flag
  end
  out.proof_based = (classes.proof or 0) + (classes.delegated or 0)
  out.password_sending = classes.password or 0
  out.only_password_sending = out.count > 0 and out.proof_based == 0 and out.password_sending > 0
  return out
end

-- Salt and iteration forensics, from the server-first messages of several names.
function analysis.scram(first_probes)
  local out = { iteration_values = {}, salts = {}, answered = 0, by_name = {} }
  for _, item in ipairs(first_probes) do
    if item.ok and item.status == "server-first" then
      out.answered = out.answered + 1
      if item.iterations then out.iteration_values[#out.iteration_values + 1] = item.iterations end
      if item.salt then
        out.salts[#out.salts + 1] = { user = item.user, salt = item.salt, b64 = item.salt_b64 }
        out.by_name[item.user] = out.by_name[item.user] or {}
        table.insert(out.by_name[item.user], item.salt)
        out.salt_length = #item.salt
      end
      if item.nonce_echoes_client == false then out.nonce_not_echoed = true end
      if item.iterations and (not out.iteration_min or item.iterations < out.iteration_min) then
        out.iteration_min = item.iterations
      end
    end
  end
  table.sort(out.iteration_values)
  out.iteration_max = out.iteration_values[#out.iteration_values]

  -- The same salt for two different names is the shared-salt anti-pattern: one
  -- precomputation then serves every account in the deployment.
  local first = out.salts[1]
  if out.answered < 2 or not first then out.salt_policy = "unreadable" else
    local shared = true
    for index = 2, #out.salts do
      if out.salts[index].user ~= first.user and out.salts[index].salt ~= first.salt then shared = false end
    end
    out.salt_policy, out.shared_salt_value = shared and "shared" or "per-user", shared and first.salt or nil
  end

  -- A salt that changes between two exchanges for the same name cannot be the
  -- salt of an account: a real client would derive a different verifier each time.
  for user, salts in pairs(out.by_name) do
    if #salts > 1 and salts[2] ~= salts[1] then
      out.unstable_user, out.salt_policy = user, "per-exchange"
    end
  end
  return out
end

function analysis.enumeration(baseline, candidates)
  local out = { baseline = baseline and baseline.failure_token, tested = 0, distinguishing = {} }
  for _, item in ipairs(candidates or {}) do
    if item and item.ok and item.failure_token then
      out.tested = out.tested + 1
      if out.baseline and item.failure_token ~= out.baseline then
        out.distinguishing[#out.distinguishing + 1] = item
      end
    end
  end
  out.oracle = #out.distinguishing > 0
  return out
end

function analysis.verdict(mechanisms, cat, scram, enum, mechanism)
  local out = { state = "unknown", reason = "nothing was read from the listener" }
  if not mechanisms.answered then
    out.state, out.reason = "unreachable", "the SaslHandshake was not answered, so the mechanism list is unknown"
  elseif cat.only_password_sending then
    out.state, out.reason = "plain-only", "the only mechanism offered sends the password itself"
  elseif not mechanism then
    out.state, out.reason = "no-scram-offered", "no SCRAM variant is offered, so the parameters were not audited"
  elseif scram.answered == 0 then
    out.state, out.reason = "nominal", "the mechanism is offered but the server-first message could not be read"
  else
    out.state = "scram-audited"
    out.reason = string.format("%s audited across %s names: salt policy %s, iterations %s",
      mechanism, num_text(scram.answered), tostring(scram.salt_policy), tostring(scram.iteration_min))
  end
  out.oracle = enum.oracle and true or false
  return out
end

----------------------------------------------------------------------------
-- 6. Findings
----------------------------------------------------------------------------

local findings = {}

function findings.evaluate(cfg, mechanism, mechanisms, cat, scram, enum, verdict)
  local list = {}
  local function add(id, title, severity, detail, evidence, ...)
    list[#list + 1] = finding(id, title, severity, detail, evidence, { ... })
  end

  if enum.oracle then
    local tokens = { string.format("name that cannot exist: %s", tostring(enum.baseline)) }
    for _, item in ipairs(enum.distinguishing) do
      tokens[#tokens + 1] = string.format("%s: %s", item.user, tostring(item.failure_token))
    end
    add("KAFKA-SCRAM-USER-ENUMERATION", "The SCRAM exchange tells an attacker which accounts exist", "MEDIUM",
      string.format("A name that cannot exist and %s got different answers, so the second message of "
        .. "the exchange is an account-existence oracle: an unauthenticated caller enumerates accounts "
        .. "at one request each, and RFC 5802 requires an unknown user and a wrong password to be "
        .. "answered identically.", plural(#enum.distinguishing, "candidate name")),
      tokens, KB.REMEDIATION[1], KB.REMEDIATION[4])
  end

  if scram.salt_policy == "shared" and scram.shared_salt_value then
    add("KAFKA-SCRAM-SHARED-SALT", "Every account is salted with the same value", "MEDIUM",
      string.format("The server-first message carries the identical %d byte salt for names that cannot "
        .. "both be accounts. One dictionary run against that salt then covers every account, and the "
        .. "salt no longer hides which accounts share a password.", #scram.shared_salt_value),
      { "salt: " .. salt_summary(scram.shared_salt_value, scram.salts[1] and scram.salts[1].b64),
        string.format("identical across %s", plural(#scram.salts, "name")) }, KB.REMEDIATION[2], KB.REMEDIATION[4])
  end

  if scram.iteration_min and scram.iteration_min < cfg.iterations_min then
    add("KAFKA-SCRAM-LOW-ITERATIONS", "The SCRAM iteration count is below the audit floor", "LOW",
      string.format("The broker asks clients for %s iterations, below the %s this run grades against "
        .. "(%s). A captured exchange can be attacked offline at that cost per password, so a weak "
        .. "account password is recoverable from one session capture.", num_text(scram.iteration_min), num_text(cfg.iterations_min),
        KB.iteration_verdict(scram.iteration_min)),
      { string.format("i=%s, seen across %s", num_text(scram.iteration_min), plural(#scram.iteration_values, "exchange")) },
      KB.REMEDIATION[3], KB.REMEDIATION[4])
  end

  if scram.salt_policy == "per-exchange" then
    add("KAFKA-SCRAM-SALT-PER-EXCHANGE", "The salt changes between two exchanges for the same account", "LOW",
      string.format("Two server-first messages for %s carried different salts. A SCRAM salt is part of "
        .. "the stored verifier and has to be stable per account, so either the broker derives a fresh "
        .. "salt per login - which no standard client can authenticate against - or the reply is not a "
        .. "SCRAM implementation.", tostring(scram.unstable_user)),
      { string.format("%s: two exchanges, two salts", tostring(scram.unstable_user)) }, KB.REMEDIATION[4])
  end

  if cat.only_password_sending then
    add("KAFKA-PLAIN-ONLY-MECHANISMS", "The only mechanism offered sends the password itself", "MEDIUM",
      string.format("The handshake offers %s and nothing that proves knowledge of the password without "
        .. "sending it, so the transport and every hop in front of the listener become part of the "
        .. "credential store.", fmt_list(mechanisms.mechanisms, 6)),
      { "mechanisms: " .. fmt_list(mechanisms.mechanisms, 8) }, KB.REMEDIATION[5], KB.REMEDIATION[4])
  end

  if cat.scram_sha_1_offered then
    add("KAFKA-SCRAM-SHA1-OFFERED", "SCRAM-SHA-1 is still offered", "LOW",
      "The exchange is the SCRAM one, but the hash is SHA-1: a client that negotiates it derives its "
        .. "verifier with a retired function, and the guarantee is only that of the weakest mechanism "
        .. "the listener accepts.", { "mechanisms: " .. fmt_list(mechanisms.mechanisms, 8) }, KB.REMEDIATION[6])
  end

  if verdict.state == "scram-audited" then
    add("KAFKA-SASL-MECHANISMS-AUDITED", "The mechanism catalogue and the SCRAM parameters were read", "INFO",
      string.format("%s offered, %s of them proof based. %s was audited: salt policy %s, iterations %s "
        .. "(%s), %s.", plural(cat.count, "mechanism"), num_text(cat.proof_based), tostring(mechanism),
        tostring(scram.salt_policy), num_text(scram.iteration_min), KB.iteration_verdict(scram.iteration_min), tostring(verdict.reason)),
      { "mechanisms: " .. fmt_list(mechanisms.mechanisms, 10), string.format("iterations: min %s, max %s", num_text(scram.iteration_min),
          num_text(scram.iteration_max)) }, KB.REMEDIATION[4])
  elseif #list == 0 then
    add("KAFKA-SASL-AUDIT-INCONCLUSIVE", "The mechanism audit could not reach a conclusion",
      verdict.state == "unreachable" and "NONE" or "INFO", tostring(verdict.reason),
      { "mechanisms read: " .. fmt_list(mechanisms.mechanisms, 6) }, KB.REMEDIATION[1])
  end

  if cfg.verified_credential then
    add("KAFKA-SCRAM-CREDENTIAL-VERIFIED", "The supplied credential completes the SCRAM exchange", "INFO",
      string.format("The exchange with the supplied account finished with the server signature "
        .. "verified (%s, iterations %s), a stronger statement than a successful login: the broker "
        .. "proved it holds the verifier for that password.", tostring(cfg.verified_credential.mechanism),
        num_text(cfg.verified_credential.iterations)), { string.format("salt: %s", tostring(cfg.verified_credential.salt or "not exposed")) },
      KB.REMEDIATION[4])
  end
  return list
end

----------------------------------------------------------------------------
-- 7. Report
----------------------------------------------------------------------------

local report = {}

function report.mechanism_section(cat, mechanisms)
  local lines = { "Offered: " .. fmt_list(mechanisms.mechanisms, 12),
    string.format("Proof based: %s, password sending: %s, delegated: %s", num_text(cat.proof_based),
      num_text(cat.password_sending), num_text(cat.counts.delegated or 0)) }
  for _, row in ipairs(cat.rows) do
    lines[#lines + 1] = string.format("%-16s %-10s %s%s", row.name, row.class, row.deprecated and "(deprecated) " or "", row.note)
  end
  if #cat.rows == 0 then lines[#lines + 1] = "The handshake returned no mechanism list." end
  return lines
end

function report.scram_section(mechanism, scram)
  if not mechanism then return { "No SCRAM variant is offered by this listener." } end
  local lines = {
    string.format("Server-first messages read: %s", plural(scram.answered, "name")),
    string.format("Salt policy: %s (length %s)", tostring(scram.salt_policy),
      scram.salt_length and (scram.salt_length .. " byte(s)") or "not present"),
    string.format("Iterations: min %s, max %s (%s)", num_text(scram.iteration_min),
      num_text(scram.iteration_max), KB.iteration_verdict(scram.iteration_min)),
    string.format("Nonce: the server's nonce %s the client's", scram.nonce_not_echoed
      and "does NOT extend" or "extends"), }
  for _, entry in ipairs(scram.salts) do
    lines[#lines + 1] = string.format("%-24s %s", entry.user, salt_summary(entry.salt, entry.b64))
  end
  return lines
end

function report.enumeration_section(enum, cfg)
  local lines = {
    string.format("Baseline (a name that cannot exist): %s", tostring(enum.baseline or "no reply")),
    string.format("Candidates tested by completing the exchange: %s", num_text(enum.tested)),
    string.format("Answers that differed from the baseline: %s", num_text(#enum.distinguishing)), }
  for _, item in ipairs(enum.distinguishing) do
    lines[#lines + 1] = string.format("%-24s %s", item.user, tostring(item.failure_token))
  end
  if enum.tested == 0 and cfg.verified_credential then
    lines[#lines + 1] = "The only candidate supplied was accepted with the credential this run was "
      .. "given, so there was no refused exchange left to compare against the baseline."
  elseif enum.tested == 0 then
    lines[#lines + 1] = "No candidate names were supplied (kafka.names), so the oracle was only "
      .. "observed for names that do not exist and no claim is made either way."
  elseif not enum.oracle then
    lines[#lines + 1] = "Every candidate was answered with the baseline token, which is what RFC 5802 " .. "requires."
  end
  if enum.tested > 0 then
    lines[#lines + 1] = "A failed authentication was sent for each candidate name; a lockout policy "
      .. "counts those attempts."
  end
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

function report.build(cfg, host, port, mechanism, mechanisms, cat, scram, enum, verdict, list, w)
  local out = stdnse.output_table()
  out["Target"] = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id %s, timeout %dms, iteration floor %s", cfg.client_id, cfg.timeout, num_text(cfg.iterations_min)),
    string.format("Audited mechanism: %s", tostring(mechanism or "none offered")),
    string.format("Candidate accounts tested: %s", fmt_list(cfg.names, 8, "none supplied")),
    string.format("Composite verdict: %s - %s", tostring(verdict.state), tostring(verdict.reason)), }
  out["Mechanisms offered"] = report.mechanism_section(cat, mechanisms)
  out["SCRAM server-first message"] = report.scram_section(mechanism, scram)
  out["User enumeration oracle"] = report.enumeration_section(enum, cfg)
  out["Findings"] = report.finding_section(list)
  out["Verification"] = KB.VERIFICATION
  out["Method limits and rubric"] = KB.METHOD_LIMITS
  for _, entry in ipairs(KB.RISK_RUBRIC) do
    out["Method limits and rubric"][#out["Method limits and rubric"] + 1] = "Rubric - " .. entry.severity .. ": " .. entry.condition
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

----------------------------------------------------------------------------
-- 8. Orchestration
----------------------------------------------------------------------------

local function unreachable_report(cfg, host, port, reason, mechanisms)
  return {
    ["Risk Level"] = "UNKNOWN", Target = { string.format("Endpoint: %s:%d/tcp", host.ip or "target", port.number),
      string.format("Client id %s, mechanism %s", cfg.client_id, cfg.requested), "No SASL response was received: " .. tostring(reason) },
    ["Mechanisms offered"] = { "Nothing was read: " .. fmt_list(mechanisms and mechanisms.mechanisms, 6) },
    ["Method limits and rubric"] = { "The listener did not answer the SASL handshake, so nothing is claimed about its mechanisms or its parameters." }, }
end

action = function(host, port)
  local cfg = read_config()
  local w = Wire.new(host, port, cfg)
  if not w.connection.sock then
    return unreachable_report(cfg, host, port, w.connection.last_error, nil)
  end

  local mechanisms = probe.mechanisms(w)
  if not mechanisms.answered then
    w:close()
    return unreachable_report(cfg, host, port, mechanisms.error, mechanisms)
  end

  local cat = catalogue(mechanisms.mechanisms)
  local mechanism, offered = choose_mechanism(mechanisms.mechanisms, cfg.requested)
  local scram = { answered = 0, iteration_values = {}, salts = {}, salt_policy = "unreadable" }
  local enum = { tested = 0, distinguishing = {}, baseline = nil }

  -- A broker keys a SASL exchange to the connection it arrived on, so every
  -- exchange after the catalogue read opens its own socket: an abandoned
  -- exchange leaves the server waiting for a client-final it will never send.
  local function exchange(fn)
    local wire = Wire.new(host, port, cfg, w.trace)
    if not wire.connection.sock then
      wire:fail("connect", wire.connection.last_error or "connection failed")
      return { ok = false, error = wire.connection.last_error or "connection failed" }
    end
    local value = fn(wire)
    wire:close()
    return value
  end

  if mechanism and offered then
    local baseline_a = impossible_name()
    local baseline_b = impossible_name()
    local probes = { exchange(function(x) return probe.scram_first(x, mechanism, baseline_a, 1) end),
      exchange(function(x) return probe.scram_first(x, mechanism, baseline_b, 2) end),
      exchange(function(x) return probe.scram_first(x, mechanism, baseline_a, 3) end) }
    scram = analysis.scram(probes)

    -- The audit reads the salt for several names; completing the exchange is
  -- what exposes the error tokens. The baseline name
    -- cannot exist, so its token is the "unknown account" answer; every candidate
    -- is compared against it.
    local wrong = string.format("nmap-wrong-%06d-not-the-password", math.random(0, 999999))
    local cheap = { proof_iterations = 1 }
    local baseline = exchange(function(x)
      return probe.scram_complete(x, mechanism, baseline_a, wrong, 1, cheap)
    end)
    enum.baseline = baseline.failure_token
    local candidates = {}
    for index, name in ipairs(cfg.names) do
      if index <= 4 then
        -- The account the operator supplied a credential for is completed with a
        -- genuine proof, because a success is the finding; every other name only
        -- needs the answer the broker gives to a well-formed wrong proof.
        local known = cfg.password_supplied and name == cfg.user
        local password = known and cfg.password or wrong
        local options = known and {} or cheap
        local attempt = exchange(function(x)
          return probe.scram_complete(x, mechanism, name, password, index + 1, options)
        end)
        if attempt.status == "accepted" then
          cfg.verified_credential = { mechanism = mechanism, iterations = attempt.iterations,
            salt = attempt.salt and (string.sub(attempt.salt, 1, 12) .. "..") or nil }
        else
          candidates[#candidates + 1] = attempt
        end
      end
    end
    enum = analysis.enumeration({ failure_token = baseline.failure_token }, candidates)
  end
  w:close()

  local verdict = analysis.verdict(mechanisms, cat, scram, enum, mechanism)
  local list = findings.evaluate(cfg, mechanism, mechanisms, cat, scram, enum, verdict)
  local result = report.build(cfg, host, port, mechanism, mechanisms, cat, scram, enum, verdict, list, w)
  publish_findings(host, port, list)
  return result
end
