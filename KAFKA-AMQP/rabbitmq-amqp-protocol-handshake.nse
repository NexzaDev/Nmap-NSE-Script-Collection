local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The AMQP engine speaks 0-9-1; the TLS probe decides whether the port is really a
-- TLS listener wearing an AMQP port number.
local ok_rmq, rabbitmq = pcall(require, "rabbitmq")
local ok_tls, tlsprobe = pcall(require, "tlsprobe")
local has_vulns, vulns_lib = pcall(require, "vulns")

local SCRIPT_NAME = "rabbitmq-amqp-protocol-handshake"
local SCRIPT_RISK = "LOW"
local SCRIPT_VERSION = "1.0.0"

description = [[
Reads what a RabbitMQ broker says before anyone authenticates.

The AMQP 0-9-1 protocol header is the first thing a client sends, and the broker
answers with connection.start: the product and version strings, the platform and
Erlang release, the cluster name, the capability table (what a client may rely
on, and which safety behaviours this broker does not have), the SASL mechanisms
it accepts and its locales. None of it needs a credential, and all of it is
version, platform and configuration disclosure.

The script sends the 0-9-1 header, then the AMQP 1.0 header on a second
connection, so the report separates a port that speaks both protocols from one
that answers a version it does not speak with its own header. A TLS listener
answers the plaintext header with a TLS record, and that transport verdict is
reported instead of a handshake that never happened.

Authentication is attempted only when an identity is supplied (rabbitmq.user and
rabbitmq.password). The reply is evidence: a refusal that names the reason ("user
'guest' can only connect via localhost") turns the login path into an
account-existence oracle, while silence explains why a failed login is hard to
diagnose. Both are findings, with the broker's words quoted, and a valid
credential is reported as proven.
]]

---
-- @usage
-- nmap -p 5672 --script rabbitmq-amqp-protocol-handshake <target>
-- nmap -p 5672 --script rabbitmq-amqp-protocol-handshake --script-args rabbitmq.mechanism=AMQPLAIN <target>
--
-- @args rabbitmq.timeout   Per-request timeout in milliseconds (default 5000).
-- @args rabbitmq.client-id Client identity reported in the connection properties.
-- @args rabbitmq.mechanism SASL mechanism for the authentication stage: "auto"
--                          (default) prefers PLAIN, AMQPLAIN, then EXTERNAL.
-- @args rabbitmq.user      Account for the authentication stage. Without it no
--                          credential is sent at all.
-- @args rabbitmq.password  Password for rabbitmq.user.
-- @args rabbitmq.vhost     Vhost to open during the authentication stage (default "/").
-- @args rabbitmq.verbose   "true" adds the per-stage probe transcript.

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({5672, 5671, 25672, 15672}, {"amqp", "amqps", "http"}, {"tcp"})

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

local function read_config()
  local user = arg_string("rabbitmq.user", nil, 128)
  return {
    timeout = arg_number("rabbitmq.timeout", 5000, 500, 60000),
    client_id = arg_string("rabbitmq.client-id", "nmap-amqp-handshake", 120),
    mechanism = string.upper(arg_string("rabbitmq.mechanism", "AUTO", 32)),
    user = user, password = arg_string("rabbitmq.password", nil, 256),
    credentials_supplied = user ~= nil,
    vhost = arg_string("rabbitmq.vhost", "/", 128),
    verbose = arg_bool("rabbitmq.verbose", false),
  }
end

----------------------------------------------------------------------------
-- 2. Formatting helpers
----------------------------------------------------------------------------

local function plural(count, singular, plural_form)
  count = tonumber(count) or 0
  return string.format("%d %s", count, count == 1 and singular or (plural_form or (singular .. "s")))
end

local function fmt_list(values, limit, empty_text)
  if not values or #values == 0 then return empty_text or "none" end
  limit = limit or 6
  local out = {}
  for index = 1, math.min(#values, limit) do out[#out + 1] = tostring(values[index]) end
  if #values > limit then out[#out + 1] = string.format("(+%d more)", #values - limit) end
  return table.concat(out, ", ")
end

-- A stable, readable ordering for a name list, used by the report and the
-- capability parser: pairs() has no order, a report does.
local function sorted_keys(values)
  local names = {}
  for name in pairs(values or {}) do names[#names + 1] = tostring(name) end
  table.sort(names)
  return names
end

local function finding(id, title, severity, detail, evidence, remediation)
  return { id = id, title = title, severity = severity, detail = detail, evidence = evidence or {},
    remediation = remediation or {} }
end

local function severity_summary(list)
  local parts, counts = {}, {}
  for _, item in ipairs(list) do counts[item.severity] = (counts[item.severity] or 0) + 1 end
  for _, severity in ipairs({ "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }) do
    if counts[severity] then parts[#parts + 1] = string.format("%s x%d", severity, counts[severity]) end
  end
  return #parts > 0 and table.concat(parts, ", ") or "no findings"
end

local function worst(list, default)
  local order = { CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0, NONE = -1, UNKNOWN = -1 }
  local level, text = order[default] or -1, default
  for _, item in ipairs(list) do
    if (order[item.severity] or -1) > level then level, text = order[item.severity], item.severity end
  end
  return text
end

-- The two shapes of the NSE vulns API (Report:new and the older factory
-- function) are folded into one publisher so a finding reaches the database
-- whichever the running Nmap ships.
local function vuln_publisher(host, port)
  if not has_vulns or type(vulns_lib) ~= "table" then return nil end
  local detail = function(text) return { format = function() return text end } end
  local ok_pub, publisher = pcall(function()
    if type(vulns_lib.Report) == "table" and type(vulns_lib.Report.new) == "function" then
      local report = vulns_lib.Report:new(SCRIPT_NAME, host, port)
      return function(id, title, text) report:add(id, title, detail(text)) end
    end
    if type(vulns_lib.Report) == "function" then
      local report = vulns_lib.Report(host, port)
      return function(id, title, text) report.add(host, port, id, title, detail(text)) end
    end
    return nil
  end)
  return ok_pub and publisher or nil
end

local function publish_findings(host, port, list)
  local publish = vuln_publisher(host, port)
  if not publish then return end
  local publishable = { CRITICAL = true, HIGH = true, MEDIUM = true }
  for _, item in ipairs(list) do
    if publishable[item.severity] then publish(item.id, item.title, item.detail) end
  end
end

----------------------------------------------------------------------------
-- 3. Knowledge tables
----------------------------------------------------------------------------

local KB = {}

-- What each advertised capability means, and what its absence costs: the table is
-- why a capability that was not advertised is described instead of printed as a
-- boolean. A missing consumer_cancel_notify is an operational defect; a missing
-- per_consumer_qos is not.
KB.CAPABILITIES = {
  publisher_confirms = { impact = "LOW", means = "the broker confirms published messages",
    absent = "publishers cannot tell a lost publish from a slow one" },
  consumer_cancel_notify = { impact = "LOW", means = "the broker tells a consumer when its queue is deleted",
    absent = "consumers wait on a queue that no longer exists and learn of it only at the next publish" },
  connection_blocked = { impact = "LOW", means = "the broker tells a client when a resource alarm blocks it",
    absent = "a blocked publisher looks like a hung network, the most common operational confusion" },
  basic_nack = { impact = "INFO", means = "negative acknowledgements are available",
    absent = "a consumer can only reject single messages" },
  consumer_priorities = { impact = "INFO", means = "consumers can declare a priority",
    absent = "priority consumers are unavailable" },
  authentication_failure_close = { impact = "LOW", means = "a failed login closes with a reason (3.2+)",
    absent = "a failed login is answered with silence, so a client can only time out" },
  exchange_exchange_bindings = { impact = "INFO", means = "exchanges can be bound to other exchanges",
    absent = "routing is limited to exchange-to-queue bindings" },
  per_consumer_qos = { impact = "INFO", means = "prefetch can be set per consumer",
    absent = "prefetch is per channel" },
  direct_reply_to = { impact = "INFO", means = "the RPC reply-to pattern is supported",
    absent = "request/reply is implemented by hand" },
}

-- The SASL mechanisms RabbitMQ ships and what each costs.
KB.MECHANISMS = {
  PLAIN = { class = "password-sending", severity = "LOW",
    note = "the password travels inside the exchange; TLS is what protects it" },
  AMQPLAIN = { class = "password-sending", severity = "LOW",
    note = "the same password in a field table: obfuscation, not protection" },
  EXTERNAL = { class = "delegated", severity = "INFO",
    note = "the identity comes from the transport (a client certificate), so no password is sent" },
  ["RABBIT-CR-DEMO"] = { class = "challenge-response", severity = "INFO",
    note = "a demonstration mechanism that proves knowledge of a shared secret" },
  ANONYMOUS = { class = "anonymous", severity = "HIGH",
    note = "the broker accepts a connection without an identity" },
}

KB.REMEDIATION = {
  { step = "Put the AMQP listener behind TLS (amqps on 5671) and retire the plaintext listener, or hold it "
      .. "on a network that cannot be observed.",
    why = "PLAIN and AMQPLAIN send the password inside the exchange, so a reader of the stream has it." },
  { step = "Keep the broker release current and review which plugins widen the exposed banner.",
    why = "The version, Erlang release and plugin list are what an attacker uses to choose an exploit." },
  { step = "Set the cluster name to a value that is not used as an inter-node credential, or rotate that "
      .. "credential.",
    why = "RabbitMQ uses the cluster name as the default inter-node authentication identity." },
  { step = "Do not let a login failure name the account, and keep authentication_failure_close enabled.",
    why = "A message separating an unknown user from a wrong password enumerates accounts; silence hides a "
      .. "real failure." },
  { step = "Remove the mechanisms the deployment does not use from the enabled list.",
    why = "Every mechanism left enabled is one a client can be downgraded into." },
}

-- How each tlsprobe classification reads as a transport verdict: both TLS kinds
-- mean the same thing, that this port is not a plaintext protocol.
-- The two reply codes that say something specific about a refused identity.
KB.REFUSAL_STATES = {
  [403] = { "refused-403", "ACCESS_REFUSED: the broker refused the credential and named a reason" },
  [530] = { "refused-vhost", "NOT_ALLOWED: the credential was accepted but the vhost was refused" },
}

KB.TRANSPORT_VERDICTS = {
  ["tls-server-hello"] = "tls-listener",
  ["tls-record"] = "tls-listener",
  ["tls-alert"] = "tls-listener-refusing-the-hello",
  ["silent"] = "no-answer",
  ["not-tls"] = "plaintext-protocol",
}

KB.VERIFICATION = {
  "rabbitmq-diagnostics listeners  (protocol, port and socket options per listener)",
  "rabbitmqctl environment | grep -E 'auth_mechanisms|enabled_plugins'  (mechanisms and plugins)",
  "rabbitmqctl status | grep -E 'listeners|interface'  (which listeners are supposed to exist)",
  "rabbitmqctl eval 'rabbit_nodes:cluster_name().'  (the cluster name the handshake disclosed)",
}

KB.METHOD_LIMITS = {
  "The protocol header and the start frame are read with no credential; connection.start-ok is sent only "
    .. "when rabbitmq.user is supplied, so no login is attempted without one.",
  "That attempt is a login the operator sees in the broker log: use an account the operator chose, and "
    .. "account for a lockout policy.",
  "The capability table says what the broker supports, not how it is configured: an advertised capability "
    .. "can still be denied by a policy or an unloaded plugin.",
  "Mechanisms come from the broker's list; whether one succeeds depends on the authentication backend.",
  "The AMQP 1.0 check reads the first reply only: a port that answers nothing is reported as unknown.",
}

KB.RISK_RUBRIC = {
  { severity = "HIGH", condition = "the broker accepts an unauthenticated connection, or an EXTERNAL "
      .. "identity nothing verifies" },
  { severity = "LOW", condition = "version, platform or cluster disclosure, a password-sending mechanism on "
      .. "a plaintext listener, or a login failure that names the account" },
  { severity = "INFO", condition = "the handshake was read and describes a normally configured listener" },
}

----------------------------------------------------------------------------
-- 4. Probes
----------------------------------------------------------------------------

local probe = {}

-- The full negotiation: header, start frame, and (only when a credential was
-- supplied) the tune or the refusal. Every stage is kept so the report can quote
-- the exact point that answered.
function probe.negotiate(host, port, cfg)
  local attempt = rabbitmq.handshake(host.ip or host.name, port.number, {
    timeout_ms = cfg.timeout, client_id = cfg.client_id, vhost = cfg.vhost,
    mechanism = cfg.mechanism ~= "AUTO" and cfg.mechanism or nil,
    user = cfg.user, password = cfg.password,
  })
  local out = { handshake = attempt, capabilities = attempt.capabilities or {},
    mechanisms = attempt.mechanisms or {}, locales = attempt.locales or {}, stages = attempt.stages or {} }
  for _, key in ipairs({ "start", "server_properties", "protocol_reply", "status", "ok", "error", "version",
    "authenticated", "first_reply", "refused" }) do
    out[key] = attempt[key]
  end
  out.reply_close = attempt.close
  return out
end

-- The 1.0 header on its own connection. Three answers look alike from outside: a
-- 0-9-1-only broker replies with its own header (the required answer to a version
-- it does not speak), a broker with the amqp1_0 plugin replies with a 1.0 header,
-- and a management port replies with HTTP.
function probe.amqp10(host, port, cfg)
  local attempt = rabbitmq.handshake(host.ip or host.name, port.number, {
    timeout_ms = cfg.timeout, client_id = cfg.client_id,
    header = rabbitmq.PROTOCOL_HEADER_100, vhost = cfg.vhost,
  })
  local reply = attempt.protocol_reply
  local out = {
    handshake = attempt, stages = attempt.stages or {}, error = attempt.error,
    status = attempt.status, first_reply = attempt.first_reply, reply = reply,
  }
  if reply and reply.family == "AMQP" then
    out.reply_version = string.format("%d.%d.%d", tonumber(reply.major) or 0, tonumber(reply.minor) or 0,
      tonumber(reply.revision) or 0)
  end
  if attempt.start then
    out.verdict, out.speaks_091 = "answers-a-0-9-1-start-frame", true
  elseif reply and reply.family == "AMQP" and tonumber(reply.major) == 1 then
    out.verdict, out.speaks_100 = "answers-the-1.0-header", true
  elseif reply and reply.family == "AMQP" then
    out.verdict, out.speaks_091 = "refuses-the-1.0-header-with-its-own", true
  elseif reply and reply.family == "HTTP" then
    out.verdict = "http-listener"
  else
    out.verdict = "no-answer"
  end
  out.answered = out.verdict ~= "no-answer"
  return out
end

-- A TLS ClientHello decides whether this is an amqps listener, which changes the
-- meaning of every credential finding.
function probe.transport(host, port, cfg)
  if not ok_tls or type(tlsprobe) ~= "table" then
    return { available = false, note = "nselib/tlsprobe.lua is not installed" }
  end
  local reply = tlsprobe.probe(host.ip or host.name, port.number, { timeout_ms = cfg.timeout })
  reply.available = true
  reply.verdict = KB.TRANSPORT_VERDICTS[reply.kind] or "unknown"
  return reply
end

----------------------------------------------------------------------------
-- 5. Analysis
----------------------------------------------------------------------------

local analysis = {}

-- The capability inventory in both directions: what the broker advertised (and
-- what that means) and what it did not (and what that costs the deployment).
function analysis.capabilities(capabilities)
  local out = { advertised = sorted_keys(capabilities), missing = {}, unknown = {}, notes = {} }
  out.count = #out.advertised
  for _, name in ipairs(out.advertised) do
    local entry = KB.CAPABILITIES[name] or { impact = "INFO",
      means = "a capability this script has no description for" }
    if not KB.CAPABILITIES[name] then out.unknown[#out.unknown + 1] = name end
    out.notes[#out.notes + 1] = { name = name, impact = entry.impact, text = entry.means }
  end
  for name, entry in pairs(KB.CAPABILITIES) do
    if not capabilities[name] then
      out.missing[#out.missing + 1] = { name = name, impact = entry.impact, text = entry.absent }
    end
  end
  table.sort(out.missing, function(a, b) return a.name < b.name end)
  return out
end

-- Each offered mechanism is classified from the table above, and the per-class
-- name lists the findings quote are collected here rather than filtered again.
local MECHANISM_CLASSES = { "password-sending", "delegated", "anonymous" }

function analysis.mechanisms(offered)
  local out = { rows = {}, names = {}, unknown = {}, by_class = {}, names_by_class = {} }
  for _, class in ipairs(MECHANISM_CLASSES) do
    out.by_class[class], out.names_by_class[class] = 0, {}
  end
  for _, name in ipairs(offered or {}) do
    local entry, row = KB.MECHANISMS[name], { name = name }
    out.names[#out.names + 1] = name
    if entry then
      row.class, row.severity, row.note = entry.class, entry.severity, entry.note
      out.by_class[entry.class] = (out.by_class[entry.class] or 0) + 1
      local names = out.names_by_class[entry.class] or {}
      names[#names + 1] = name
      out.names_by_class[entry.class] = names
    else
      row.class, row.severity, row.note = "opaque", "INFO", "no description in this script"
      out.unknown[#out.unknown + 1] = name
    end
    out.rows[#out.rows + 1] = row
  end
  out.count = #out.rows
  out.password_sending, out.delegated = out.by_class["password-sending"], out.by_class.delegated
  out.anonymous = out.by_class.anonymous
  out.password_names, out.delegated_names = out.names_by_class["password-sending"], out.names_by_class.delegated
  out.anonymous_names = out.names_by_class.anonymous
  return out
end

-- The authentication stage verdict. The distinction that matters: a refusal that
-- names the reason is an oracle, silence is a diagnosis problem, and a tune means
-- the identity was accepted for the vhost.
function analysis.authentication(negotiation, cfg)
  local out = { attempted = cfg.credentials_supplied, user = cfg.user, state = "not-attempted",
    reason = "no credential was supplied (rabbitmq.user), so the login path was not exercised" }
  if not cfg.credentials_supplied then return out end
  if negotiation.authenticated then
    out.state = "accepted"
    out.reason = string.format("the broker tuned the connection for user %s, so the credential is valid",
      tostring(cfg.user))
    out.vhost_opened = negotiation.handshake and negotiation.handshake.vhost_open or false
    return out
  end
  local close = negotiation.reply_close
  if close then
    out.code, out.code_name, out.text = close.reply_code, close.reply_name, close.reply_text
    local text = tostring(close.reply_text or "")
    out.names_the_account = string.find(text, "does not exist") ~= nil
      or string.find(text, "not found") ~= nil or string.find(text, "can only connect via localhost") ~= nil
    if string.find(text, "can only connect via localhost") then
      out.state = "refused-localhost-restriction"
      out.reason = "the account exists but is restricted to loopback connections"
    elseif KB.REFUSAL_STATES[close.reply_code] then
      out.state, out.reason = KB.REFUSAL_STATES[close.reply_code][1], KB.REFUSAL_STATES[close.reply_code][2]
    else
      out.state = "refused"
      out.reason = string.format("%s during the negotiation", tostring(close.reply_name))
    end
    return out
  end
  if negotiation.status == "no-tune" then
    out.state = "no-answer"
    out.reason = "the broker accepted start-ok and then answered nothing: a failed login without a reason, "
      .. "which is what a broker without authentication_failure_close does"
    return out
  end
  if negotiation.status == "mechanism-not-offered" then
    out.state = "mechanism-not-offered"
    out.reason = "the requested mechanism is not in the broker's list"
    return out
  end
  out.state = "unknown"
  out.reason = tostring(negotiation.error or "the authentication stage produced no verdict")
  return out
end

-- The composite verdict: which kind of listener this is, before any finding is
-- graded, so the report cannot describe a TLS port as an AMQP one.
function analysis.verdict(negotiation, transport, mechanisms, capabilities)
  local out = { state = "unknown", reason = "nothing was read from the port" }
  if transport and transport.verdict == "tls-listener" then
    out.state = "tls-listener"
    out.reason = string.format("the port answered a TLS ClientHello (%s): this is an amqps listener",
      tostring(transport.cipher_suite_name or transport.summary or "a TLS record"))
    return out
  end
  if not negotiation.start then
    local reply = negotiation.protocol_reply or {}
    if reply.family == "HTTP" then
      out.state = "http-listener"
      out.reason = "the AMQP header was answered with an HTTP response: this port serves the management API"
    elseif reply.family == "TLS" then
      out.state = "tls-listener"
      out.reason = "the AMQP header was answered with a TLS record, so this is an amqps listener and the "
        .. "plaintext protocol is refused, as it should be"
    elseif reply.family == "AMQP" then
      out.state = "protocol-version-mismatch"
      out.reason = string.format("the server answered with its own protocol header (AMQP %s.%s.%s), which "
        .. "is the required answer to a version it does not speak", tostring(reply.major),
        tostring(reply.minor), tostring(reply.revision))
    else
      out.state = "not-amqp"
      out.reason = string.format("the AMQP 0-9-1 header was not answered (%s)",
        tostring(negotiation.error or "no reply"))
    end
    return out
  end
  if mechanisms.anonymous > 0 then
    out.state = "anonymous-mechanism"
    out.reason = "the broker advertises an anonymous mechanism, so a connection needs no identity"
    return out
  end
  out.state = "handshake-read"
  out.reason = string.format("AMQP %s read with %s from %s and %d capability(ies)", tostring(negotiation.version),
    plural(mechanisms.count, "mechanism"),
    tostring((negotiation.server_properties or {}).product or "an unnamed product"),
    tonumber(capabilities and capabilities.count) or 0)
  return out
end

----------------------------------------------------------------------------
-- 6. Findings
----------------------------------------------------------------------------

local findings = {}

function findings.evaluate(cfg, negotiation, capabilities, mechanisms, authentication, amqp10, transport,
  verdict)
  local list = {}
  local function add(id, title, severity, detail, evidence, ...)
    list[#list + 1] = finding(id, title, severity, detail, evidence, { ... })
  end
  local properties = negotiation.server_properties or {}

  if negotiation.start then
    add("RABBITMQ-HANDSHAKE-DISCLOSURE", "The broker describes itself before authentication", "LOW",
      string.format("connection.start names %s %s on %s, in cluster %s, to any client that sends eight bytes: "
        .. "it is how AMQP works, and it is the first line of an exploit search.", tostring(properties.product),
        tostring(properties.version), tostring(properties.platform), tostring(properties.cluster_name)),
      { string.format("%s %s on %s, cluster %s", tostring(properties.product), tostring(properties.version),
          tostring(properties.platform), tostring(properties.cluster_name)) }, KB.REMEDIATION[2])
  end

  if properties.cluster_name and #tostring(properties.cluster_name) > 0 then
    add("RABBITMQ-CLUSTER-NAME-DISCLOSURE", "The cluster name is disclosed to an unauthenticated client", "LOW",
      string.format("connection.start reports the cluster name %s, which RabbitMQ uses as the default "
        .. "inter-node authentication identity: a reader of this frame has half of the internal credential.",
        tostring(properties.cluster_name)),
      { "cluster name: " .. tostring(properties.cluster_name) }, KB.REMEDIATION[3])
  end

  if mechanisms.password_sending > 0 and negotiation.start and verdict.state ~= "tls-listener" then
    add("RABBITMQ-PASSWORD-MECHANISM-ON-PLAINTEXT", "A password-sending SASL mechanism is offered on an "
      .. "unencrypted listener", "LOW",
      string.format("The broker accepts %s, and without TLS the password travels inside the exchange, so a "
        .. "reader of the stream has the credential: how plaintext AMQP is defined, graded as a deployment "
        .. "decision rather than as a vulnerability.", fmt_list(mechanisms.password_names, 4)),
      { "mechanisms: " .. fmt_list(mechanisms.names, 8) }, KB.REMEDIATION[1], KB.REMEDIATION[5])
  end

  if mechanisms.delegated > 0 and negotiation.start then
    add("RABBITMQ-EXTERNAL-MECHANISM", "The broker accepts an identity taken from the transport", "INFO",
      "EXTERNAL is offered, so the identity comes from the transport (a TLS client certificate) rather than "
        .. "from a password: strong when certificates are verified, weak when a proxy header is trusted.",
      { "mechanisms: " .. fmt_list(mechanisms.delegated_names, 4) }, KB.REMEDIATION[5])
  end

  if mechanisms.anonymous > 0 and negotiation.start then
    add("RABBITMQ-ANONYMOUS-MECHANISM-OFFERED", "The broker offers to authenticate nobody", "HIGH",
      "An anonymous mechanism is offered, so a client completes the negotiation without proving an identity: "
        .. "anything that can reach the port reaches the broker.",
      { "mechanisms: " .. fmt_list(mechanisms.anonymous_names, 4) }, KB.REMEDIATION[1])
  end

  if authentication.attempted and authentication.names_the_account then
    add("RABBITMQ-LOGIN-FAILURE-NAMES-THE-ACCOUNT", "A failed login says whether the account exists", "LOW",
      string.format("The broker refused the attempt with %s in a message that separates an unknown account "
        .. "from a wrong password, so accounts can be enumerated one connection each, without guessing one.",
        tostring(authentication.code_name)),
      { "reply: " .. tostring(authentication.code) .. " " .. tostring(authentication.code_name),
        "text: " .. tostring(authentication.text) }, KB.REMEDIATION[4])
  elseif authentication.attempted and authentication.state == "no-answer" then
    add("RABBITMQ-LOGIN-FAILURE-IS-SILENT", "A failed login is answered with nothing", "INFO",
      "The broker stopped talking instead of refusing: nothing is disclosed, and a real user with the wrong "
        .. "password sees a hung client rather than a reason. That is why authentication_failure_close exists.",
      { "state: " .. tostring(authentication.state) }, KB.REMEDIATION[4])
  end

  if authentication.attempted and authentication.state == "accepted" then
    local plaintext = verdict.state ~= "tls-listener"
    add("RABBITMQ-CREDENTIAL-ACCEPTED", "The credential the operator supplied is valid on this listener",
      plaintext and "LOW" or "INFO",
      string.format("The broker tuned the connection and opened vhost %s for %s, so the identity is real.%s",
        tostring(cfg.vhost), tostring(cfg.user), plaintext
          and " Over an unencrypted listener that credential also travels in a form a stream reader captures."
          or ""),
      { string.format("account: %s, vhost: %s (opened), transport: %s", tostring(cfg.user), tostring(cfg.vhost),
          plaintext and "plaintext" or "TLS") }, KB.REMEDIATION[1])
  end

  local close_reply = negotiation.reply_close
  if close_reply and close_reply.reply_code == 530 then
    add("RABBITMQ-VHOST-ACCESS-REFUSED", "The credential is valid but the vhost is denied", "INFO",
      string.format("The broker accepted the identity, then refused vhost %s with %s (%s): the login "
        .. "succeeded and the authorization did not.", tostring(cfg.vhost),
        tostring(close_reply.reply_code_name), tostring(close_reply.reply_text)),
      { string.format("connection.open: %s %s for vhost %s", tostring(close_reply.reply_code),
          tostring(close_reply.reply_code_name), tostring(cfg.vhost)) }, KB.REMEDIATION[1])
  end

  -- A capability list only means something when a start frame carried one: on a
  -- port that never spoke AMQP, every capability would look missing.
  if negotiation.start then
    for _, entry in ipairs(capabilities.missing) do
      if entry.impact == "LOW" or entry.impact == "MEDIUM" then
        add("RABBITMQ-CAPABILITY-NOT-ADVERTISED", "A safety capability a client may rely on is not advertised",
          entry.impact, string.format("The broker does not advertise %s: %s.", entry.name, entry.text),
          { "missing: " .. entry.name }, KB.REMEDIATION[2])
      end
    end
  end


  if amqp10 and amqp10.speaks_100 then
    add("RABBITMQ-AMQP10-AVAILABLE", "The port answers the AMQP 1.0 protocol header", "INFO",
      string.format("The 1.0 header was answered with the server's own 1.0 header (%s), so the amqp1_0 plugin "
        .. "is loaded: a second protocol is a second implementation, with its own version and its own history.",
        tostring(amqp10.reply_version)),
      { "1.0 probe: " .. tostring(amqp10.verdict) .. "; first reply: " .. tostring(amqp10.first_reply) },
      KB.REMEDIATION[2])
  elseif amqp10 and amqp10.verdict == "refuses-the-1.0-header-with-its-own" then
    add("RABBITMQ-AMQP10-NOT-OFFERED", "The broker answers the AMQP 1.0 header with its own 0-9-1 header",
      "INFO",
      string.format("The 1.0 header was answered with AMQP %s, the required answer to a version that is not "
        .. "supported: the listener speaks AMQP 0-9-1 only.", tostring(amqp10.reply_version)),
      { "first reply: " .. tostring(amqp10.first_reply) }, KB.REMEDIATION[2])
  elseif amqp10 and amqp10.verdict == "no-answer" then
    add("RABBITMQ-AMQP10-SILENT", "The port ignored the AMQP 1.0 protocol header", "INFO",
      "The 1.0 header was answered with nothing: a 0-9-1 broker answers a version mismatch with its own "
        .. "header, so either the port is not a RabbitMQ listener or a middlebox drops it.",
      { "first reply: " .. tostring(amqp10.error or "nothing") }, KB.REMEDIATION[2])
  end

  if transport and transport.verdict == "tls-listener" then
    add("RABBITMQ-CONFIGURED-FOR-TLS", "The audited port is a TLS listener", "INFO",
      string.format("A ClientHello was answered with %s, so this is the amqps listener: the credential "
        .. "findings above are protected by the transport.", tostring(transport.summary or "a TLS record")),
      { "tls: " .. tostring(transport.summary or transport.kind) }, KB.REMEDIATION[1])
  end

  if properties.product and not string.find(string.lower(tostring(properties.product)), "rabbitmq") then
    add("RABBITMQ-DIFFERENT-PRODUCT", "The AMQP broker is not RabbitMQ", "INFO",
      string.format("connection.start names %s %s, a different AMQP 0-9-1 implementation: the capability and "
        .. "mechanism findings still apply, the RabbitMQ remediation does not.",
        tostring(properties.product), tostring(properties.version)),
      { "product: " .. tostring(properties.product) }, KB.REMEDIATION[2])
  end

  if verdict.state == "http-listener" then
    add("RABBITMQ-MANAGEMENT-PORT", "The port answers the AMQP header with HTTP", "INFO",
      "The AMQP header was answered with HTTP, so this port serves the management API rather than AMQP. The "
        .. "management scripts in this category audit that surface.",
      { "first reply: " .. tostring(negotiation.first_reply or "HTTP") }, KB.REMEDIATION[2])
  end

  if #list == 0 then
    add("RABBITMQ-HANDSHAKE-READ", "The AMQP handshake was read without authentication", "INFO",
      string.format("The listener answered the header and offered %s, with no property graded as a defect.",
        plural(mechanisms.count, "mechanism")),
      { "verdict: " .. tostring(verdict.state) }, KB.REMEDIATION[5])
  end
  return list
end

----------------------------------------------------------------------------
-- 7. Report
----------------------------------------------------------------------------

local report = {}

function report.start_section(negotiation)
  if not negotiation.start then
    return { "Not read: " .. tostring(negotiation.error or "the broker did not answer the protocol header") }
  end
  local properties, capabilities = negotiation.server_properties or {}, negotiation.capabilities or {}
  return {
    string.format("Protocol: AMQP %s (connection.start, no credential required)", tostring(negotiation.version)),
    string.format("Product: %s %s", tostring(properties.product), tostring(properties.version)),
    string.format("Platform: %s", tostring(properties.platform)),
    string.format("Cluster name: %s", tostring(properties.cluster_name or "not disclosed")),
    string.format("Locales: %s", fmt_list(negotiation.locales, 6)),
    string.format("Capabilities: %s", fmt_list(sorted_keys(capabilities), 12)),
  }
end

function report.capability_section(capabilities)
  local lines = { string.format("Advertised: %s", plural(capabilities.count, "capability")),
    string.format("Not advertised: %s", plural(#capabilities.missing, "capability")) }
  for _, entry in ipairs(capabilities.notes) do
    lines[#lines + 1] = string.format("%-32s %-7s %s", entry.name, entry.impact, entry.text)
  end
  for _, entry in ipairs(capabilities.missing) do
    lines[#lines + 1] = string.format("%-32s %-7s NOT ADVERTISED: %s", entry.name, entry.impact, entry.text)
  end
  if #capabilities.unknown > 0 then
    lines[#lines + 1] = "Capabilities this script cannot describe: " .. fmt_list(capabilities.unknown, 8)
  end
  return lines
end

function report.mechanism_section(mechanisms)
  local lines = { string.format("Offered: %s", fmt_list(mechanisms.names, 8)) }
  for _, row in ipairs(mechanisms.rows) do
    lines[#lines + 1] = string.format("%-18s %-18s %s", row.name, row.class, row.note)
  end
  if mechanisms.count == 0 then lines[#lines + 1] = "The start frame carried no mechanism list." end
  return lines
end

function report.authentication_section(authentication)
  local lines = { string.format("Attempted: %s", authentication.attempted and "yes" or "no"),
    string.format("Verdict: %s", tostring(authentication.state)),
    string.format("Reason: %s", tostring(authentication.reason)) }
  if authentication.attempted then
    lines[#lines + 1] = string.format("Account tested: %s", tostring(authentication.user))
  end
  if authentication.code then
    lines[#lines + 1] = string.format("Broker reply: %s %s", tostring(authentication.code),
      tostring(authentication.code_name))
  end
  if authentication.text then lines[#lines + 1] = "Broker text: " .. tostring(authentication.text) end
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
      local is_table = type(step) == "table"
      lines[#lines + 1] = "   fix: " .. (is_table and step.step or tostring(step))
      if is_table and step.why then lines[#lines + 1] = "        why: " .. step.why end
    end
  end
  return lines
end

function report.build(cfg, host, port, negotiation, capabilities, mechanisms, authentication, amqp10,
  transport, verdict, list)
  local out = stdnse.output_table()
  out["Target"] = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id %s, timeout %dms, vhost %s", cfg.client_id, cfg.timeout, cfg.vhost),
    string.format("Requested mechanism: %s", cfg.mechanism),
    string.format("Composite verdict: %s - %s", tostring(verdict.state), tostring(verdict.reason)),
    string.format("Transport: %s", (negotiation.protocol_reply or {}).family == "TLS"
        and "tls-listener (the AMQP header was answered with a TLS record)"
      or (transport and transport.available)
        and string.format("%s (%s)", tostring(transport.verdict), tostring(transport.summary or "no detail"))
      or "the TLS probe is unavailable, so the transport was not classified"),
  }
  out["AMQP connection.start"] = report.start_section(negotiation)
  out["Server capabilities"] = report.capability_section(capabilities)
  out["SASL mechanisms"] = report.mechanism_section(mechanisms)
  out["Authentication"] = report.authentication_section(authentication)
  out["AMQP 1.0 on this port"] = {
    string.format("1.0 header answered: %s, verdict %s", amqp10.answered and "yes" or "no",
      tostring(amqp10.verdict)),
    string.format("Protocol reply: %s", amqp10.reply_version or (amqp10.reply and amqp10.reply.family) or "none"),
    string.format("First reply: %s", tostring(amqp10.first_reply or amqp10.error or "nothing")),
  }
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
    for _, group in ipairs({ { "", negotiation.stages }, { "amqp10/", amqp10.stages } }) do
      for _, stage in ipairs(group[2]) do
        transcript[#transcript + 1] = string.format("%s%s: %s", group[1], stage.name,
          tostring(stage.detail or ""))
      end
    end
    out["Probe transcript"] = transcript
  end
  return out
end

----------------------------------------------------------------------------
-- 8. Orchestration
----------------------------------------------------------------------------

action = function(host, port)
  if not ok_rmq or type(rabbitmq) ~= "table" then
    return { ["Risk Level"] = "UNKNOWN",
      ["Target"] = { "nselib/rabbitmq.lua is not installed, so the AMQP engine is unavailable." } }
  end
  local cfg = read_config()
  local transport, negotiation = probe.transport(host, port, cfg), probe.negotiate(host, port, cfg)
  local capabilities = analysis.capabilities(negotiation.capabilities)
  local mechanisms = analysis.mechanisms(negotiation.mechanisms)
  local authentication, amqp10 = analysis.authentication(negotiation, cfg), probe.amqp10(host, port, cfg)
  local verdict = analysis.verdict(negotiation, transport, mechanisms, capabilities)
  local list = findings.evaluate(cfg, negotiation, capabilities, mechanisms, authentication, amqp10, transport,
    verdict)
  local result = report.build(cfg, host, port, negotiation, capabilities, mechanisms, authentication, amqp10,
    transport, verdict, list)
  publish_findings(host, port, list)
  return result
end
