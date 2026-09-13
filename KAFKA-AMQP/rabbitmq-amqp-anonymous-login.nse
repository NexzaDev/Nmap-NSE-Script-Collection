local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The engine speaks the protocol; the TLS probe decides whether the port is a
-- listener that can answer a plaintext handshake at all.
local ok_rmq, rabbitmq = pcall(require, "rabbitmq")
local ok_tls, tlsprobe = pcall(require, "tlsprobe")
local has_vulns, vulns_lib = pcall(require, "vulns")

local SCRIPT_NAME = "rabbitmq-amqp-anonymous-login"
local SCRIPT_RISK = "CRITICAL"
local SCRIPT_VERSION = "1.0.0"

description = [[
Confirms whether a RabbitMQ AMQP listener accepts a session with no credential.

The audit runs a small matrix of unauthenticated logins and reads what the broker
does with each one. ANONYMOUS is the mechanism RabbitMQ's anonymous plugin adds,
and its response may be empty: the broker then logs the connection in as the
account named by anonymous_login_user with the tag in anonymous_login_tag. The
matrix also covers the shapes that reach a misconfigured broker without that
plugin: an empty PLAIN or AMQPLAIN response, the guest account with an empty
password, and EXTERNAL, which takes the identity from the transport (a client
certificate, or whatever a terminator in front of the listener claims).

An accepted attempt is not reported on the strength of the tune frame alone. The
script opens the vhost, opens a channel, asks the broker for a queue it knows
does not exist with a passive declare, and reads the reply code: 404 means the
session is authorized to read that vhost (the broker searched and found nothing),
while 403 means it connected but is not allowed to read. The winning attempt is
then repeated on a fresh connection, so the report quotes two independent
sessions rather than one, and every step of every attempt is kept for the
transcript.

Nothing here changes broker state: the script declares nothing, publishes
nothing, consumes nothing and never closes another client's channel. A passive
declare of a name that does not exist creates nothing and deletes nothing.
]]

---
-- @usage
-- nmap -p 5672 --script rabbitmq-amqp-anonymous-login <target>
-- nmap -p 5672 --script rabbitmq-amqp-anonymous-login --script-args rabbitmq.vhost=prod <target>
--
-- @args rabbitmq.timeout     Per-request timeout in milliseconds (default 5000).
-- @args rabbitmq.client-id   Client identity reported in the connection properties.
-- @args rabbitmq.vhost       Vhost to open for the anonymous session (default "/").
-- @args rabbitmq.vhosts      Comma separated extra vhosts to try after the first,
--                            to show how far an anonymous session reaches.
-- @args rabbitmq.identity    Identity string sent by the ANONYMOUS and EXTERNAL
--                            attempts (default "nmap-nse").
-- @args rabbitmq.confirm     How many independent sessions to establish to
--                            confirm an accepted mechanism (default 2, at most 3).
-- @args rabbitmq.shapes      "false" skips the malformed-response matrix, which
--                            is the only part of the audit that sends a response
--                            no real client would send.
-- @args rabbitmq.burst       How many sessions to request in one burst when a
--                            login was accepted, to see whether the broker
--                            throttles the unauthenticated path (default 3, 0 disables).
-- @args rabbitmq.channels    How many channels to open on a confirmed session
--                            (default 3, 0 disables).
-- @args rabbitmq.verbose     "true" adds the per-stage probe transcript.

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

portrule = shortport.port_or_service({5672, 5671, 25672}, {"amqp", "amqps"}, "tcp")

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

local function split_list(raw, max_items)
  local out = {}
  for item in string.gmatch(tostring(raw or ""), "[^,]+") do
    item = string.gsub(item, "^%s+", "")
    item = string.gsub(item, "%s+$", "")
    if #item > 0 and #out < (max_items or 8) then out[#out + 1] = item end
  end
  return out
end

local function read_config()
  local vhosts = { arg_string("rabbitmq.vhost", "/", 128) }
  for _, vhost in ipairs(split_list(arg_string("rabbitmq.vhosts", "", 512), 6)) do
    local seen = false
    for _, existing in ipairs(vhosts) do if existing == vhost then seen = true end end
    if not seen then vhosts[#vhosts + 1] = vhost end
  end
  return {
    timeout = arg_number("rabbitmq.timeout", 5000, 500, 60000),
    client_id = arg_string("rabbitmq.client-id", "nmap-anonymous-audit", 120),
    vhost = vhosts[1],
    vhosts = vhosts,
    identity = arg_string("rabbitmq.identity", "nmap-nse", 128),
    confirm = arg_number("rabbitmq.confirm", 2, 1, 3),
    shapes = arg_bool("rabbitmq.shapes", true),
    burst = arg_number("rabbitmq.burst", 3, 0, 6),
    channels = arg_number("rabbitmq.channels", 3, 0, 6),
    verbose = arg_bool("rabbitmq.verbose", false),
    sentinel = string.format("nse-probe-%d-%d", nmap.timing_level and nmap.timing_level() or 0,
      math.random(100000, 999999)),
  }
end

----------------------------------------------------------------------------
-- 2. Formatting helpers
----------------------------------------------------------------------------

local function plural(count, singular, plural_form)
  count = tonumber(count) or 0
  return string.format("%d %s", count, count == 1 and singular or (plural_form or (singular .. "s")))
end

local function yes_no(value)
  return value and "yes" or "no"
end

local function fmt_list(values, limit, empty_text)
  if not values or #values == 0 then return empty_text or "none" end
  limit = limit or 6
  local out = {}
  for index = 1, math.min(#values, limit) do out[#out + 1] = tostring(values[index]) end
  if #values > limit then out[#out + 1] = string.format("(+%d more)", #values - limit) end
  return table.concat(out, ", ")
end

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

-- The two shapes of the NSE vulns API are folded into one publisher, so a
-- confirmation reaches the database whichever Nmap release is running.
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

-- Only a confirmed, unauthenticated session is published as a vulnerability:
-- an informational finding about a broker that refused everything is not.
local function publish_findings(host, port, list)
  local publish = vuln_publisher(host, port)
  if not publish then return end
  local publishable = { CRITICAL = true, HIGH = true }
  for _, item in ipairs(list) do
    if publishable[item.severity] then publish(item.id, item.title, item.detail) end
  end
end

----------------------------------------------------------------------------
-- 3. Knowledge tables
----------------------------------------------------------------------------

local KB = {}

-- The login matrix. Each entry is a different way a broker can end up accepting
-- a session with no usable credential, and each one carries the configuration
-- mistake it reveals. The order matters only for reading the report: the
-- anonymous plugin first, then the empty-credential shapes, then the identity
-- taken from the transport.
KB.ATTEMPTS = {
  {
    id = "anonymous-empty",
    mechanism = "ANONYMOUS",
    user = "",
    password = "",
    label = "ANONYMOUS with an empty response",
    reveals = "the rabbitmq_auth_mechanism_anonymous plugin is enabled and logs the session in as "
      .. "anonymous_login_user with anonymous_login_tag",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "anonymous-named",
    mechanism = "ANONYMOUS",
    user = "%IDENTITY%",
    password = "",
    label = "ANONYMOUS asking to be logged in as a named identity",
    reveals = "the anonymous plugin accepts a client supplied username, so the session carries whatever "
      .. "identity the client asked for",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "plain-empty",
    mechanism = "PLAIN",
    user = "",
    password = "",
    label = "PLAIN with an empty account and password",
    reveals = "an empty login reaches an internal account, or a backend maps an empty user onto a default "
      .. "one",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "amqplain-empty",
    mechanism = "AMQPLAIN",
    user = "",
    password = "",
    label = "AMQPLAIN with an empty field table",
    reveals = "the same empty identity through the older mechanism, which some backends treat differently",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "guest-empty",
    mechanism = "PLAIN",
    user = "guest",
    password = "",
    label = "guest with an empty password",
    reveals = "the built-in account was left with a blank password, which is how a hand-edited user "
      .. "database often ends up",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "external-empty",
    mechanism = "EXTERNAL",
    user = "",
    password = "",
    label = "EXTERNAL with an empty authorization identity",
    reveals = "the listener trusts the transport for the identity, and the transport identified nobody",
    severity_if_accepted = "HIGH",
  },
  {
    id = "external-named",
    mechanism = "EXTERNAL",
    user = "%IDENTITY%",
    password = "%IDENTITY%",
    label = "EXTERNAL with a client chosen authorization identity",
    reveals = "the listener trusts a transport identity that a client can set: a TLS terminator that does "
      .. "not verify certificates, or a plugin that reads an unauthenticated header",
    severity_if_accepted = "HIGH",
  },
}

-- What an accepted session is allowed to do, and what each answer proves. A
-- passive declare of a name that does not exist is the cheapest read the AMQP
-- protocol offers: it creates nothing, deletes nothing, and the reply code says
-- whether the vhost's permissions were consulted and satisfied.
KB.DECLARE_CODES = {
  [404] = { verdict = "authorized", severity = "HIGH",
    means = "the broker searched the vhost and reported the queue missing, so the session reached the "
      .. "vhost's queue index: its read and configure permissions were consulted and satisfied" },
  [403] = { verdict = "not-authorized", severity = "INFO",
    means = "the broker refused the request: the session connected but is not allowed to declare on this "
      .. "vhost, so an anonymous connection is possible and not immediately useful" },
  [530] = { verdict = "vhost-refused", severity = "INFO",
    means = "the vhost itself is closed to this session" },
}

-- The RabbitMQ configuration keys that decide all of this, and the value that is
-- safe for each. The report quotes them so an operator can check the running
-- configuration against a known-good one.
KB.CONFIG_KEYS = {
  { key = "auth_mechanisms", safe = ".plain, .amqplain (no .anonymous)",
    why = "the mechanism list the listener accepts; every entry is a way in" },
  { key = "anonymous_login_user", safe = "not set",
    why = "the account an anonymous connection is logged in as; when the anonymous plugin is enabled this "
      .. "account decides what the session may do" },
  { key = "anonymous_login_tag", safe = "not set",
    why = "the tag granted to that account: monitoring or administrator turns an anonymous connection into "
      .. "a management foothold" },
  { key = "loopback_users", safe = "guest is only reachable from loopback (the default)",
    why = "listing a user here restricts it to local connections; removing guest from it exposes the "
      .. "built-in account to the network" },
  { key = "ssl_cert_login_from", safe = "distinguished_name, with peer verification on",
    why = "which certificate field EXTERNAL maps to a user; common_name without verification lets a client "
      .. "choose its identity" },
  { key = "ssl_verify", safe = "verify_peer",
    why = "a TLS listener with verify_none accepts any certificate, so an EXTERNAL identity is a claim "
      .. "rather than a proof" },
  { key = "auth_backends", safe = "an explicit list with internal last",
    why = "an authentication backend that accepts a missing password (LDAP with anonymous bind, for "
      .. "example) is how an empty PLAIN response becomes a session" },
}

-- What each mechanism is on the wire, and what a broker that completes it is
-- really saying. The table is what turns "accepted" into an explanation.
KB.MECHANISM_CLASSES = {
  ANONYMOUS = {
    wire = "a single long string, usually empty: the identity the client asks for",
    completes_when = "the anonymous plugin is loaded, and it hands the session to anonymous_login_user",
    class = "unauthenticated",
    note = "the mechanism exists to create an unauthenticated path on purpose; it is the only one whose "
      .. "name states that no proof was given",
  },
  PLAIN = {
    wire = "\\0user\\0password as one long string",
    completes_when = "the account exists and the password matches, or an authentication backend accepts the "
      .. "pair it was given",
    class = "password",
    note = "empty strings are a legal PLAIN response, so a backend that treats an empty password as an "
      .. "anonymous bind completes it without a credential",
  },
  AMQPLAIN = {
    wire = "a field table with LOGIN and PASSWORD keys",
    completes_when = "the same account check as PLAIN, through the older encoding",
    class = "password",
    note = "the encoding differs, the credential does not; backends that special-case it are worth testing "
      .. "separately because the parser is separate code",
  },
  EXTERNAL = {
    wire = "a long string holding the authorization identity, usually empty",
    completes_when = "the listener is satisfied with whatever the transport proved: a client certificate "
      .. "over TLS, or a header a terminator inserted",
    class = "transport",
    note = "the mechanism is exactly as strong as the transport's verification, which is why an accepted "
      .. "EXTERNAL is reported together with the TLS configuration",
  },
  ["RABBIT-CR-DEMO"] = {
    wire = "a username, answered by the broker with a challenge the client must respond to",
    completes_when = "the client completes the challenge; this audit does not implement it and reports the "
      .. "mechanism as untested rather than as absent",
    class = "challenge",
    note = "the mechanism ships as a demonstration of the pluggable mechanism API, not as an "
      .. "authentication method",
  },
}

-- The AMQP reply codes an audit of this kind actually sees, with the meaning the
-- report quotes. The distinction between 403 and 404 is the whole permission
-- question: one says the request was refused, the other says it was allowed.
KB.REPLY_CODES = {
  [200] = { name = "REPLY_SUCCESS", class = "success", means = "the request was accepted" },
  [311] = { name = "CONTENT_TOO_LARGE", class = "error", means = "the frame exceeded the negotiated size" },
  [312] = { name = "NO_ROUTE", class = "error", means = "a published message had nowhere to go" },
  [320] = { name = "CONNECTION_FORCED", class = "connection", means = "the broker closed the connection" },
  [403] = { name = "ACCESS_REFUSED", class = "authorization",
    means = "the request was understood and refused: the credential or the permission was not accepted" },
  [404] = { name = "NOT_FOUND", class = "resource",
    means = "the request was allowed and the resource does not exist: the permission check passed" },
  [406] = { name = "PRECONDITION_FAILED", class = "resource",
    means = "the request contradicted an existing object's properties" },
  [501] = { name = "FRAME_ERROR", class = "protocol", means = "the frame could not be parsed" },
  [502] = { name = "SYNTAX_ERROR", class = "protocol", means = "the method arguments were malformed" },
  [503] = { name = "COMMAND_INVALID", class = "protocol", means = "the method is not valid in this state" },
  [504] = { name = "CHANNEL_ERROR", class = "protocol", means = "the channel could not be used" },
  [505] = { name = "UNEXPECTED_FRAME", class = "protocol", means = "a frame arrived out of sequence" },
  [506] = { name = "RESOURCE_ERROR", class = "resource", means = "the broker ran out of a resource" },
  [530] = { name = "NOT_ALLOWED", class = "authorization",
    means = "the connection or the vhost was refused: usually the credential, sometimes the vhost" },
  [541] = { name = "INTERNAL_ERROR", class = "server", means = "the broker failed while serving the request" },
}

-- The shapes of SASL response the probe sends to see what the broker does with a
-- response that does not fit the mechanism. Each one is a login attempt, so they
-- are sent against the mechanisms the broker already offered and nothing more.
KB.SHAPES = {
  {
    id = "malformed-plain",
    mechanism = "PLAIN",
    raw = "no-separators-at-all",
    label = "PLAIN response with no separators",
    expects = "the mechanism parser refuses it, because a PLAIN response has exactly two NUL separators",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "short-plain",
    mechanism = "PLAIN",
    raw = "\0user-only",
    label = "PLAIN response with one separator",
    expects = "the parser refuses it as malformed rather than reading it as an empty password",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "empty-amqplain",
    mechanism = "AMQPLAIN",
    raw = "\0",
    label = "AMQPLAIN response that is not a field table",
    expects = "the table parser refuses it instead of reading an empty table as an empty login",
    severity_if_accepted = "CRITICAL",
  },
  {
    id = "overlong-plain",
    mechanism = "PLAIN",
    raw = "\\0" .. string.rep("a", 900) .. "\\0" .. string.rep("b", 900),
    label = "PLAIN response far larger than any real credential",
    expects = "the broker bounds the response it will parse; an unbounded parser is a denial of service "
      .. "surface",
    severity_if_accepted = "HIGH",
  },
}

-- The accounts an unauthenticated session can land in, in the order the inference
-- tries them. The audit cannot read the login name back from AMQP, so the report
-- names the account whose configuration would explain the behaviour it saw.
KB.ACCOUNT_SHAPES = {
  {
    id = "anonymous-plugin",
    account = "anonymous_login_user (configured)",
    tag = "anonymous_login_tag",
    explains = "ANONYMOUS completed",
    next_step = "read anonymous_login_user and anonymous_login_tag, then list_permissions for that account",
  },
  {
    id = "guest-blank",
    account = "guest",
    tag = "whatever tag guest carries",
    explains = "PLAIN completed with an empty or blank password",
    next_step = "rabbitmqctl list_users, and check whether guest was given a remote or a blank credential",
  },
  {
    id = "internal-empty",
    account = "an internal account an empty login maps onto",
    tag = "that account's tag",
    explains = "PLAIN or AMQPLAIN completed with an empty response from a non-guest account name",
    next_step = "check the authentication backends for a path that accepts an empty password",
  },
  {
    id = "transport-identity",
    account = "the user the transport's identity maps onto",
    tag = "that user's tag",
    explains = "EXTERNAL completed",
    next_step = "check ssl_cert_login_from and ssl_verify, and what terminates TLS in front of the broker",
  },
}

-- What to do with a confirmed anonymous session, in order, with the command that
-- shows each fact.
KB.TRIAGE = {
  { step = "Find the session in the broker's view: rabbitmqctl list_connections user protocol peer_host",
    why = "the audit's connections are still in the log even after they closed, and the user column names "
      .. "the account the anonymous session landed in" },
  { step = "Read the account's permissions: rabbitmqctl list_permissions -p <vhost>",
    why = "the declare answer already proved read access on one vhost; this shows the whole permission set" },
  { step = "Check the mechanism configuration: rabbitmqctl environment | grep auth_mechanisms",
    why = "the list is what the listener offers, and it is the setting the fix changes" },
  { step = "Review the authentication backend chain: rabbitmqctl environment | grep auth_backends",
    why = "an internal-empty or backend-driven acceptance is a backend bug, not a listener setting" },
  { step = "Look for the account in the log: journalctl -u rabbitmq-server | grep -i anonymous",
    why = "the broker logs the login it performed, which turns the inference into a fact" },
}

KB.REMEDIATION = {
  { step = "Remove rabbitmq_auth_mechanism_anonymous from enabled_plugins, or delete anonymous_login_user "
      .. "and anonymous_login_tag so the plugin has no account to hand out.",
    why = "The plugin is the mechanism: without it ANONYMOUS is refused, and without those keys the plugin "
      .. "refuses an empty response instead of picking a default." },
  { step = "Set auth_mechanisms to the two you use (.plain, .amqplain) or remove it and use the defaults, "
      .. "and require TLS on 5671.",
    why = "A mechanism list is an attack surface; every mechanism not needed is one that cannot be abused. "
      .. "PLAIN over TLS is the ordinary deployment." },
  { step = "Keep guest out of the network: leave loopback_users at its default and give every real client "
      .. "its own account.",
    why = "The empty-password and guest shapes only work when the built-in account was made remote or "
      .. "given a blank password." },
  { step = "For EXTERNAL, set ssl_verify to verify_peer and ssl_cert_login_from to distinguished_name, and "
      .. "verify the certificate chain at whatever terminates TLS.",
    why = "EXTERNAL is only as strong as the identity the transport proves; a terminator that forwards an "
      .. "unverified header makes the mechanism a client-supplied login." },
  { step = "Audit the authentication backends for a path that accepts an empty password, and test it from a "
      .. "host that is not the broker.",
    why = "An internal backend that treats an empty password as an anonymous bind is the failure mode this "
      .. "script's PLAIN and AMQPLAIN attempts are aimed at." },
  { step = "Give the anonymous account (if it must exist) read access to one queue and nothing else, and "
      .. "never a management tag.",
    why = "If anonymous access is a deliberate design, bounding it is what keeps a network-reachable "
      .. "listener from being a full broker compromise." },
}

KB.VERIFICATION = {
  "rabbitmqctl environment | grep -E 'auth_mechanisms|anonymous_login|loopback_users|ssl_cert_login_from'",
  "rabbitmqctl status  (enabled plugins under Applications, and the listeners)",
  "rabbitmqctl list_users  (look for the user named by anonymous_login_user)",
  "rabbitmqctl list_permissions  (what the anonymous or guest account may do per vhost)",
  "rabbitmq-diagnostics listeners  (which listeners exist, and which have TLS options)",
  "rabbitmqctl eval 'rabbit_auth_mechanism_anonymous:description().'  (is the plugin even loaded)",
  "journalctl -u rabbitmq-server | grep -i 'anonymous\\|access_refused'  (sessions the broker already logged)",
}

KB.METHOD_LIMITS = {
  "Every attempt is a real login, so each one appears in the broker's log and in the failed-authentication "
    .. "counters on the management API, exactly as any other login would.",
  "The script declares nothing, publishes nothing, consumes nothing and does not touch another client's "
    .. "channel; the only request beyond the handshake is a passive declare of a queue name generated for "
    .. "this run.",
  "An accepted session is reported only after the vhost opened and the channel was confirmed; the tune "
    .. "frame alone is not treated as a login, because a broker that answers tune before checking the "
    .. "credential would otherwise look permissive.",
  "The declaration codes prove what the anonymous session may do on one vhost with one request; they say "
    .. "nothing about every queue in the vhost, and a 403 does not mean the session has no other permission.",
  "The EXTERNAL attempts can only succeed when the listener is behind TLS with a client certificate "
    .. "configured; without a certificate the broker normally closes the connection, which is reported as a "
    .. "refusal rather than as a finding.",
  "The empty PLAIN and AMQPLAIN attempts are aimed at internal backends. A deployment whose users are all "
    .. "internal accounts with real passwords refuses them, and that refusal is reported as the healthy "
    .. "result it is.",
}

KB.RISK_RUBRIC = {
  { severity = "CRITICAL", condition = "a session opened with no credential and a passive declare proved "
      .. "the vhost's permissions were satisfied" },
  { severity = "HIGH", condition = "a session opened with no credential but the vhost refused the read, or "
      .. "an EXTERNAL identity was accepted from a transport that proved nothing" },
  { severity = "MEDIUM", condition = "an unauthenticated session is possible but the account it lands in "
      .. "is denied everywhere this audit looked" },
  { severity = "INFO", condition = "every attempt was refused, or the port does not speak AMQP" },
}

KB.EVIDENCE_RULES = {
  "A finding is quoted with the mechanism that produced the session, the account the broker reported, and "
    .. "the exact reply code of the question that followed it.",
  "Two independent sessions are required before an accepted mechanism is graded CRITICAL, so a single "
    .. "transient answer cannot produce a false confirmation.",
  "The broker's own words from the refusal frame are quoted in full, because 'user guest can only connect "
    .. "via localhost' and 'password does not match' are different facts about the same account.",
  "A conclusion drawn from a truncated or timed-out exchange is not reported as a refusal: the attempt is "
    .. "marked inconclusive and the audit says so.",
}

----------------------------------------------------------------------------
-- 4. Probes
----------------------------------------------------------------------------

local probe = {}

-- The pre-authentication handshake, read once per port: what the broker says
-- before anyone tries to log in decides how the attempt matrix is read (which
-- mechanisms even exist) and gives the report its context.
function probe.handshake(host, port, cfg)
  local attempt = rabbitmq.handshake(host.ip or host.name, port.number, {
    timeout_ms = cfg.timeout, client_id = cfg.client_id, vhost = cfg.vhost,
  })
  return {
    attempt = attempt,
    ok = attempt.ok,
    status = attempt.status,
    error = attempt.error,
    start = attempt.start,
    version = attempt.version,
    product = (attempt.server_properties or {}).product,
    platform = (attempt.server_properties or {}).platform,
    cluster_name = (attempt.server_properties or {}).cluster_name,
    capabilities = attempt.capabilities or {},
    mechanisms = attempt.mechanisms or {},
    locales = attempt.locales or {},
    protocol_reply = attempt.protocol_reply,
    stages = attempt.stages or {},
    first_reply = attempt.first_reply,
  }
end

-- The channel liveness question: basic.qos is answered on the channel itself and
-- touches no queue, so it proves a live channel without touching a resource.
local function channel_liveness(conn, channel)
  local ok, err = conn:write_method(60, 10, channel, rabbitmq.u32(10) .. string.char(0))
  if not ok then return { ok = false, error = err } end
  local reply, read_err = conn:await(function(packet)
    if packet.kind ~= rabbitmq.FRAME_METHOD or packet.channel ~= channel then return false end
    return packet.class_id == 60
  end, 4)
  if not reply then return { ok = false, error = read_err or "no reply" } end
  return { ok = reply.method_id == 11, method = reply.method, error = reply.method_id ~= 11
    and (reply.method or "not qos-ok") or nil }
end

-- Ask the broker for a queue name that was generated for this run. A passive
-- declare never creates anything: the broker searches, finds nothing, and the
-- reply code says whether the search was allowed.
local function sentinel_probe(conn, channel, cfg)
  local out = rabbitmq.probe_queue(conn, channel, cfg.vhost, cfg.sentinel)
  out.sentinel = cfg.sentinel
  out.code_class = KB.DECLARE_CODES[tonumber(out.reply_code)]
  if out.exists then
    -- A queue with the generated name already exists, which means something else
    -- answered the request: worth reporting, because the probe must never be
    -- mistaken for a successful create.
    out.unexpected = true
  end
  return out
end

-- One unauthenticated login attempt, start to finish. Every step is recorded so
-- the report can quote the point at which the broker stopped cooperating, and
-- the session is closed politely at the end.
function probe.attempt(host, port, cfg, entry)
  local user = string.gsub(tostring(entry.user or ""), "%%IDENTITY%%", cfg.identity)
  local password = string.gsub(tostring(entry.password or ""), "%%IDENTITY%%", cfg.identity)
  local out = {
    id = entry.id, label = entry.label, mechanism = entry.mechanism, user = user,
    identity_bytes = #user, password_bytes = #password, started = os.time(),
    reveals = entry.reveals, severity_if_accepted = entry.severity_if_accepted,
  }
  local started = os.clock()
  local attempt = rabbitmq.handshake(host.ip or host.name, port.number, {
    timeout_ms = cfg.timeout, client_id = cfg.client_id, vhost = cfg.vhost,
    mechanism = entry.mechanism, user = user, password = password,
    send_empty_credentials = true, heartbeat = 0,
  })
  out.seconds = os.clock() - started
  out.attempt = attempt
  out.stages = attempt.stages or {}
  out.status = attempt.status
  out.error = attempt.error
  out.mechanism_offered = attempt.mechanism_offered
  out.tune = attempt.tune
  out.accepted = attempt.authenticated and true or false
  out.vhost_open = attempt.vhost_open and true or false
  out.server_product = (attempt.server_properties or {}).product
  out.close = attempt.close

  if not attempt.authenticated then
    out.outcome = attempt.status == "no-tune" and "inconclusive"
      or (attempt.status == "mechanism-not-offered" and "mechanism-not-offered")
      or (attempt.status == "start-only" and "not-attempted")
      or (attempt.close and "refused")
      or (attempt.error and "inconclusive")
      or "refused"
    return out
  end

  out.outcome = "accepted"
  local conn, channel = attempt.connection, attempt.channel or 1
  out.tune_summary = attempt.tune and string.format("channel-max %s, frame-max %s, heartbeat %s",
    tostring(attempt.tune.channel_max), tostring(attempt.tune.frame_max), tostring(attempt.tune.heartbeat))
    or "the broker did not send a tune"
  out.channel = channel
  out.liveness = channel_liveness(conn, channel)
  out.sentinel = sentinel_probe(conn, channel, cfg)
  -- More channels on the same session: a broker that admits the connection and
  -- then allows only one channel is bounding the session; one that allows the
  -- rest is not.
  if cfg.channels and cfg.channels > 1 then
    out.extra_channels = { opened = 1, attempted = cfg.channels }
    for extra = channel + 1, cfg.channels do
      local ok_open = conn:write_method(20, 10, extra, rabbitmq.short_string(""))
      if ok_open then
        local reply = conn:await(function(packet)
          if packet.kind ~= rabbitmq.FRAME_METHOD or packet.channel ~= extra then return false end
          return packet.class_id == 20 or packet.class_id == 10
        end, 3)
        if reply and reply.method_id == 11 then out.extra_channels.opened = out.extra_channels.opened + 1 end
      end
    end
  end
  out.declare = out.sentinel
  -- A polite close: the broker is told the client is leaving rather than being
  -- left to expire the connection.
  local ok_close, close_err = conn:write_method(10, 50, 0,
    rabbitmq.u16(200) .. rabbitmq.short_string("OK") .. rabbitmq.u16(0) .. rabbitmq.u16(0))
  out.closed_politely = ok_close and true or false
  out.close_error = close_err
  conn:close()
  out.bytes_out = conn.stats and conn.stats.bytes_out or nil
  out.bytes_in = conn.stats and conn.stats.bytes_in or nil
  out.frames_in = conn.stats and conn.stats.frames_in or nil
  out.frames_out = conn.stats and conn.stats.frames_out or nil
  return out
end

-- The confirmation: the winning attempt is repeated on fresh connections, so a
-- confirmation rests on two independent sessions rather than on one answer that
-- could have come from something in front of the broker.
function probe.confirm(host, port, cfg, entry)
  local out = { sessions = {}, accepted = 0, attempts = 0 }
  for _ = 1, cfg.confirm do
    out.attempts = out.attempts + 1
    local session = probe.attempt(host, port, cfg, entry)
    out.sessions[#out.sessions + 1] = session
    if session.outcome == "accepted" then out.accepted = out.accepted + 1 end
  end
  out.reproducible = out.accepted >= 2
  out.stable = out.accepted == out.attempts
  return out
end

-- How far an unauthenticated session reaches: each configured vhost is opened
-- with the same identity and asked the same sentinel question.
function probe.vhost_reach(host, port, cfg, entry)
  local out = { vhosts = {}, reachable = 0 }
  for _, vhost in ipairs(cfg.vhosts) do
    local attempt = rabbitmq.handshake(host.ip or host.name, port.number, {
      timeout_ms = cfg.timeout, client_id = cfg.client_id, vhost = vhost,
      mechanism = entry.mechanism, user = string.gsub(tostring(entry.user or ""), "%%IDENTITY%%", cfg.identity),
      password = string.gsub(tostring(entry.password or ""), "%%IDENTITY%%", cfg.identity),
      send_empty_credentials = true, heartbeat = 0,
    })
    local row = { vhost = vhost, opened = attempt.vhost_open and true or false,
      status = attempt.status, close = attempt.close }
    if attempt.authenticated and attempt.connection then
      row.sentinel = rabbitmq.probe_queue(attempt.connection, attempt.channel or 1, vhost, cfg.sentinel)
      row.sentinel.code_class = KB.DECLARE_CODES[tonumber(row.sentinel.reply_code)]
      row.authorized = row.sentinel.missing and true or false
      attempt.connection:close()
    end
    if row.authorized then out.reachable = out.reachable + 1 end
    out.vhosts[#out.vhosts + 1] = row
  end
  return out
end

-- The transport, because an anonymous session over plaintext is a different
-- finding from an anonymous session over TLS.
function probe.transport(host, port, cfg)
  if not ok_tls or type(tlsprobe) ~= "table" then
    return { available = false, note = "nselib/tlsprobe.lua is not installed" }
  end
  local reply = tlsprobe.probe(host.ip or host.name, port.number, { timeout_ms = cfg.timeout })
  reply.available = true
  reply.tls = reply.kind == "tls-server-hello" or reply.kind == "tls-record"
  reply.verdict = KB.TRANSPORT_VERDICTS[reply.kind] or "unknown"
  return reply
end

KB.TRANSPORT_VERDICTS = {
  ["tls-server-hello"] = "tls-listener",
  ["tls-record"] = "tls-listener",
  ["tls-alert"] = "tls-listener-refusing-the-hello",
  ["silent"] = "no-answer",
  ["not-tls"] = "plaintext-protocol",
}

-- The response-shape matrix: what the broker does with a SASL response that does
-- not fit the mechanism it claims. A parser that accepts one is how a malformed
-- probe becomes a session, and the finding is graded as such.
function probe.shapes(host, port, cfg, handshake)
  local out = { rows = {}, accepted = 0, refused = 0, not_offered = 0, inconclusive = 0 }
  for _, shape in ipairs(KB.SHAPES) do
    local offered = false
    for _, mechanism in ipairs(handshake.mechanisms or {}) do
      if mechanism == shape.mechanism then offered = true end
    end
    local row = { id = shape.id, label = shape.label, mechanism = shape.mechanism, raw = shape.raw,
      expects = shape.expects, offered = offered, severity_if_accepted = shape.severity_if_accepted,
      raw_bytes = #shape.raw }
    if not offered then
      row.outcome = "mechanism-not-offered"
      out.not_offered = out.not_offered + 1
    else
      local ok_probe, attempt = pcall(rabbitmq.handshake, host.ip or host.name, port.number, {
        timeout_ms = cfg.timeout, client_id = cfg.client_id, vhost = cfg.vhost,
        mechanism = shape.mechanism, raw_response = shape.raw, heartbeat = 0,
        user = "", password = "", send_empty_credentials = true,
      })
      if not ok_probe then
        -- A shape that cannot be sent at all is reported as its own outcome
        -- rather than stopping the matrix.
        row.outcome = "probe-error"
        row.error = tostring(attempt)
        out.rows[#out.rows + 1] = row
        out.inconclusive = out.inconclusive + 1
      else
      row.attempt = attempt
      row.status = attempt.status
      row.close = attempt.close
      if attempt.authenticated then
        row.outcome = "accepted"
        row.tune_summary = attempt.tune and string.format("channel-max %s, frame-max %s, heartbeat %s",
          tostring(attempt.tune.channel_max), tostring(attempt.tune.frame_max),
          tostring(attempt.tune.heartbeat)) or "no tune"
        out.accepted = out.accepted + 1
        if attempt.connection then attempt.connection:close() end
      elseif attempt.close then
        row.outcome = "refused"
        row.code, row.code_name, row.text = attempt.close.reply_code, attempt.close.reply_name,
          attempt.close.reply_text
        out.refused = out.refused + 1
      else
        row.outcome = "inconclusive"
        row.error = attempt.error
        out.inconclusive = out.inconclusive + 1
      end
      out.rows[#out.rows + 1] = row
      end
    end
  end
  out.count = #out.rows
  return out
end

-- A second channel on a confirmed session: a broker that admits an anonymous
-- connection on one channel and then allows more channels is not rate limiting
-- or bounding what the session can do.
function probe.channel_reach(host, port, cfg, entry)
  local attempt = rabbitmq.handshake(host.ip or host.name, port.number, {
    timeout_ms = cfg.timeout, client_id = cfg.client_id, vhost = cfg.vhost,
    mechanism = entry.mechanism,
    user = string.gsub(tostring(entry.user or ""), "%%IDENTITY%%", cfg.identity),
    password = string.gsub(tostring(entry.password or ""), "%%IDENTITY%%", cfg.identity),
    send_empty_credentials = true, heartbeat = 0,
  })
  local out = { opened = attempt.authenticated and true or false, channels = {} }
  if not out.opened then
    out.status = attempt.status
    return out
  end
  local conn = attempt.connection
  for channel = 1, 3 do
    local ok, err = conn:write_method(20, 10, channel, rabbitmq.short_string(""))
    if not ok then
      out.channels[#out.channels + 1] = { channel = channel, opened = false, error = err }
    else
      local reply, read_err = conn:await(function(packet)
        if packet.kind ~= rabbitmq.FRAME_METHOD or packet.channel ~= channel then return false end
        return packet.class_id == 20 or packet.class_id == 10
      end, 4)
      out.channels[#out.channels + 1] = { channel = channel, opened = reply ~= nil,
        method = reply and reply.method or nil, error = read_err }
    end
  end
  out.count = 0
  for _, row in ipairs(out.channels) do if row.opened then out.count = out.count + 1 end end
  conn:close()
  return out
end

-- How fast the broker hands out sessions: the same login repeated in a burst. A
-- listener that accepts every attempt in a second has no throttle on the
-- unauthenticated path, which matters for how loudly the mistake can be abused.
function probe.burst(host, port, cfg, entry, attempts)
  local out = { attempts = attempts, accepted = 0, sessions = {} }
  local started = os.clock()
  for index = 1, attempts do
    local session = probe.attempt(host, port, cfg, entry)
    out.sessions[#out.sessions + 1] = { index = index, outcome = session.outcome,
      declare_code = session.sentinel and session.sentinel.reply_code }
    if session.outcome == "accepted" then out.accepted = out.accepted + 1 end
  end
  out.seconds = os.clock() - started
  out.rate = out.seconds > 0 and (out.accepted / out.seconds) or out.accepted
  out.throttled = out.accepted < attempts
  return out
end

----------------------------------------------------------------------------
-- 5. Analysis
----------------------------------------------------------------------------

local analysis = {}
-- Which offered mechanisms the matrix did not test, and why that matters: an
-- untested mechanism is an unknown, not a clean bill of health.
function analysis.mechanism_gap(handshake, results)
  local tested, gaps = {}, {}
  for _, result in ipairs(results) do tested[result.mechanism] = true end
  for _, shape in ipairs(KB.SHAPES) do tested[shape.mechanism] = true end
  for _, mechanism in ipairs(handshake.mechanisms or {}) do
    if not tested[mechanism] then
      local class = KB.MECHANISM_CLASSES[mechanism] or {}
      gaps[#gaps + 1] = { mechanism = mechanism, class = class.class or "opaque",
        reason = class.class == "challenge"
            and "the mechanism needs a challenge response this audit does not implement"
          or "no response encoder is implemented for this mechanism" }
    end
  end
  return { tested = tested, gaps = gaps, count = #gaps }
end

-- The account the session landed in, inferred from what was sent and what the
-- broker did with it. AMQP does not report the login name back, so the report
-- says which configuration would explain the observed behaviour and how to
-- confirm it from the broker's own state.
function analysis.account_hypothesis(winner, shapes)
  if not winner then return { hypothesis = "none", text = "no session was established" } end
  local mechanism, user = winner.result.mechanism, winner.result.user
  local shape = shapes and shapes.accepted > 0
  if mechanism == "ANONYMOUS" then
    return { hypothesis = "anonymous-plugin", text = string.format("ANONYMOUS completed, so the session is "
      .. "the account named by anonymous_login_user with the tag in anonymous_login_tag%s",
      shape and " (and the shape matrix shows the same backend accepting responses it should refuse)" or "") }
  end
  if mechanism == "EXTERNAL" then
    return { hypothesis = "transport-identity", text = "EXTERNAL completed, so the session carries whatever "
      .. "identity the transport proved; check ssl_cert_login_from and whether the certificate was verified" }
  end
  if #user == 0 then
    return { hypothesis = "internal-empty", text = "an empty PLAIN or AMQPLAIN response was accepted, so an "
      .. "account with an empty password exists or a backend mapped the empty identity onto one" }
  end
  if user == "guest" then
    return { hypothesis = "guest-blank", text = "guest authenticated from a remote address with an empty "
      .. "password, so the loopback restriction was lifted and the password was left blank" }
  end
  return { hypothesis = "internal-empty", text = string.format("the account %s authenticated without a "
    .. "password", tostring(user)) }
end

-- The per-attempt timeline, which is also how the report shows that the audit
-- actually ran rather than describing a hypothetical: durations come from
-- os.clock() around each exchange.
function analysis.timeline(results)
  local out = { rows = {}, total_seconds = 0 }
  for _, result in ipairs(results) do
    local seconds = tonumber(result.seconds) or 0
    out.rows[#out.rows + 1] = { id = result.id, outcome = result.outcome, seconds = seconds }
    out.total_seconds = out.total_seconds + seconds
  end
  return out
end


-- What one attempt produced, in the words the report uses.
function analysis.classify(result)
  local out = { id = result.id, label = result.label, severity = "INFO" }
  if result.outcome == "accepted" then
    local declare = result.sentinel or {}
    if declare.missing then
      out.state = "accepted-authorized"
      out.severity = result.severity_if_accepted or "CRITICAL"
      out.means = string.format("the broker opened vhost %s and then answered the sentinel request with "
        .. "404, so the session's permissions on that vhost were satisfied",
        result.vhost or "(the configured vhost)")
    elseif declare.refused then
      out.state = "accepted-denied"
      out.severity = "MEDIUM"
      out.means = "the broker opened a session but refused the sentinel request, so the anonymous account "
        .. "exists and is denied the read this audit performed"
    elseif declare.reply_code == 530 then
      out.state = "accepted-vhost-refused"
      out.severity = "MEDIUM"
      out.means = "the session opened but the vhost itself is closed to it"
    else
      out.state = "accepted-unmeasured"
      out.severity = result.severity_if_accepted or "HIGH"
      out.means = "the session opened, and the sentinel request was not answered, so what it may do was "
        .. "not measured"
    end
    return out
  end
  if result.outcome == "mechanism-not-offered" then
    out.state = "mechanism-not-offered"
    out.means = string.format("%s is not in the broker's mechanism list", tostring(result.mechanism))
    return out
  end
  if result.outcome == "inconclusive" then
    out.state = "inconclusive"
    out.means = "the exchange did not complete: the broker stopped answering, so this attempt proves "
      .. "neither acceptance nor refusal"
    return out
  end
  out.state = "refused"
  out.code = result.close and result.close.reply_code
  out.code_name = result.close and result.close.reply_name
  out.text = result.close and result.close.reply_text
  out.means = result.close and string.format("the broker refused the attempt with %s %s",
    tostring(out.code), tostring(out.code_name)) or "the broker refused the attempt"
  return out
end

function analysis.matrix(results)
  local out = { rows = {}, accepted = 0, refused = 0, unmeasured = 0, not_offered = 0, inconclusive = 0 }
  for _, result in ipairs(results) do
    local row = analysis.classify(result)
    row.mechanism = result.mechanism
    row.user = result.user
    row.accepted = result.outcome == "accepted"
    row.declare_code = result.sentinel and result.sentinel.reply_code
    row.tune = result.tune_summary
    out.rows[#out.rows + 1] = row
    if row.state == "accepted-authorized" or row.state == "accepted-denied"
      or row.state == "accepted-vhost-refused" or row.state == "accepted-unmeasured" then
      out.accepted = out.accepted + 1
    elseif row.state == "mechanism-not-offered" then
      out.not_offered = out.not_offered + 1
    elseif row.state == "inconclusive" then
      out.inconclusive = out.inconclusive + 1
    else
      out.refused = out.refused + 1
    end
  end
  out.count = #out.rows
  out.authorized = 0
  for _, row in ipairs(out.rows) do
    if row.state == "accepted-authorized" then out.authorized = out.authorized + 1 end
  end
  return out
end

-- The winning attempt, if any: the one the confirmation step repeats and the one
-- the report leads with.
function analysis.winner(results)
  local best, best_rank = nil, -1
  local rank = { ["accepted-authorized"] = 5, ["accepted-unmeasured"] = 4, ["accepted-denied"] = 3,
    ["accepted-vhost-refused"] = 2 }
  for _, result in ipairs(results) do
    local row = analysis.classify(result)
    if (rank[row.state] or -1) > best_rank then best, best_rank = { result = result, row = row }, rank[row.state] end
  end
  if best_rank < 0 then return nil end
  best.row.mechanism = best.result.mechanism
  best.row.user = best.result.user
  return best
end

-- How exposed the listener is, in one sentence the operator can act on.
function analysis.exposure(matrix, winner, transport)
  if not winner then
    if matrix.inconclusive > 0 and matrix.accepted == 0 then
      return { level = "UNKNOWN", text = "no attempt completed, so the listener's exposure was not measured" }
    end
    return { level = "NONE", text = string.format("%s were refused, so no unauthenticated session was "
      .. "possible on this listener", plural(matrix.refused, "attempt")) }
  end
  local session = winner.result
  local declared = winner.row.state == "accepted-authorized"
  local tls = transport and transport.tls
  local parts = {}
  parts[#parts + 1] = string.format("a session opened without a credential via %s", tostring(session.mechanism))
  if session.user and #session.user > 0 then
    parts[#parts + 1] = string.format("asking to be %s", tostring(session.user))
  end
  parts[#parts + 1] = declared and "and the vhost's permissions were satisfied"
    or "but the vhost refused the read this audit performed"
  parts[#parts + 1] = tls and "over TLS" or "over an unencrypted transport"
  -- The grade comes from what the attempt that succeeded actually proves: an
  -- anonymous or empty-credential session is CRITICAL, an EXTERNAL identity is
  -- HIGH, a transport that is TLS caps the grade at HIGH, and a session that
  -- cannot read the vhost is MEDIUM.
  local level = winner.row.severity or "HIGH"
  if tls and level == "CRITICAL" then level = "HIGH" end
  if not declared and level == "CRITICAL" then level = "MEDIUM" end
  return { level = level, text = table.concat(parts, " ") }
end

----------------------------------------------------------------------------
-- 6. Findings
----------------------------------------------------------------------------

local findings = {}

function findings.evaluate(cfg, handshake, results, matrix, winner, confirmation, reach, transport, exposure,
  shapes, burst, coverage)
  local list = {}
  local function add(id, title, severity, detail, evidence, ...)
    list[#list + 1] = finding(id, title, severity, detail, evidence, { ... })
  end
  local tls = transport and transport.tls

  if not handshake.ok and not handshake.start then
    add("RABBITMQ-ANON-NOT-AMQP", "The port did not answer the AMQP protocol header", "INFO",
      string.format("The header was answered with %s, so there is no AMQP listener here to log in to. The "
        .. "other scripts in this category cover the management API and the TLS listener.",
        tostring(handshake.first_reply or handshake.error or "nothing")),
      { "status: " .. tostring(handshake.status) }, KB.REMEDIATION[2])
    return list
  end

  local mechanism_count = #(handshake.mechanisms or {})
  add("RABBITMQ-ANON-MECHANISMS", "The listener lists the SASL mechanisms it will accept", "INFO",
    string.format("The start frame offers %s: %s. Each one is an authentication path, and the audit tests "
      .. "the ones that can be completed without a usable credential.", plural(mechanism_count, "mechanism"),
      fmt_list(handshake.mechanisms, 8)),
    { "mechanisms: " .. fmt_list(handshake.mechanisms, 8) }, KB.REMEDIATION[2])

  if winner then
    local session, row = winner.result, winner.row
    local confirm_text = confirmation and confirmation.reproducible
      and string.format(" The session was confirmed on %d of %d independent connections.",
        confirmation.accepted, confirmation.attempts)
      or string.format(" The session was established once; the confirmation step saw %d of %d connections "
        .. "accepted, so the finding is quoted without that corroboration.",
        confirmation and confirmation.accepted or 0, confirmation and confirmation.attempts or 0)
    if row.state == "accepted-authorized" then
      add("RABBITMQ-ANON-LOGIN-ACCEPTED", "A credential-free login was accepted: an unauthenticated "
        .. "session reached a vhost and was allowed to read it", (tls and row.severity == "CRITICAL") and "HIGH" or (row.severity or "HIGH"),
        string.format("The broker accepted %s with %s response and then answered a passive declare in "
          .. "vhost %s with 404 NOT_FOUND: the search was performed, which means the session's permissions "
          .. "were consulted and satisfied. %s%s", row.label, row.mechanism, tostring(cfg.vhost),
          row.means, confirm_text),
        { string.format("mechanism: %s", tostring(row.mechanism)),
          string.format("identity asked for: %s", #session.user > 0 and session.user or "(none)"),
          string.format("vhost: %s (opened)", tostring(cfg.vhost)),
          string.format("tune: %s", tostring(session.tune_summary or "not read")),
          string.format("sentinel declare answer: %s %s", tostring(row.declare_code),
            tostring(row.sentinel and row.sentinel.reply_name or "no reply")),
          string.format("transport: %s", tls and "TLS" or "plaintext") },
        KB.REMEDIATION[1], KB.REMEDIATION[6])
    else
      add("RABBITMQ-ANON-LOGIN-ACCEPTED", "An unauthenticated session was accepted by the broker",
        "HIGH", string.format("The broker completed the handshake for %s and opened vhost %s, but the "
          .. "sentinel request was answered with %s, so the session could not read this vhost. The login "
          .. "itself is the defect: an account nobody authenticated is admitted to the broker.%s",
          row.label, tostring(cfg.vhost), tostring(row.declare_code), confirm_text),
        { string.format("mechanism: %s", tostring(row.mechanism)),
          string.format("declare answer: %s %s", tostring(row.declare_code), tostring(row.means)),
          string.format("tune: %s", tostring(session.tune_summary or "not read")) },
        KB.REMEDIATION[1])
    end

    if row.mechanism == "EXTERNAL" then
      add("RABBITMQ-ANON-EXTERNAL-TRUSTED", "An identity supplied by the transport was accepted",
        "HIGH", string.format("EXTERNAL completed for %s. The mechanism takes the identity from the "
          .. "transport: over TLS that is a client certificate, and what the listener verified is the whole "
          .. "question. A terminator in front of the broker that does not verify certificates makes this a "
          .. "client-chosen login.", row.label),
        { string.format("authorization identity sent: %s", row.user) }, KB.REMEDIATION[4])
    end
    if row.mechanism == "ANONYMOUS" then
      add("RABBITMQ-ANON-PLUGIN-ENABLED", "The anonymous authentication plugin answered the login",
        "HIGH", "ANONYMOUS is offered and completed, so rabbitmq_auth_mechanism_anonymous is loaded. The "
          .. "session is logged in as anonymous_login_user with anonymous_login_tag, which is a configuration "
          .. "that exists on purpose only when somebody built an unauthenticated path deliberately.",
        { "mechanism: ANONYMOUS" }, KB.REMEDIATION[1])
    end
    if #session.user == 0 and row.mechanism ~= "EXTERNAL" then
      add("RABBITMQ-ANON-EMPTY-CREDENTIAL", "An empty credential produced a session", "HIGH",
        string.format("The %s response carried no account and no password, and the broker accepted it. "
          .. "Either the account database contains an entry with an empty password, or an authentication "
          .. "backend treated the empty response as an anonymous bind.", tostring(row.mechanism)),
        { "response bytes: 0" }, KB.REMEDIATION[5])
    end
    if row.user == "guest" then
      add("RABBITMQ-ANON-GUEST-REMOTE", "The built-in guest account was usable with an empty password",
        "HIGH", "guest authenticated from a remote address with an empty password, which means the "
          .. "loopback_users default was changed and the account was left with a blank password.",
        { "account: guest" }, KB.REMEDIATION[3])
    end
  end

  -- Every accepted attempt is examined, not only the winner: a broker that admits
  -- an anonymous session and also accepts an empty guest password has both facts
  -- reported, and each fact is reported once.
  local reported = {}
  for _, item in ipairs(list) do reported[item.id] = true end
  for _, result in ipairs(results) do
    if result.outcome == "accepted" then
      local row = analysis.classify(result)
      if result.mechanism == "EXTERNAL" and not reported["RABBITMQ-ANON-EXTERNAL-TRUSTED"] then
        reported["RABBITMQ-ANON-EXTERNAL-TRUSTED"] = true
        add("RABBITMQ-ANON-EXTERNAL-TRUSTED", "An identity supplied by the transport was accepted", "HIGH",
          string.format("EXTERNAL completed for %s (%s). The mechanism takes the identity from the transport, "
            .. "so what the listener verified is the whole question: over TLS that is a certificate chain, and "
            .. "a terminator that does not verify one makes this a client-chosen login.",
            tostring(result.user), tostring(result.label)),
          { string.format("%s: authorization identity %s", tostring(result.id),
              #tostring(result.user) > 0 and tostring(result.user) or "(empty)") },
          KB.REMEDIATION[4])
      end
      if result.mechanism == "ANONYMOUS" and not reported["RABBITMQ-ANON-PLUGIN-ENABLED"] then
        reported["RABBITMQ-ANON-PLUGIN-ENABLED"] = true
        add("RABBITMQ-ANON-PLUGIN-ENABLED", "The anonymous authentication plugin answered the login", "HIGH",
          string.format("ANONYMOUS completed for %s, so rabbitmq_auth_mechanism_anonymous is loaded and the "
            .. "session is logged in as anonymous_login_user with anonymous_login_tag. That configuration "
            .. "exists on purpose only when somebody built an unauthenticated path deliberately.",
            tostring(result.label)), { string.format("%s: ANONYMOUS accepted", tostring(result.id)) },
          KB.REMEDIATION[1])
      end
      -- "Empty credential" means the field the mechanism checks was empty when
      -- the broker accepted it: the password for PLAIN and AMQPLAIN, the whole
      -- response for ANONYMOUS. EXTERNAL has no secret to be empty.
      local password_bytes = tonumber(result.password_bytes) or 0
      local response_bytes = tonumber(result.response_bytes) or 0
      local empty_credential = false
      if result.mechanism == "ANONYMOUS" then
        empty_credential = response_bytes == 0
      elseif result.mechanism == "PLAIN" or result.mechanism == "AMQPLAIN" then
        empty_credential = password_bytes == 0
      end
      if empty_credential and not reported["RABBITMQ-ANON-EMPTY-CREDENTIAL"] then
        reported["RABBITMQ-ANON-EMPTY-CREDENTIAL"] = true
        add("RABBITMQ-ANON-EMPTY-CREDENTIAL", "An empty credential produced a session", "HIGH",
          string.format("The %s response the broker accepted carried %d password byte(s) for account %s "
            .. "(%d response bytes in total): either an account with an empty password exists, or an "
            .. "authentication backend treated the empty response as an anonymous bind.",
            tostring(result.mechanism), password_bytes,
            #tostring(result.user) > 0 and tostring(result.user) or "(none)", response_bytes),
          { string.format("%s: password bytes %d, response bytes %d", tostring(result.id), password_bytes,
              response_bytes) }, KB.REMEDIATION[5])
      end
      if result.user == "guest" and not reported["RABBITMQ-ANON-GUEST-REMOTE"] then
        reported["RABBITMQ-ANON-GUEST-REMOTE"] = true
        add("RABBITMQ-ANON-GUEST-REMOTE", "The built-in guest account was usable with an empty password",
          "HIGH", string.format("guest authenticated from a remote address with an empty password (%s), so "
            .. "the loopback_users default was changed and the account left with a blank password.",
            tostring(result.label)), { string.format("%s: guest accepted with %d password bytes",
              tostring(result.id), tonumber(result.password_bytes) or 0) }, KB.REMEDIATION[3])
      end
      if row.state == "accepted-authorized" and not reported["RABBITMQ-ANON-READ-AUTHORIZED"] then
        reported["RABBITMQ-ANON-READ-AUTHORIZED"] = true
        add("RABBITMQ-ANON-READ-AUTHORIZED", "An unauthenticated session may read the vhost it opened",
          "HIGH", string.format("The session opened by %s was allowed to ask about queues in vhost %s: the "
            .. "passive declare was answered with 404, which means the permission check passed and the lookup "
            .. "ran.", tostring(result.label), tostring(cfg.vhost)),
          { string.format("%s: declare %s %s", tostring(result.id), tostring(result.sentinel and
              result.sentinel.reply_code), tostring(row.means)) }, KB.REMEDIATION[6])
      end
    end
  end

  if matrix.accepted > 1 then
    add("RABBITMQ-ANON-MULTIPLE-MECHANISMS", "More than one credential-free login was accepted", "HIGH",
      string.format("%d of the %d attempts were accepted, so the exposure is not one mechanism that could "
        .. "be turned off in isolation: the listener admits sessions through several paths at once.",
        matrix.accepted, matrix.count),
      { string.format("accepted: %d, refused: %d, not offered: %d", matrix.accepted, matrix.refused,
          matrix.not_offered) }, KB.REMEDIATION[1], KB.REMEDIATION[2])
  end

  if reach and reach.reachable > 0 then
    add("RABBITMQ-ANON-VHOST-REACH", "The unauthenticated session reached more than one vhost", "MEDIUM",
      string.format("Of the %d vhosts tried, %d answered the sentinel request with 404, so the anonymous "
        .. "account has read permission on each of them.", #reach.vhosts, reach.reachable),
      (function()
        local rows = {}
        for _, row in ipairs(reach.vhosts) do
          rows[#rows + 1] = string.format("%s: %s", tostring(row.vhost),
            row.authorized and "authorized" or (row.opened and "opened, refused" or "not opened"))
        end
        return rows
      end)(), KB.REMEDIATION[6])
  end

  if winner and not tls then
    add("RABBITMQ-ANON-PLAINTEXT", "The unauthenticated session runs over an unencrypted listener", "HIGH",
      "The accepted login travelled in the clear on this port, so any client on the path can open the same "
        .. "session, and any traffic the session carries can be read or altered.",
      { string.format("transport: %s", tostring(transport and transport.verdict or "not classified")) },
      KB.REMEDIATION[2])
  end

  if not winner then
    if matrix.inconclusive > 0 then
      add("RABBITMQ-ANON-AUDIT-INCONCLUSIVE", "Part of the login matrix did not complete", "INFO",
        string.format("%d of %d attempts produced no answer at all, so the audit cannot exclude an accepted "
          .. "login on this listener; the transcript shows where each exchange stopped.",
          matrix.inconclusive, matrix.count),
        { "attempts that timed out: " .. tostring(matrix.inconclusive) }, KB.REMEDIATION[2])
    else
      add("RABBITMQ-ANON-REFUSED", "Every credential-free login was refused", "INFO",
        string.format("All %d attempts were refused with a named reason, and %d mechanisms were not offered "
          .. "at all. That is the expected result for a listener that requires credentials.",
          matrix.refused, matrix.not_offered),
        { string.format("refused: %d, not offered: %d", matrix.refused, matrix.not_offered) },
        KB.REMEDIATION[3])
    end
  end

  if shapes and shapes.accepted > 0 then
    local accepted = {}
    for _, row in ipairs(shapes.rows) do
      if row.outcome == "accepted" then
        accepted[#accepted + 1] = string.format("%s (%s, %d bytes): %s", row.id, tostring(row.mechanism),
          row.raw_bytes, row.tune_summary or "tuned")
      end
    end
    add("RABBITMQ-ANON-MALFORMED-RESPONSE-ACCEPTED", "A SASL response that is malformed for its mechanism "
      .. "was accepted", "CRITICAL",
      string.format("%d of the %d response shapes were accepted, each of them a login attempt with a "
        .. "response no correct client sends. The parser that should have refused the response handed the "
        .. "session to the backend instead, which is how a protocol-level mistake becomes a broker login.",
        shapes.accepted, shapes.count), accepted, KB.REMEDIATION[5], KB.REMEDIATION[1])
  elseif shapes and shapes.count > 0 and shapes.accepted == 0 then
    add("RABBITMQ-ANON-SHAPES-REFUSED", "The malformed SASL responses were refused", "INFO",
      string.format("All %d shapes were refused at the parser%s, so the broker validates what it parses "
        .. "before it consults a backend.", shapes.refused,
        shapes.not_offered > 0 and string.format(" (%d were not sent: the mechanism is not offered)",
          shapes.not_offered) or ""),
      (function()
        local rows = {}
        for _, row in ipairs(shapes.rows) do
          rows[#rows + 1] = string.format("%s: %s%s", row.id, row.outcome,
            row.code and (" (" .. tostring(row.code) .. " " .. tostring(row.code_name) .. ")") or "")
        end
        return rows
      end)(), KB.REMEDIATION[5])
  end

  if winner and winner.result.extra_channels then
    local extra = winner.result.extra_channels
    if extra.opened > 1 then
      add("RABBITMQ-ANON-MULTI-CHANNEL", "The unauthenticated session opened several channels", "MEDIUM",
        string.format("%d of %d channels opened on the one unauthenticated session, so the broker is not "
          .. "limiting the anonymous connection to a single stream of work.", extra.opened, extra.attempted),
        { string.format("channels: %d of %d", extra.opened, extra.attempted) }, KB.REMEDIATION[6])
    end
  end

  if burst and burst.attempts > 0 then
    if burst.accepted == burst.attempts then
      add("RABBITMQ-ANON-NO-THROTTLE", "Every unauthenticated session in the burst was accepted", "MEDIUM",
        string.format("%d of %d sessions were established in %.2f seconds (%.1f sessions per second), so "
          .. "the broker does not slow the unauthenticated path down: whatever the session may do, it can be "
          .. "done repeatedly.", burst.accepted, burst.attempts, burst.seconds, burst.rate),
        { string.format("burst: %d of %d accepted in %.2fs", burst.accepted, burst.attempts, burst.seconds) },
        KB.REMEDIATION[1])
    else
      add("RABBITMQ-ANON-BURST-PARTIAL", "The burst of unauthenticated sessions was partly refused", "INFO",
        string.format("%d of %d sessions were established, so the broker accepted the first connection and "
          .. "then stopped: an acceptance is still an acceptance, but there is a bound on how quickly it "
          .. "repeats.", burst.accepted, burst.attempts),
        { string.format("burst: %d of %d accepted", burst.accepted, burst.attempts) }, KB.REMEDIATION[1])
    end
  end

  if coverage and coverage.count > 0 then
    local lines = {}
    for _, gap in ipairs(coverage.gaps) do
      lines[#lines + 1] = string.format("%s: %s", gap.mechanism, gap.reason)
    end
    add("RABBITMQ-ANON-MECHANISM-GAP", "Some offered mechanisms were not tested", "INFO",
      string.format("The broker offers %s that this audit did not exercise, so their acceptance is unknown "
        .. "rather than disproved.", plural(coverage.count, "mechanism")), lines, KB.REMEDIATION[2])
  end

  if winner and winner.result.sentinel and winner.result.sentinel.exists then
    add("RABBITMQ-ANON-SENTINEL-EXISTS", "The sentinel queue name already existed on the broker", "LOW",
      string.format("The passive declare for %s was answered with a declare-ok, which means a queue with "
        .. "that name existed before the audit. The name is generated per run, so this points at a naming "
        .. "collision rather than at anything the audit created.", tostring(cfg.sentinel)),
      { string.format("name: %s", tostring(cfg.sentinel)) }, KB.REMEDIATION[3])
  end

  if handshake.product and not string.find(string.lower(tostring(handshake.product)), "rabbitmq") then
    add("RABBITMQ-ANON-BROKER-NOT-RABBITMQ", "The AMQP broker is not RabbitMQ", "INFO",
      string.format("connection.start names %s, so the engine is auditing a different AMQP 0-9-1 "
        .. "implementation. The login matrix is still meaningful; the RabbitMQ-specific configuration keys "
        .. "in the remediation are not.", tostring(handshake.product)),
      { "product: " .. tostring(handshake.product) }, KB.REMEDIATION[2])
  end

  return list
end

----------------------------------------------------------------------------
-- 7. Report
----------------------------------------------------------------------------

local report = {}

function report.handshake_section(handshake)
  if not handshake.start then
    return { "Not read: " .. tostring(handshake.error or "the broker did not answer the protocol header") }
  end
  return {
    string.format("AMQP %s, %s", tostring(handshake.version), tostring(handshake.product)),
    string.format("Platform: %s, cluster: %s", tostring(handshake.platform),
      tostring(handshake.cluster_name or "not disclosed")),
    string.format("Mechanisms offered: %s", fmt_list(handshake.mechanisms, 8)),
    string.format("Locales: %s", fmt_list(handshake.locales, 4)),
    string.format("Capabilities: %s", fmt_list(sorted_keys(handshake.capabilities), 10)),
  }
end

function report.matrix_section(matrix, results)
  local lines = { string.format("Attempts: %d (accepted %d, authorized %d, refused %d, not offered %d, "
    .. "inconclusive %d)", matrix.count, matrix.accepted, matrix.authorized, matrix.refused,
    matrix.not_offered, matrix.inconclusive) }
  for index, row in ipairs(matrix.rows) do
    local result = results[index] or {}
    lines[#lines + 1] = string.format("%-16s %-10s %-22s %-8s %s", row.id, tostring(row.mechanism),
      row.state, tostring(row.declare_code or "-"),
      result.outcome == "accepted" and "" or tostring(row.text or row.means or ""))
  end
  return lines
end

function report.session_section(winner, confirmation)
  if not winner then return { "No session was established without a credential." } end
  local session = winner.result
  local lines = {
    string.format("Mechanism: %s (%s)", tostring(session.mechanism), tostring(session.label)),
    string.format("Identity asked for: %s", #session.user > 0 and session.user or "(none)"),
    string.format("Vhost opened: %s", tostring(session.vhost_open and "yes" or "no")),
    string.format("Tune: %s", tostring(session.tune_summary or "not read")),
    string.format("Channel liveness (basic.qos): %s", yes_no(session.liveness and session.liveness.ok)),
    string.format("Session closed politely: %s", yes_no(session.closed_politely)),
  }
  if confirmation then
    lines[#lines + 1] = string.format("Confirmation: %d of %d independent connections accepted",
      confirmation.accepted, confirmation.attempts)
    lines[#lines + 1] = string.format("Reproducible: %s", yes_no(confirmation.reproducible))
  end
  return lines
end

function report.declare_section(winner)
  if not winner or not winner.result.sentinel then
    return { "No session reached a vhost, so no permission question was asked." }
  end
  local sentinel = winner.result.sentinel
  local code_class = sentinel.code_class or {}
  return {
    string.format("Sentinel queue: %s (generated for this run, declared passively)", tostring(sentinel.sentinel)),
    string.format("Reply: %s %s", tostring(sentinel.reply_code), tostring(sentinel.reply_name or "")),
    string.format("Meaning: %s", tostring(code_class.means or sentinel.error or "not answered")),
    string.format("Queue created: %s", yes_no(sentinel.exists)),
  }
end

function report.reach_section(reach)
  if not reach then return { "Not measured." } end
  local lines = { string.format("Vhosts tried: %d, authorized by the anonymous session: %d",
    #reach.vhosts, reach.reachable) }
  for _, row in ipairs(reach.vhosts) do
    lines[#lines + 1] = string.format("%-16s %s", tostring(row.vhost), row.authorized and "authorized"
      or (row.opened and "opened but refused" or "not opened"))
  end
  return lines
end

function report.shape_section(shapes)
  if not shapes or shapes.count == 0 then return { "Not run (rabbitmq.shapes=false)." } end
  local lines = { string.format("Shapes sent: %d (accepted %d, refused %d, not offered %d, inconclusive %d)",
    shapes.count, shapes.accepted, shapes.refused, shapes.not_offered, shapes.inconclusive) }
  for _, row in ipairs(shapes.rows) do
    lines[#lines + 1] = string.format("%-18s %-10s %-10s %s", row.id, tostring(row.mechanism),
      tostring(row.outcome), row.outcome == "refused"
        and string.format("%s %s", tostring(row.code), tostring(row.code_name))
        or tostring(row.error or row.status or ""))
  end
  return lines
end

function report.coverage_section(coverage)
  if not coverage then return { "Not measured." } end
  local lines = { string.format("Mechanisms with no encoder in this audit: %d", coverage.count) }
  for _, gap in ipairs(coverage.gaps) do
    lines[#lines + 1] = string.format("%-18s %-12s %s", gap.mechanism, gap.class, gap.reason)
  end
  return lines
end

function report.session_extra_section(winner, burst)
  local lines = {}
  if winner and winner.result.extra_channels then
    local extra = winner.result.extra_channels
    lines[#lines + 1] = string.format("Channels opened on the session: %d of %d attempted", extra.opened,
      extra.attempted)
  else
    lines[#lines + 1] = "Channels beyond the first: not attempted"
  end
  if burst and burst.attempts > 0 then
    lines[#lines + 1] = string.format("Burst: %d of %d sessions in %.2fs (%.1f per second)%s", burst.accepted,
      burst.attempts, burst.seconds, burst.rate, burst.throttled and ", so the broker did bound it" or "")
  else
    lines[#lines + 1] = "Burst: not attempted"
  end
  return lines
end

function report.hypothesis_section(hypothesis)
  return { string.format("Account inferred: %s", tostring(hypothesis.hypothesis)), hypothesis.text }
end

function report.timeline_section(timeline)
  local lines = { string.format("Total exchange time: %.2f seconds", timeline.total_seconds) }
  for _, row in ipairs(timeline.rows) do
    lines[#lines + 1] = string.format("%-18s %-20s %.2fs", tostring(row.id), tostring(row.outcome),
      tonumber(row.seconds) or 0)
  end
  return lines
end

function report.triage_section()
  local lines = {}
  for index, entry in ipairs(KB.TRIAGE) do
    lines[#lines + 1] = string.format("%d. %s", index, entry.step)
    lines[#lines + 1] = "   why: " .. entry.why
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
      local is_table = type(step) == "table"
      lines[#lines + 1] = "   fix: " .. (is_table and step.step or tostring(step))
      if is_table and step.why then lines[#lines + 1] = "        why: " .. step.why end
    end
  end
  return lines
end

function report.build(cfg, host, port, handshake, results, matrix, winner, confirmation, reach, transport,
  exposure, list, shapes, burst, coverage, hypothesis, timeline)
  local out = stdnse.output_table()
  out["Target"] = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id %s, timeout %dms, vhost %s", cfg.client_id, cfg.timeout, cfg.vhost),
    string.format("Attempts in the matrix: %d, confirmation sessions per accepted mechanism: %d",
      #results, cfg.confirm),
    string.format("Exposure: %s - %s", tostring(exposure.level), tostring(exposure.text)),
    string.format("Transport: %s", transport and transport.available
        and string.format("%s (%s)", tostring(transport.verdict), tostring(transport.summary or "no detail"))
      or "the TLS probe is unavailable, so the transport was not classified"),
  }
  out["Pre-authentication handshake"] = report.handshake_section(handshake)
  out["Login attempt matrix"] = report.matrix_section(matrix, results)
  out["Confirmed session"] = report.session_section(winner, confirmation)
  out["Authorization evidence"] = report.declare_section(winner)
  out["Vhost reach"] = report.reach_section(reach)
  out["Session reach"] = report.session_extra_section(winner, burst)
  out["Response-shape matrix"] = report.shape_section(shapes)
  out["Mechanism coverage"] = report.coverage_section(coverage)
  out["Account hypothesis"] = report.hypothesis_section(hypothesis)
  out["Attempt timeline"] = report.timeline_section(timeline)
  out["Triage checklist"] = report.triage_section()
  out["Findings"] = report.finding_section(list)
  out["Verification"] = KB.VERIFICATION
  out["Method limits and rubric"] = KB.METHOD_LIMITS
  for _, rule in ipairs(KB.EVIDENCE_RULES) do out["Method limits and rubric"][#out["Method limits and rubric"] + 1] =
    "Evidence rule: " .. rule end
  for _, entry in ipairs(KB.RISK_RUBRIC) do
    out["Method limits and rubric"][#out["Method limits and rubric"] + 1] =
      "Rubric - " .. entry.severity .. ": " .. entry.condition
  end
  out["Finding summary"] = severity_summary(list)
  out["Risk Level"] = worst(list, "NONE")
  if cfg.verbose then
    local transcript = {}
    for _, result in ipairs(results) do
      transcript[#transcript + 1] = string.format("=== attempt %s (%s)", tostring(result.id),
        tostring(result.mechanism))
      for _, stage in ipairs(result.stages or {}) do
        transcript[#transcript + 1] = string.format("  %s: %s", stage.name, tostring(stage.detail or ""))
      end
      if result.tune_summary then transcript[#transcript + 1] = "  tune: " .. result.tune_summary end
      if result.sentinel then
        transcript[#transcript + 1] = string.format("  sentinel: %s %s", tostring(result.sentinel.reply_code),
          tostring(result.sentinel.reply_name or ""))
      end
    end
    for _, row in ipairs((shapes and shapes.rows) or {}) do
      transcript[#transcript + 1] = string.format("=== shape %s (%s, %d bytes) -> %s", tostring(row.id),
        tostring(row.mechanism), row.raw_bytes, tostring(row.outcome))
      for _, stage in ipairs((row.attempt and row.attempt.stages) or {}) do
        transcript[#transcript + 1] = string.format("  %s: %s", stage.name, tostring(stage.detail or ""))
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
  local handshake = probe.handshake(host, port, cfg)
  local transport = probe.transport(host, port, cfg)
  local results = {}
  for _, entry in ipairs(KB.ATTEMPTS) do results[#results + 1] = probe.attempt(host, port, cfg, entry) end
  local matrix = analysis.matrix(results)
  local winner = analysis.winner(results)
  local confirmation = nil
  if winner then
    for _, entry in ipairs(KB.ATTEMPTS) do
      if entry.id == winner.result.id then confirmation = probe.confirm(host, port, cfg, entry) end
    end
  end
  local winning_entry = nil
  if winner then
    for _, entry in ipairs(KB.ATTEMPTS) do
      if entry.id == winner.result.id then winning_entry = entry end
    end
  end
  local reach = winning_entry and probe.vhost_reach(host, port, cfg, winning_entry) or nil
  -- The malformed-response matrix runs whenever the handshake was read, whether
  -- or not a login was accepted: a broker that refuses every credential-free
  -- login but accepts a malformed response has its own problem.
  local shapes = (handshake.start and cfg.shapes) and probe.shapes(host, port, cfg, handshake) or nil
  local burst = (winning_entry and cfg.burst > 0) and probe.burst(host, port, cfg, winning_entry,
    math.min(cfg.burst, cfg.confirm + 3)) or nil
  local coverage = analysis.mechanism_gap(handshake, results)
  local hypothesis = analysis.account_hypothesis(winner, shapes)
  local timeline = analysis.timeline(results)
  local exposure = analysis.exposure(matrix, winner, transport)
  local list = findings.evaluate(cfg, handshake, results, matrix, winner, confirmation, reach, transport,
    exposure, shapes, burst, coverage)
  local result = report.build(cfg, host, port, handshake, results, matrix, winner, confirmation, reach,
    transport, exposure, list, shapes, burst, coverage, hypothesis, timeline)
  publish_findings(host, port, list)
  return result
end
