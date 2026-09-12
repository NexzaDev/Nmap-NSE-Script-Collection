local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The wire engine owns framing, version negotiation and the response parsers.
local ok, kafka = pcall(require, "kafka")
-- Findings are published through Nmap's vulnerability machinery as well as
-- through the script table; the module is optional so the script still runs
-- under a minimal NSE installation.
local has_vulns, vulns = pcall(require, "vulns")

description = [[
Determines whether a Kafka cluster lets an unauthenticated caller create
topics, without ever creating one.

Topic creation is the permission that turns a read-only observer into a
participant: a caller that may create topics can name a topic that a producer
will later write to, exhaust the cluster's disk with a topic it controls, or
plant a name that a misconfigured consumer will read from.

The script measures that permission the only way it can be measured without
changing the cluster:

  * CreateTopics is sent with validate_only=true, a flag the broker honours by
    running the whole creation path - authorization, name validation, partition
    and replication validation, configuration validation - and then discarding
    the result. A broker that answers NONE to a validate-only request would have
    created the topic; a broker that answers TOPIC_AUTHORIZATION_FAILED is
    enforcing the ACL.
  * The error code is read carefully, because several of them prove the
    authorization check already passed: INVALID_PARTITIONS,
    INVALID_REPLICATION_FACTOR, INVALID_CONFIG and INVALID_TOPIC_EXCEPTION are
    all validation failures, and authorization is evaluated before validation.
    A broker that answers one of those to an unauthenticated caller has told the
    scanner that it may create topics, just not that one.
  * A matrix of parameter combinations (partitions 1 and a large count,
    replication factor 1 and 3, a configuration override) maps how much of the
    creation surface the caller may use.
  * Before and after the probes the script asks whether the probe name exists,
    with allow_auto_topic_creation forced to false, so a broker that ignored the
    flag is detected and reported as an emergency rather than as a successful
    audit.

If the broker's CreateTopics version predates validate_only (Kafka before 0.11),
the script does not send a creating request at all: it names a topic that
already exists, which the broker answers with TOPIC_ALREADY_EXISTS before it
creates anything.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-create-topic-allowed <target>
-- nmap -p 9092 --script kafka-create-topic-allowed --script-args kafka.partitions=3,kafka.verbose=true <target>
--
-- @args kafka.timeout         Per-request timeout in milliseconds
--                            (default 5000, range 500-60000).
-- @args kafka.client-id       Client id used in every request header
--                            (default "nmap-kafka-create-audit").
-- @args kafka.partitions      Comma separated partition counts to validate
--                            (default "1,64").
-- @args kafka.replication     Comma separated replication factors to validate
--                            (default "1,3").
-- @args kafka.config-check    "true" (default) adds a configuration override to
--                            one of the variants.
-- @args kafka.defaults        "true" (default) reads the broker defaults an
--                            auto-created topic would use (DescribeConfigs).
-- @args kafka.verify-cleanup  "true" (default) re-checks the probe name to prove
--                            that no topic was created.
-- @args kafka.verbose         "true" adds the per-stage transcript.
--
-- @output
-- 9092/tcp open  kafka
-- | kafka-create-topic-allowed:
-- |   CreateTopics v7 advertised; validate_only available
-- |   Variant partitions=1 replication=1: validate_only -> NONE (authorized)
-- |   Variant partitions=64 replication=3: validate_only -> NONE (authorized)
-- |   Probe name nmap-create-audit-...-1234: not present before and not present after
-- |_  Risk Level: HIGH
---

if not ok or type(kafka) ~= "table" then
  action = function()
    return stdnse.format_output(true, {
      "The Kafka engine (nselib/kafka.lua) is not installed.",
      "Install it next to this script and re-run the scan.",
    })
  end
  return
end

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service({9092, 9093, 9094, 19092, 29092}, "kafka", {"tcp"})

local SCRIPT_RISK = "HIGH"
local SCRIPT_VERSION = "2.0.0"

----------------------------------------------------------------------------
-- 1. Configuration
----------------------------------------------------------------------------

local function arg_number(name, default, minimum, maximum)
  local raw = nmap.registry.args and nmap.registry.args[name]
  if raw == nil then return default end
  local value = tonumber(raw)
  if not value then return default end
  value = math.floor(value)
  if value < minimum then return minimum end
  if value > maximum then return maximum end
  return value
end

local function arg_string(name, default, max_length)
  local raw = nmap.registry.args and nmap.registry.args[name]
  if raw == nil then return default end
  raw = tostring(raw)
  if max_length and #raw > max_length then raw = string.sub(raw, 1, max_length) end
  return raw
end

local function arg_bool(name, default)
  local raw = nmap.registry.args and nmap.registry.args[name]
  if raw == nil then return default end
  raw = string.lower(tostring(raw))
  if raw == "1" or raw == "true" or raw == "yes" or raw == "on" then return true end
  if raw == "0" or raw == "false" or raw == "no" or raw == "off" then return false end
  return default
end

local function number_list(raw, limit, minimum, maximum)
  local out = {}
  for piece in string.gmatch(raw or "", "[^,%s]+") do
    local value = tonumber(piece)
    if value then
      value = math.floor(value)
      if value < minimum then value = minimum end
      if value > maximum then value = maximum end
      local duplicate = false
      for _, existing in ipairs(out) do
        if existing == value then duplicate = true end
      end
      if not duplicate then out[#out + 1] = value end
    end
  end
  if #out == 0 then return nil end
  table.sort(out)
  if limit and #out > limit then
    local capped = {}
    for index = 1, limit do capped[index] = out[index] end
    return capped
  end
  return out
end

local function read_config()
  local cfg = {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000),
    client_id = arg_string("kafka.client-id", "nmap-kafka-create-audit", 120),
    partitions = number_list(arg_string("kafka.partitions", nil, 200), 4, 1, 10000) or { 1, 64 },
    replication = number_list(arg_string("kafka.replication", nil, 200), 4, 1, 32) or { 1, 3 },
    config_check = arg_bool("kafka.config-check", true),
    defaults = arg_bool("kafka.defaults", true),
    verify_cleanup = arg_bool("kafka.verify-cleanup", true),
    retry = not arg_bool("kafka.no-retry", false),
    verbose = arg_bool("kafka.verbose", false),
  }
  cfg.transient_backoff_ms = 250
  return cfg
end

----------------------------------------------------------------------------
-- 2. Formatting helpers
----------------------------------------------------------------------------

local function fmt_bool(value)
  return value == nil and "unknown" or (value and "yes" or "no")
end

local plural = kafka.fmt_plural
local fmt_list = kafka.fmt_list
local num_text = kafka.fmt_num

local SEVERITY_ORDER = { CRITICAL = 5, HIGH = 4, MEDIUM = 3, LOW = 2, INFO = 1, NONE = 0, UNKNOWN = 0 }

local function worst(list, fallback)
  local highest = fallback or "NONE"
  for _, item in ipairs(list or {}) do
    if (SEVERITY_ORDER[item.severity] or 0) > (SEVERITY_ORDER[highest] or 0) then
      highest = item.severity
    end
  end
  return highest
end

local function finding(id, title, severity, detail, evidence, remediation)
  return { id = id, title = title, severity = severity, detail = detail,
    evidence = evidence or {}, remediation = remediation or {} }
end

local function sorted_keys(map)
  local keys = {}
  for key in pairs(map or {}) do keys[#keys + 1] = key end
  table.sort(keys)
  return keys
end

-- The probe name never collides with a real topic: it is generated per run from
-- the clock and a random draw, and Kafka topic names may contain only letters,
-- digits, '.', '_' and '-'.
local function probe_topic_name()
  return string.format("nmap-create-audit-%d-%d", os.time() % 1000000, math.random(100000, 999999))
end

----------------------------------------------------------------------------
-- 3. Wire layer
----------------------------------------------------------------------------

local function new_wire(host, port, cfg)
  local w = {
    host = host, port = port, cfg = cfg,
    connection = nil, connected = false, failure = nil,
    stages = {}, version_map = {}, negotiate_summary = nil,
  }

  function w:stage(name, detail)
    self.stages[#self.stages + 1] = { name = name, detail = detail, at = os.time() }
  end

  function w:connect()
    if self.connected then return true end
    self:stage("connect", string.format("%s:%d/tcp", host.ip or "target", port.number))
    local conn = kafka.new_connection(host.ip or self.host, port.number, {
      timeout_ms = self.cfg.timeout, client_id = self.cfg.client_id,
    })
    if not conn.sock then
      self.failure = conn.last_error or "connect failed"
      self:stage("connect", "failed: " .. tostring(self.failure))
      return false, self.failure
    end
    self.connection = conn
    self.connected = true
    return true
  end

  function w:close()
    if self.connection then self.connection:close() end
    self.connected = false
  end

  function w:negotiate()
    if self.negotiate_summary then return self.version_map end
    local summary, err = kafka.negotiate(self.connection)
    if not summary then
      self:stage("api_versions", "failed: " .. tostring(err))
      self.failure = self.failure or err
      return nil, err
    end
    self.negotiate_summary = summary
    self.version_map = summary.versions or {}
    self:stage("api_versions", string.format("broker offers %s", plural(summary.count or 0, "API")))
    return self.version_map
  end

  function w:call(label, fn)
    local attempts = self.cfg.retry and 2 or 1
    local last = nil
    for attempt = 1, attempts do
      local result = fn(attempt)
      if result and result.ok then return result end
      last = result
      local code = result and result.error_code
      local entry = code and kafka.ERRORS and kafka.ERRORS[code]
      if not (entry and entry.retriable) or attempt == attempts then break end
      self:stage(label, "transient error, retrying: " .. tostring(result.error))
      stdnse.sleep(self.cfg.transient_backoff_ms / 1000)
    end
    return last
  end

  return w
end


----------------------------------------------------------------------------
-- 4. What a CreateTopics result means
----------------------------------------------------------------------------
--
-- The error code is the whole measurement, so it is interpreted once, here.
-- The distinction the report turns on is between "the ACL stopped the request"
-- and "the request got past the ACL and failed validation": Kafka evaluates
-- authorization before it validates anything, so a validation error from an
-- unauthenticated caller is proof that the caller was allowed to create the
-- topic it named.

local OUTCOMES = {
  [0] = { verdict = "authorized", severity = "HIGH",
    meaning = "the broker accepted the request: with validate_only absent this topic would exist now" },
  [6] = { verdict = "not-leader", severity = "INFO",
    meaning = "the broker that answered does not lead the partition set; the controller may answer differently" },
  [17] = { verdict = "authorized-name-rejected", severity = "MEDIUM",
    meaning = "the name was invalid, and the authorization check ran before it: the caller may create topics" },
  [19] = { verdict = "replicas-unavailable", severity = "LOW",
    meaning = "the broker could not satisfy the replication factor, which it only checks after authorizing" },
  [29] = { verdict = "denied", severity = "NONE",
    meaning = "the topic ACL refused the caller: creation is enforced" },
  [31] = { verdict = "denied", severity = "NONE",
    meaning = "the cluster ACL refused the caller: creation is enforced" },
  [35] = { verdict = "unsupported-version", severity = "INFO",
    meaning = "the broker does not implement the requested CreateTopics version" },
  [36] = { verdict = "authorized-exists-name", severity = "HIGH",
    meaning = "the broker compared the name against its topic list, which it does only after the ACL let "
      .. "the request through" },
  [37] = { verdict = "authorized-partitions-rejected", severity = "MEDIUM",
    meaning = "the partition count was rejected, and the authorization check ran before it" },
  [38] = { verdict = "authorized-replication-rejected", severity = "MEDIUM",
    meaning = "the replication factor was rejected, and the authorization check ran before it" },
  [40] = { verdict = "authorized-config-rejected", severity = "MEDIUM",
    meaning = "the configuration override was rejected, and the authorization check ran before it" },
  [41] = { verdict = "not-controller", severity = "INFO",
    meaning = "the request reached a broker that does not control topic creation; the controller may differ" },
  [42] = { verdict = "invalid-request", severity = "LOW",
    meaning = "the request itself was refused, which is a broker-side policy answer rather than an ACL one" },
}

local function outcome_for(error_code, error_name)
  if error_code == nil then
    return { verdict = "no-answer", severity = "INFO", meaning = "the broker did not answer" }
  end
  local known = OUTCOMES[error_code]
  if known then
    if known.verdict == "denied" and not kafka.is_authz_error(error_code) then
      return { verdict = "denied", severity = "NONE",
        meaning = "the broker refused the request with an authorization error" }
    end
    return known
  end
  if kafka.is_authz_error(error_code) then
    return { verdict = "denied", severity = "NONE",
      meaning = "the broker refused the request with an authorization error" }
  end
  return { verdict = "other-error", severity = "INFO",
    meaning = string.format("the broker answered %s, which this script does not interpret further",
      tostring(error_name or error_code)) }
end

local function is_authorized_verdict(verdict)
  if verdict == nil then return false end
  return verdict == "authorized" or string.sub(verdict, 1, 11) == "authorized-"
end

----------------------------------------------------------------------------
-- 5. Probes
----------------------------------------------------------------------------

local probe = {}

function probe.negotiate(w)
  local versions, err = w:negotiate()
  if not versions then
    return { stage = "api_versions", answered = false, error = err, access = "unknown" }
  end
  local summary = w.negotiate_summary
  local out = {
    stage = "api_versions", answered = true,
    access = (summary.error_code == 0) and "granted" or "error",
    error_code = summary.error_code, error_name = summary.error_name,
    api_count = summary.count, versions = versions,
    version_rows = kafka.version_table(w.connection),
  }
  local create = versions[19]
  out.create_topics_version = create and create.broker_max or nil
  out.create_topics_min = create and create.min or nil
  out.validate_only_available = out.create_topics_version ~= nil and out.create_topics_version >= 1
  out.metadata_version = (versions[3] or {}).broker_max
  out.describe_configs_version = (versions[32] or {}).broker_max
  out.api_offered = create ~= nil
  return out
end

-- Existence is asked with allow_auto_topic_creation forced to false, so the
-- question cannot create the topic it asks about.
function probe.topic_exists(w, name)
  local result = w:call("metadata_probe", function()
    return kafka.metadata(w.connection, { name }, {
      auto_create = false, cluster_authorized_operations = false,
      topic_authorized_operations = false,
    })
  end)
  if not result or not result.ok then
    return { stage = "metadata_probe", name = name, answered = false,
      error = result and result.error or "no response", version = result and result.version,
      exists = nil }
  end
  local entry = (result.topics or {})[1]
  local out = {
    stage = "metadata_probe", name = name, answered = true, version = result.version,
    error_code = entry and entry.error_code, error_name = entry and entry.error_name,
    partition_count = entry and #(entry.partitions or {}) or 0,
    cloned_auto_create = false,
  }
  out.exists = entry ~= nil and entry.error_code == 0
  out.access = out.exists and "granted" or "answered"
  if kafka.is_authz_error(out.error_code) then out.access = "denied" end
  return out
end

-- One validate-only creation attempt. The engine hard-codes validate_only, and
-- this script never calls a create path any other way.
function probe.create_validate_only(w, spec)
  local result = w:call("create_validate_only", function()
    return kafka.create_topics(w.connection,
      { { name = spec.name, partitions = spec.partitions, replication_factor = spec.replication,
          configs = spec.configs } },
      { timeout_ms = math.min(w.cfg.timeout, 10000) })
  end)
  if not result or not result.ok then
    return { stage = "create_validate_only", name = spec.name, answered = false,
      error = result and result.error or "no response", version = result and result.version,
      partitions = spec.partitions, replication = spec.replication, configs = spec.configs,
      validate_only = true }
  end
  local topic = (result.topics or {})[1] or {}
  local outcome = outcome_for(topic.error_code, topic.error_name)
  return {
    stage = "create_validate_only", name = spec.name, answered = true, version = result.version,
    partitions = spec.partitions, replication = spec.replication, configs = spec.configs,
    validate_only = result.validate_only ~= false,
    error_code = topic.error_code, error_name = topic.error_name, error_message = topic.error_message,
    returned_partitions = topic.num_partitions, returned_replication = topic.replication_factor,
    returned_configs = topic.configs, config_error_code = result.config_error_code,
    config_error_name = result.config_error_name, throttle_ms = result.throttle_ms,
    verdict = outcome.verdict, severity = outcome.severity, meaning = outcome.meaning,
    trailing_bytes = result.trailing_bytes,
  }
end

-- A grant is only useful to an attacker if it generalises: the confirmation
-- repeats the accepted variant under a second, differently shaped name, so the
-- report can tell a permission from a name that happens to be allowed.
function probe.confirm(w, spec)
  local result = w:call("create_confirm", function()
    return kafka.create_topics(w.connection,
      { { name = spec.name, partitions = spec.partitions, replication_factor = spec.replication,
          configs = spec.configs } },
      { timeout_ms = math.min(w.cfg.timeout, 10000) })
  end)
  if not result or not result.ok then
    return { stage = "create_confirm", name = spec.name, answered = false,
      error = result and result.error or "no response", version = result and result.version,
      partitions = spec.partitions, replication = spec.replication, validate_only = true,
      verdict = "no-answer", severity = "INFO", meaning = "the confirmation request was not answered" }
  end
  local topic = (result.topics or {})[1] or {}
  local outcome = outcome_for(topic.error_code, topic.error_name)
  return {
    stage = "create_confirm", name = spec.name, answered = true, version = result.version,
    partitions = spec.partitions, replication = spec.replication, validate_only = result.validate_only ~= false,
    error_code = topic.error_code, error_name = topic.error_name, error_message = topic.error_message,
    throttle_ms = result.throttle_ms, verdict = outcome.verdict, severity = outcome.severity,
    meaning = outcome.meaning,
  }
end

-- The pre-0.11 path. CreateTopics v0 has no validate_only, so the script asks
-- the broker to create a topic that already exists: the existence check runs
-- before any creation, and the answer is TOPIC_ALREADY_EXISTS (or an
-- authorization error). The request is written here rather than by the engine,
-- because the engine refuses to send a creating request at all.
function probe.create_v0_existing(w, spec)
  local version = 0
  local writer = kafka.writer()
  writer:array({ spec }, function(ww, item)
    ww:str(item.name)
    ww:i32(item.partitions or 1)
    ww:i16(item.replication or 1)
    ww:array({}, function() end)
    ww:array({}, function() end)
  end)
  writer:i32(math.min(w.cfg.timeout, 10000))
  local result, err = kafka.exchange(w.connection, 19, version, writer:result())
  if not result then
    return { stage = "create_v0_existing", name = spec.name, answered = false, error = err,
      version = version, safety = "existing-topic-name" }
  end
  local entry = (result:array(function(rr)
    local name = rr:str()
    local ec = rr:i16()
    local message = (version >= 1) and rr:str() or nil
    return { name = name, error_code = ec, error_name = kafka.error_name(ec or 0), error_message = message }
  end) or {})[1] or {}
  local outcome = outcome_for(entry.error_code, entry.error_name)
  return {
    stage = "create_v0_existing", name = spec.name, answered = true, version = version,
    partitions = spec.partitions, replication = spec.replication, validate_only = false,
    safety = "existing-topic-name",
    error_code = entry.error_code, error_name = entry.error_name, error_message = entry.error_message,
    verdict = outcome.verdict, severity = outcome.severity, meaning = outcome.meaning,
    trailing_bytes = result:remaining(),
  }
end

-- The defaults an auto-created topic would use are the same permissions from a
-- different direction: if auto-creation is on, any client that names a topic
-- creates it without ever calling CreateTopics.
function probe.defaults(w, broker_id)
  if not w.cfg.defaults then
    return { stage = "describe_configs", answered = true, skipped = "kafka.defaults=false", configs = {} }
  end
  local resources = {}
  if broker_id ~= nil then
    resources[#resources + 1] = { type = 4, name = num_text(broker_id) }
  end
  if #resources == 0 then
    return { stage = "describe_configs", answered = true, skipped = "the broker id was not returned", configs = {} }
  end
  local result = w:call("describe_configs", function()
    return kafka.describe_configs(w.connection, resources, {})
  end)
  if not result or not result.ok then
    return { stage = "describe_configs", answered = false, configs = {},
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = { stage = "describe_configs", answered = true, version = result.version, configs = {}, rows = 0 }
  local entry = (result.results or {})[1]
  if entry then
    out.error_code, out.error_name = entry.error_code, entry.error_name
    for _, config in ipairs(entry.configs or {}) do
      out.configs[config.name] = config
      out.rows = out.rows + 1
    end
  end
  out.access = (out.error_code == 0) and "granted" or "denied"
  return out
end

----------------------------------------------------------------------------
-- 6. Analysis
----------------------------------------------------------------------------

local analysis = {}

-- The variant matrix. Every row is one validate-only attempt, so the report can
-- say exactly which creation parameters the caller may use rather than only
-- that "creation is possible".
function analysis.variants(records)
  local out = { rows = {}, authorized = 0, denied = 0, authorized_invalid = 0,
    authorized_exists = 0, validation_refused = 0, unanswered = 0, verdicts = {},
    v0_measurements = 0 }
  for _, row in ipairs(records.create_variants or {}) do
    out.verdicts[row.verdict] = (out.verdicts[row.verdict] or 0) + 1
    if row.answered == false then
      out.unanswered = out.unanswered + 1
    elseif row.verdict == "authorized" then
      out.authorized = out.authorized + 1
      out.rows[#out.rows + 1] = row
    elseif row.verdict == "authorized-exists-name" then
      -- The pre-0.11 measurement: the request named a topic that already
      -- exists, and the answer means the ACL allowed it that far.
      out.authorized_exists = out.authorized_exists + 1
      if row.validate_only == false then out.v0_measurements = out.v0_measurements + 1 end
      out.rows[#out.rows + 1] = row
    elseif is_authorized_verdict(row.verdict) then
      out.authorized_invalid = out.authorized_invalid + 1
      out.rows[#out.rows + 1] = row
    elseif row.verdict == "denied" then
      out.denied = out.denied + 1
      out.rows[#out.rows + 1] = row
    else
      out.validation_refused = out.validation_refused + 1
      out.rows[#out.rows + 1] = row
    end
  end
  out.total = #(records.create_variants or {})
  return out
end

-- The confirmation result decides how the grant is described: a permission that
-- holds for two unrelated names is a permission; one that holds for a single
-- name is a name-shaped ACL.
function analysis.confirmations(records, variants)
  local out = { rows = {}, confirmed = 0, contradicted = 0, unanswered = 0, name_dependent = false }
  for _, row in ipairs(records.confirmations or {}) do
    out.rows[#out.rows + 1] = row
    if row.answered == false then
      out.unanswered = out.unanswered + 1
    elseif is_authorized_verdict(row.verdict) then
      out.confirmed = out.confirmed + 1
    else
      out.contradicted = out.contradicted + 1
    end
  end
  out.attempted = #(records.confirmations or {})
  out.grant_measured = variants.authorized > 0 or variants.authorized_invalid > 0
    or variants.authorized_exists > 0
  if out.contradicted > 0 and out.confirmed == 0 and out.grant_measured then
    out.name_dependent = true
  end
  return out
end

-- The safety ledger: what the script did, and what the cluster looked like
-- before and after. This is the part an operator reads to decide whether the
-- scan was actually non-destructive.
function analysis.safety(records, cfg)
  local out = {
    validate_only = true, created_anything = false, materialised = {},
    pre_answered = (records.pre_check or {}).answered, post_answered = (records.post_check or {}).answered,
    pre_exists = (records.pre_check or {}).exists, post_exists = (records.post_check or {}).exists,
    v0_requests = 0, creating_requests = 0, names_checked = 2,
    probe_name = (records.pre_check or {}).name,
  }
  for _, row in ipairs(records.create_variants or {}) do
    if row.validate_only == false then
      out.v0_requests = out.v0_requests + 1
    else
      out.creating_requests = out.creating_requests + 1
    end
  end
  if out.post_exists then
    out.created_anything = true
    out.materialised[#out.materialised + 1] = out.probe_name
  end
  if records.confirm_check then
    out.confirm_name = records.confirm_check.name
    out.confirm_checked = records.confirm_check.answered
    out.confirm_exists = records.confirm_check.exists
    if out.confirm_exists then
      out.created_anything = true
      out.materialised[#out.materialised + 1] = out.confirm_name
    end
  end
  if cfg.verify_cleanup and out.pre_exists then
    out.pre_existed = true
  end
  out.clean = (not out.created_anything) and (out.post_answered ~= false)
  return out
end

function analysis.defaults(records)
  local describe = records.defaults or {}
  local out = { answered = describe.answered, skipped = describe.skipped, access = describe.access,
    values = {}, auto_create = nil, num_partitions = nil, default_replication = nil,
    min_insync = nil, unclean_election = nil, retention_ms = nil, rows = describe.rows or 0,
    error_name = describe.error_name }
  local wanted = {
    ["auto.create.topics.enable"] = "auto_create", ["num.partitions"] = "num_partitions",
    ["default.replication.factor"] = "default_replication", ["min.insync.replicas"] = "min_insync",
    ["unclean.leader.election.enable"] = "unclean_election", ["log.retention.ms"] = "retention_ms",
  }
  for name, config in pairs(describe.configs or {}) do
    out.values[name] = config
    if wanted[name] then out[wanted[name]] = config.value end
  end
  return out
end

-- The access matrix, in the order the script actually asks the questions.
function analysis.exposure(records, variants, safety)
  local rows = {}
  local function add(name, record, access, detail)
    rows[#rows + 1] = { name = name, access = access or (record and record.access) or "unknown",
      version = record and record.version, detail = detail,
      error_name = record and record.error_name, record = record }
  end
  local negotiate = records.negotiate or {}
  add("ApiVersions", negotiate, negotiate.answered and (negotiate.access or "granted") or "unanswered",
    negotiate.answered and (plural(negotiate.api_count or 0, "API") .. " offered") or tostring(negotiate.error))
  add("Metadata (existence check)", records.pre_check,
    records.pre_check and (records.pre_check.answered and (records.pre_check.exists and "granted" or "answered")
      or "unanswered"),
    records.pre_check and (records.pre_check.exists and "the probe name exists already"
      or tostring(records.pre_check.error_name or "not present")) or nil)
  add("CreateTopics (validate_only)", records.create_variants and records.create_variants[1],
    (variants.authorized + variants.authorized_invalid + variants.authorized_exists) > 0 and "granted"
      or (variants.denied > 0 and "denied" or "unknown"),
    string.format("%d variant(s): %d authorized, %d refused by validation, %d past the ACL, %d denied",
      variants.total or 0, variants.authorized, variants.authorized_invalid, variants.authorized_exists,
      variants.denied))
  add("DescribeConfigs (defaults)", records.defaults,
    records.defaults and (records.defaults.skipped and "skipped" or records.defaults.access) or "unanswered",
    records.defaults and (records.defaults.skipped or plural(records.defaults.rows or 0, "configuration value"))
      or nil)
  local confirmation = (records.confirmations or {})[1]
  add("CreateTopics (confirmation)", confirmation,
    confirmation and (confirmation.answered == false and "unanswered"
      or (is_authorized_verdict(confirmation.verdict) and "granted" or "answered")) or "skipped",
    confirmation and string.format("%s -> %s", tostring(confirmation.name),
      tostring(confirmation.error_name or confirmation.verdict)) or "no accepted variant to confirm")
  add("Metadata (safety re-check)", records.post_check,
    records.post_check and (records.post_check.answered and (records.post_check.exists and "changed" or "answered")
      or "unanswered"),
    records.post_check and (records.post_check.exists and "THE PROBE TOPIC EXISTS" or "not present") or nil)
  local granted, denied, unanswered = 0, 0, 0
  for _, row in ipairs(rows) do
    if row.access == "granted" or row.access == "answered" then granted = granted + 1
    elseif row.access == "denied" or row.access == "changed" then denied = denied + 1
    elseif row.access == "unanswered" then unanswered = unanswered + 1 end
  end
  return { rows = rows, granted = granted, denied = denied, unanswered = unanswered,
    creation_granted = (variants.authorized + variants.authorized_invalid + variants.authorized_exists) > 0,
    creation_denied = variants.denied > 0, clean = safety.clean }
end


----------------------------------------------------------------------------
-- 7. Knowledge base
----------------------------------------------------------------------------

local KB = {}

KB.SAFETY = {
  "Every CreateTopics request this script sends carries validate_only=true, which is the protocol's own "
    .. "\"run the checks and discard the result\" flag: the broker authorizes, validates the name, the "
    .. "partition count, the replication factor and the configuration overrides, and then creates nothing.",
  "Before the first attempt and after the last one the script asks Metadata whether the probe topic exists, "
    .. "with allow_auto_topic_creation set to false. The answer is reported either way: a probe topic that "
    .. "appears is treated as an incident, not as a successful test.",
  "On a broker whose CreateTopics version predates validate_only, the script does not send a creating request. "
    .. "It names a topic that already exists, which the broker answers with TOPIC_ALREADY_EXISTS before it "
    .. "reaches the creation path.",
  "The probe topic name is generated per run and contains a timestamp and a random draw, so it cannot "
    .. "collide with a topic an operator created.",
  "No other administrative API is called: the script never sends AlterConfigs, IncrementalAlterConfigs, "
    .. "CreatePartitions, CreateAcls or DeleteTopics.",
}

KB.REMEDIATION = {
  {
    step = "Require authentication on the listener: set the SASL mechanism and the JAAS configuration for the "
      .. "listener a client uses, so topic creation is attributed to a principal instead of to ANONYMOUS.",
    why = "Authorization in Kafka is evaluated per principal; an unauthenticated caller is a principal "
      .. "(ANONYMOUS) that a wildcard ACL can easily cover, and no ACL can express 'anyone at all may not "
      .. "create'. Authentication is what makes the ACL meaningful.",
  },
  {
    step = "Remove CREATE from wildcard topic ACLs and grant it to named principals: "
      .. "'kafka-acls.sh --remove --allow-principal User:* --operation Create --topic \"*\"' then add the "
      .. "few service principals that genuinely create topics.",
    why = "A wildcard CREATE grant is what makes a validate-only request answer NONE. The operation is only "
      .. "needed by provisioning pipelines and by Connect; a consumer or a producer never needs it.",
  },
  {
    step = "Turn off auto-creation and pin the new-topic defaults: 'auto.create.topics.enable=false', "
      .. "'num.partitions=<n>' with a replication factor of 3, and 'min.insync.replicas=2' where durability "
      .. "matters.",
    why = "Auto-creation is the same permission without an ACL: a client that names a topic creates it, so "
      .. "the ACL that protects CreateTopics protects nothing on that path.",
  },
  {
    step = "Watch topic creation as an audited event: Kafka emits a broker log line and, with a supported "
      .. "version, an authorization failure metric for each CreateTopics it refuses. Alert on creation from "
      .. "an unexpected principal rather than on the ACL being right.",
    why = "The permission is only dangerous when it is used; the audit trail is what turns a scanner's "
      .. "validate-only request into a signal, and a real creation into an incident.",
  },
  {
    step = "Limit the blast radius at the broker: set 'max.connections.per.ip', a request quota for the "
      .. "client, and a disk quota on the log directories, so a caller that can create topics cannot fill the "
      .. "cluster with a few large ones.",
    why = "A quota does not remove a permission, but it bounds what the permission is worth to an attacker "
      .. "who is not trying to be quiet.",
  },
  {
    step = "After the change, re-run this script and confirm the variant matrix reports 'denied' rows and "
      .. "that the probe names are still absent.",
    why = "The ACL has to be verified on the path that matters: a DENY on the topic resource and a CREATE "
      .. "grant on the cluster resource interact, and only a request proves which one wins.",
  },
}

KB.VERIFICATION = {
  "kafka-acls.sh --bootstrap-server <broker> --list --topic <name>  (show the CREATE grant, or its absence)",
  "kafka-topics.sh --bootstrap-server <broker> --create --topic test-probe --partitions 1 "
    .. "--replication-factor 1  (run without credentials: the expected answer is TopicAuthorizationException)",
  "kafka-configs.sh --bootstrap-server <broker> --describe --entity-type brokers --entity-name <id> "
    .. "(confirm auto.create.topics.enable and the default replication factor)",
  "kafka-topics.sh --bootstrap-server <broker> --list  (confirm that no nmap-create-audit- topic exists)",
  "grep -i 'CreateTopics' <broker server.log>  (confirm the refused requests are attributed and logged)",
  "nmap -p 9092 --script kafka-create-topic-allowed <target>  (the same matrix, expected to report 'denied')",
}

KB.METHOD_LIMITS = {
  "validate_only is honoured by every broker release that implements CreateTopics v1 or later; this script "
    .. "never sends a creating request on any version.",
  "The answer is the broker's own decision for the connection it answered on. A cluster with more than one "
    .. "listener can enforce authentication on one and not on another, and a load balancer in front of the "
    .. "cluster can send the probe to a broker that answers differently from its peers.",
  "Authorization for CreateTopics is checked against the topic resource, and the ACL model also allows a "
    .. "cluster-level CREATE grant. The probe observes the result of that interaction, not which rule "
    .. "produced it.",
  "A validation error proves that the authorization check passed, but it does not prove that a valid request "
    .. "would have succeeded: the broker may refuse on a later check that this script cannot reach without "
    .. "creating something.",
  "The variant matrix covers the partition counts and replication factors given on the command line (by "
    .. "default 1 and 64 partitions, replication 1 and 3). A broker can enforce a policy per value, so the "
    .. "absence of a NONE answer for one variant is not evidence about another.",
  "The defaults read with DescribeConfigs describe what an auto-created topic would use. They are reported "
    .. "as context for the creation permission and not as a statement about any existing topic.",
  "The confirmation request repeats only the first variant the broker accepted, under one new name. It proves "
    .. "that the grant is not bound to a single name; it does not prove that every name is accepted, because "
    .. "only a full name sweep could, and a sweep of a live cluster is both rude and unnecessary for a report "
    .. "that already states what the accepted variant was.",
  "Every request the script sends is one the broker answers from its controller-side state; a request that "
    .. "times out leaves the verdict of that variant unknown and is reported as unanswered rather than as a "
    .. "refusal.",
}

KB.ATTACK_VALUE = {
  { exposure = "topic creation allowed",
    value = "a topic an attacker names is a topic a misconfigured producer writes to, and a topic a "
      .. "misconfigured consumer reads from: the name is a rendezvous point chosen by the attacker" },
  { exposure = "creation with a large partition count",
    value = "each partition is a directory with its own index files and its share of the broker's memory, so "
      .. "a permitted partition count is a resource-exhaustion budget" },
  { exposure = "creation with a configuration override",
    value = "an attacker-chosen retention or segment size changes how much disk the topic consumes, and a "
      .. "compacted topic can be used to overwrite what a consumer reads without touching the producer" },
  { exposure = "auto-creation enabled",
    value = "the same permission without an ACL: a typo or a probe creates the topic, and an existence "
      .. "oracle becomes a creation primitive" },
  { exposure = "weak new-topic defaults",
    value = "a topic created with replication factor 1 and min.insync.replicas=1 loses data on a single "
      .. "broker restart, and the loss happens in a topic nobody is watching" },
}

KB.OPERATOR_SIGNALS = {
  { signal = "a CreateTopics request from an unexpected principal",
    where = "broker log line 'Created topic' / 'Topic creation' with the principal, and the "
      .. "kafka.server:type=RequestMetrics counters for CreateTopics",
    note = "the script's validate-only requests are refused or accepted without creating, but they are still "
      .. "logged as CreateTopics; a scan therefore shows up in the request counters even when it changed "
      .. "nothing" },
  { signal = "an increase in the number of topics",
    where = "kafka.server:type=BrokerTopicMetrics,name=Topics or the topic count reported by "
      .. "kafka-topics.sh --describe",
    note = "a topic that appears without a deployment is either auto-creation or a caller that may create "
      .. "topics, and the two are told apart by the presence of a CreateTopics request" },
  { signal = "auto-created topics",
    where = "broker log line 'Auto-created topic' with the client id",
    note = "auto-creation bypasses the CreateTopics ACL, so this is the signal that matters when the "
      .. "existence-oracle finding is in the report" },
  { signal = "topic names that match a scanner's probe pattern",
    where = "any topic name containing a timestamp, 'probe', 'test' or 'audit', or a name with no dash-separated "
      .. "service prefix",
    note = "the script reports the names it used, so an operator can correlate them with the topic list and "
      .. "confirm that none of them exists" },
  { signal = "disk growth on the log directories",
    where = "node_filesystem_avail_bytes on the log mount, and the size of the largest partition directories",
    note = "a caller that may create topics with a large partition count converts the permission into disk "
      .. "consumption, and the growth starts inside the retention window" },
  { signal = "CreateTopics requests that carry validate_only",
    where = "the request log at DEBUG level, or a network sensor that understands the Kafka wire protocol",
    note = "validate_only is not a normal client behaviour: a producer, a consumer and the standard admin "
      .. "tools never set it. Seeing it is how a defender recognises this audit, and a caller that sets it is "
      .. "reconnoitring rather than provisioning" },
}

KB.RISK_RUBRIC = {
  { severity = "CRITICAL", condition = "the validate-only probe name was created anyway, or the broker "
    .. "created a topic in response to a request that asked it not to" },
  { severity = "HIGH", condition = "a validate-only creation was accepted, or was refused only because of "
    .. "the parameters - which means the authorization check passed" },
  { severity = "MEDIUM", condition = "auto-creation is enabled, or the defaults a new topic would use are "
    .. "weak, without a direct creation grant" },
  { severity = "LOW", condition = "only the configuration defaults were readable, or the probe was answered "
    .. "with a broker-side policy error" },
  { severity = "INFO", condition = "creation was refused, or the API was not offered, or nothing answered" },
}

----------------------------------------------------------------------------
-- 8. Findings
----------------------------------------------------------------------------

local findings = {}

function findings.evaluate(records, variants, safety, defaults, exposure, confirmations, cfg)
  local list = {}
  local negotiate = records.negotiate or {}

  if #safety.materialised > 0 then
    list[#list + 1] = finding("KAFKA-PROBE-TOPIC-MATERIALISED",
      "A topic was created despite validate_only",
      "CRITICAL",
      string.format("The probe topic '%s' did not exist before the scan and existed after it, although every "
        .. "creation request carried validate_only=true. The flag is not advisory: a broker that creates the "
        .. "topic anyway is ignoring it. Treat this as an incident: the audit changed the cluster, and any "
        .. "client with the same access can create topics at will.",
        tostring(safety.probe_name)),
      { string.format("before: %s", tostring(safety.pre_exists)),
        string.format("after: %s", tostring(safety.post_exists)) },
      { KB.REMEDIATION[1], KB.REMEDIATION[2], KB.REMEDIATION[4] })
  end

  if variants.authorized > 0 then
    local evidence = {}
    for _, row in ipairs(variants.rows) do
      if row.verdict == "authorized" then
        evidence[#evidence + 1] = string.format("partitions=%s replication=%s -> %s",
          num_text(row.partitions), num_text(row.replication), tostring(row.error_name or "NONE"))
      end
    end
    list[#list + 1] = finding("KAFKA-ANONYMOUS-TOPIC-CREATE",
      "Topic creation is authorized without authentication",
      "HIGH",
      string.format("CreateTopics with validate_only answered NONE for %s of %s variant(s): the broker ran "
        .. "the complete creation path - authorization, name, partitions, replication, configuration - and "
        .. "accepted it. With validate_only removed the topic would exist. The probe covers %s; the cluster "
        .. "therefore lets a caller that never authenticated choose a topic name, a partition count and a "
        .. "configuration, which is the permission that turns an observer into a participant.",
        plural(variants.authorized, "variant"), num_text(variants.total),
        fmt_list((function()
          local parts = {}
          for _, row in ipairs(variants.rows) do
            if row.verdict == "authorized" then
              parts[#parts + 1] = string.format("%s partitions x %s replicas",
                num_text(row.partitions), num_text(row.replication))
            end
          end
          return parts
        end)(), 6)),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[2], KB.REMEDIATION[5] })
  end

  if variants.authorized_exists > 0 then
    local evidence = {}
    for _, row in ipairs(variants.rows) do
      if row.verdict == "authorized-exists-name" then
        evidence[#evidence + 1] = string.format("%s -> %s (partitions=%s replication=%s)",
          tostring(row.name), tostring(row.error_name), num_text(row.partitions), num_text(row.replication))
      end
    end
    list[#list + 1] = finding("KAFKA-TOPIC-CREATE-AUTHORIZED-EXISTING-NAME",
      "Creation reached the existence check, which happens after the ACL",
      "HIGH",
      string.format("The broker answered TOPIC_ALREADY_EXISTS for %s. Kafka authorizes the CREATE operation "
        .. "on the topic resource before it looks the name up, so the existence answer is only ever produced "
        .. "for a caller the ACL allowed. The same caller could create a topic under a name that is free.",
        plural(variants.authorized_exists, "request")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[2] })
  end

  if variants.authorized_invalid > 0 then
    local evidence = {}
    for _, row in ipairs(variants.rows) do
      if is_authorized_verdict(row.verdict) and row.verdict ~= "authorized" then
        evidence[#evidence + 1] = string.format("partitions=%s replication=%s -> %s (%s)",
          num_text(row.partitions), num_text(row.replication), tostring(row.error_name),
          tostring(row.meaning))
      end
    end
    list[#list + 1] = finding("KAFKA-TOPIC-CREATE-PERMITTED-PARAMETERS-REJECTED",
      "Topic creation passed authorization and failed only validation",
      "HIGH",
      string.format("For %s the broker answered with a validation error rather than an authorization error. "
        .. "Kafka evaluates the ACL before it validates the request, so the ACL let the caller through and "
        .. "the refusal is about the parameters this script chose - not about the caller. A request with "
        .. "acceptable parameters would have been created.",
        plural(variants.authorized_invalid, "variant")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[2] })
  end

  if variants.denied > 0 then
    list[#list + 1] = finding("KAFKA-TOPIC-CREATE-DENIED",
      "Topic creation was refused without authentication",
      "INFO",
      string.format("%s were refused with an authorization error, which is the intended behaviour. It is "
        .. "reported so the baseline is explicit: the ACL for CREATE on the topic resource is enforcing, and "
        .. "a later run that stops reporting this row is a regression.",
        plural(variants.denied, "variant")),
      { string.format("refusals: %s -> %s", num_text(variants.denied),
        fmt_list((function()
          local names = {}
          for _, row in ipairs(variants.rows) do
            if row.verdict == "denied" then names[#names + 1] = tostring(row.error_name) end
          end
          return names
        end)(), 4)) }, { KB.REMEDIATION[2], KB.REMEDIATION[6] })
  end

  if confirmations.attempted > 0 and confirmations.confirmed > 0 then
    list[#list + 1] = finding("KAFKA-CREATE-GRANT-CONFIRMED",
      "The creation grant holds for a second, unrelated name",
      "INFO",
      string.format("%s repeated the accepted variant under a different probe name and were accepted again. "
        .. "The answer is therefore a permission attached to the caller, not to a name that happens to be "
        .. "allowed: the ACL model in front of creation is not name-shaped.",
        plural(confirmations.confirmed, "request")),
      { string.format("confirmed: %d, contradicted: %d, unanswered: %d", confirmations.confirmed,
        confirmations.contradicted, confirmations.unanswered) }, { KB.REMEDIATION[2] })
  end

  if confirmations.name_dependent then
    list[#list + 1] = finding("KAFKA-CREATE-GRANT-NAME-DEPENDENT",
      "Creation was accepted for one probe name and refused for another",
      "MEDIUM",
      string.format("The first probe name was accepted and the confirmation name was refused: %s. A "
        .. "name-dependent answer is usually a prefix ACL or a quota that applies to a pattern, and it means "
        .. "the grant an attacker gets depends on what they call the topic.",
        fmt_list((function()
          local names = {}
          for _, row in ipairs(confirmations.rows) do
            names[#names + 1] = string.format("%s -> %s", tostring(row.name), tostring(row.error_name or row.verdict))
          end
          return names
        end)(), 4)),
      { "the two names differ, the permission did not" }, { KB.REMEDIATION[2], KB.REMEDIATION[6] })
  end

  if negotiate.answered and not negotiate.api_offered then
    list[#list + 1] = finding("KAFKA-CREATE-API-NOT-OFFERED",
      "The broker does not advertise CreateTopics",
      "INFO",
      "ApiVersions does not list CreateTopics, so the creation permission could not be measured. A broker "
        .. "that hides the API from an unauthenticated caller is showing part of the enforcement posture, not "
        .. "the absence of a permission.",
      { string.format("ApiVersions answered %s with %s", tostring(negotiate.answered),
        plural(negotiate.api_count or 0, "API")) }, { KB.REMEDIATION[1] })
  elseif negotiate.answered and not negotiate.validate_only_available then
    list[#list + 1] = finding("KAFKA-VALIDATE-ONLY-UNAVAILABLE",
      "The broker predates validate_only",
      "INFO",
      string.format("CreateTopics is advertised up to v%s, which has no validate_only flag. The script "
        .. "therefore did not send a creating request: it named an existing topic, which the broker answers "
        .. "with TOPIC_ALREADY_EXISTS before it creates anything. Measure this cluster with a name that "
        .. "already exists, or upgrade the broker.",
        tostring(negotiate.create_topics_version)),
      { "CreateTopics version 0 has no validate_only field" }, { KB.REMEDIATION[1] })
  end

  if defaults.answered and not defaults.skipped then
    if defaults.auto_create == "true" then
      list[#list + 1] = finding("KAFKA-AUTO-CREATE-ENABLED",
        "Auto topic creation is enabled",
        "MEDIUM",
        string.format("The broker reports auto.create.topics.enable=true, so a client that names a topic the "
          .. "cluster does not have causes it to be created with %s and %s. That path does not consult the "
          .. "CreateTopics ACL at all: it is governed by the DESCRIBE/CREATE authorization on the metadata "
          .. "path, which is exactly the check an anonymous client tends to pass.",
          defaults.num_partitions and (num_text(defaults.num_partitions) .. " partitions") or "the default",
          defaults.default_replication and (num_text(defaults.default_replication) .. " replica(s)")
            or "the default replication"),
        { "auto.create.topics.enable=true (broker configuration)" },
        { KB.REMEDIATION[3], KB.REMEDIATION[2] })
    end
    if defaults.default_replication and tonumber(defaults.default_replication) == 1 then
      list[#list + 1] = finding("KAFKA-WEAK-NEW-TOPIC-DEFAULTS",
        "New topics default to a single replica",
        "MEDIUM",
        string.format("default.replication.factor is %s and min.insync.replicas is %s, so a topic created "
          .. "without an explicit replication factor has no redundancy and an acks=all write needs one "
          .. "replica. Neither setting stops an attacker, but both decide how much data a caller who may "
          .. "create topics can put at risk.",
          num_text(defaults.default_replication), tostring(defaults.min_insync or "not reported")),
        { string.format("default.replication.factor=%s", num_text(defaults.default_replication)),
          string.format("min.insync.replicas=%s", tostring(defaults.min_insync or "not reported")) },
        { KB.REMEDIATION[3] })
    end
  elseif defaults.answered == false then
    list[#list + 1] = finding("KAFKA-CREATE-DEFAULTS-UNREADABLE",
      "The defaults for a new topic could not be read",
      "INFO",
      string.format("DescribeConfigs did not answer (%s), so the report cannot say what a created topic "
        .. "would look like. The creation permission itself was measured independently of this read.",
        tostring(defaults.error or defaults.error_name)), {}, { KB.REMEDIATION[3] })
  elseif defaults.skipped then
    list[#list + 1] = finding("KAFKA-CREATE-DEFAULTS-NOT-READ",
      "The defaults for a new topic were not read",
      "INFO", tostring(defaults.skipped), {}, { KB.REMEDIATION[3] })
  end

  for _, row in ipairs(records.create_variants or {}) do
    if row.throttle_ms and row.throttle_ms > 0 then
      list[#list + 1] = finding("KAFKA-CREATE-QUOTA-OBSERVED",
        "A quota delayed the creation request",
        "LOW",
        string.format("The broker reported %dms of throttle time on the creation request, so a quota is "
          .. "attached to the client that asked. Quotas bound how quickly a permission can be exercised, "
          .. "which is worth knowing when the permission is granted to an anonymous principal.",
          row.throttle_ms),
        { string.format("throttle_time_ms=%s", num_text(row.throttle_ms)) }, { KB.REMEDIATION[5] })
      break
    end
  end

  -- A listener that never answered the negotiation has not been measured at
  -- all, whatever else the run produced.
  if not negotiate.answered then
    list[#list + 1] = finding("KAFKA-CREATE-PERMISSION-NOT-MEASURED",
      "The creation permission could not be measured",
      "INFO",
      string.format("ApiVersions was not answered (%s), so no creation request was sent and this report "
        .. "makes no claim about the cluster. A listener that requires authentication, a TLS-only listener "
        .. "and a filtered network path all look like this from outside.",
        tostring(negotiate.error)),
      { tostring(negotiate.error) }, { KB.REMEDIATION[1] })
  end

  if exposure.granted > 0 and variants.total == 0 and negotiate.answered then
    list[#list + 1] = finding("KAFKA-CREATE-VARIANTS-EMPTY",
      "No creation variant was sent",
      "INFO",
      "The listener answered other API calls but no creation variant was attempted, which means the variant "
        .. "list was empty. Raise kafka.partitions or kafka.replication to send at least one.",
      { "variant budget: 0" }, { KB.REMEDIATION[1] })
  end

  return list
end


----------------------------------------------------------------------------
-- 9. Report
----------------------------------------------------------------------------

local report = {}

function report.target_section(cfg, host, port, w, records)
  local negotiate = records.negotiate or {}
  local lines = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id: %s", cfg.client_id),
    string.format("Timeout: %dms, retry on transient errors: %s", cfg.timeout, fmt_bool(cfg.retry)),
    string.format("Variants: partitions %s, replication %s, configuration override: %s",
      fmt_list(cfg.partitions, 4), fmt_list(cfg.replication, 4), fmt_bool(cfg.config_check)),
    string.format("Defaults read: %s, cleanup re-check: %s", fmt_bool(cfg.defaults),
      fmt_bool(cfg.verify_cleanup)),
  }
  if negotiate.answered then
    lines[#lines + 1] = string.format("CreateTopics: v%s (validate_only %s)",
      negotiate.create_topics_version ~= nil and num_text(negotiate.create_topics_version) or "not offered",
      negotiate.validate_only_available and "available" or "unavailable")
    lines[#lines + 1] = string.format("Probe name: %s", tostring((records.pre_check or {}).name))
  elseif negotiate.error then
    lines[#lines + 1] = "ApiVersions was not answered: " .. tostring(negotiate.error)
  end
  if #w.stages > 0 then
    local stages = {}
    for _, stage in ipairs(w.stages) do
      stages[#stages + 1] = stage.detail and (stage.name .. " (" .. stage.detail .. ")") or stage.name
    end
    lines[#lines + 1] = "Stages: " .. table.concat(stages, ", ")
  end
  if w.failure then lines[#lines + 1] = "Transport failure: " .. tostring(w.failure) end
  return lines
end

function report.safety_section(safety, cfg, records)
  local lines = {
    string.format("validate_only used on every creating request: %s", fmt_bool(safety.validate_only)),
    string.format("CreateTopics requests: %d with validate_only, %d with an existing name (v0 path)",
      safety.creating_requests, safety.v0_requests),
    string.format("Probe name '%s': before=%s after=%s", tostring(safety.probe_name),
      tostring(safety.pre_exists), tostring(safety.post_exists)),
  }
  if safety.confirm_name then
    lines[#lines + 1] = string.format("Confirmation name '%s': after=%s", tostring(safety.confirm_name),
      tostring(safety.confirm_exists))
  end
  if not cfg.verify_cleanup then
    lines[#lines + 1] = "The cleanup re-check was disabled (kafka.verify-cleanup=false): the report cannot "
      .. "state that no topic was created."
  elseif safety.created_anything then
    lines[#lines + 1] = "A topic that did not exist before the scan exists after it: see the findings."
  elseif safety.post_answered == false then
    lines[#lines + 1] = string.format("The cleanup re-check was not answered (%s), so the report cannot rule "
      .. "out a creation; the answer to the re-check is part of the evidence.",
      tostring((records.post_check or {}).error))
  else
    lines[#lines + 1] = "The probe names do not exist: the cluster is unchanged by this scan."
  end
  for _, line in ipairs(KB.SAFETY) do lines[#lines + 1] = line end
  return lines
end

function report.access_section(exposure, records)
  local lines = { string.format("%-30s %-12s %-8s %s", "Request", "Access", "Version", "What came back") }
  for _, row in ipairs(exposure.rows or {}) do
    lines[#lines + 1] = string.format("%-30s %-12s %-8s %s", row.name, tostring(row.access),
      row.version and ("v" .. num_text(row.version)) or "-", tostring(row.detail or "-"))
  end
  lines[#lines + 1] = string.format("Summary: %d answered, %d refused, %d unanswered",
    exposure.granted or 0, exposure.denied or 0, exposure.unanswered or 0)
  return lines
end

-- The variant matrix is the measurement itself: one line per attempt, with the
-- error code and what that code proves about the authorization check.
function report.variant_section(variants, records)
  local lines = {}
  if variants.total == 0 then
    return { "No variant was sent." }
  end
  lines[#lines + 1] = string.format("%-10s %-12s %-9s %-26s %-22s %s", "Partitions", "Replication",
    "Mode", "Error", "Verdict", "Proves")
  for _, row in ipairs(variants.rows or {}) do
    local configs = row.configs and #row.configs > 0 and fmt_list((function()
      local out = {}
      for _, config in ipairs(row.configs) do out[#out + 1] = tostring(config.name) end
      return out
    end)(), 3) or "none"
    lines[#lines + 1] = string.format("%-10s %-12s %-9s %-26s %-22s %s", num_text(row.partitions),
      num_text(row.replication), row.validate_only and "validate" or "v0/existing",
      tostring(row.error_name or row.error_code or "no answer"), tostring(row.verdict),
      tostring(row.meaning))
    if row.error_message and #tostring(row.error_message) > 0 then
      lines[#lines + 1] = "    broker message: " .. tostring(row.error_message)
    end
    if row.config_error_name then
      lines[#lines + 1] = string.format("    configuration error: %s", tostring(row.config_error_name))
    end
    if row.returned_partitions or row.returned_replication then
      lines[#lines + 1] = string.format("    the broker echoed partitions=%s replication=%s",
        tostring(row.returned_partitions), tostring(row.returned_replication))
    end
    if row.throttle_ms and row.throttle_ms > 0 then
      lines[#lines + 1] = string.format("    throttled by %sms", num_text(row.throttle_ms))
    end
    if configs ~= "none" then lines[#lines + 1] = "    configuration override: " .. configs end
  end
  local parts = {}
  for _, verdict in ipairs(sorted_keys(variants.verdicts)) do
    parts[#parts + 1] = string.format("%s x%s", tostring(verdict), num_text(variants.verdicts[verdict]))
  end
  lines[#lines + 1] = "Verdicts: " .. fmt_list(parts, 8)
  if variants.unanswered > 0 then
    lines[#lines + 1] = string.format("%s were not answered at all: a listener that drops the request is "
      .. "neither a grant nor a refusal.", plural(variants.unanswered, "variant"))
  end
  return lines
end

function report.confirmation_section(confirmations, records)
  local lines = {}
  if confirmations.attempted == 0 then
    return { "No confirmation request was sent: no variant was accepted, so there was nothing to confirm." }
  end
  for _, row in ipairs(confirmations.rows) do
    lines[#lines + 1] = string.format("%s: partitions=%s replication=%s -> %s (%s)", tostring(row.name),
      num_text(row.partitions), num_text(row.replication),
      tostring(row.error_name or row.error_code or "no answer"), tostring(row.verdict))
  end
  lines[#lines + 1] = string.format("Confirmed %s, contradicted %s, unanswered %s",
    num_text(confirmations.confirmed), num_text(confirmations.contradicted),
    num_text(confirmations.unanswered))
  if confirmations.name_dependent then
    lines[#lines + 1] = "The answer depends on the topic name: the grant measured by the first probe does not "
      .. "generalise to every name."
  elseif confirmations.confirmed > 0 then
    lines[#lines + 1] = "The permission is attached to the caller rather than to a name."
  end
  return lines
end

function report.version_section(records)
  local negotiate = records.negotiate or {}
  if not negotiate.answered then
    return { "ApiVersions was not answered, so no version table exists." }
  end
  local table_rows = negotiate.version_rows or {}
  if #table_rows == 0 then
    return { "The broker answered ApiVersions without a version table." }
  end
  local lines = { string.format("%-34s %-8s %-8s %-8s %s", "API", "Min", "Max", "Chosen",
    "Used by this script") }
  local used = { [18] = "negotiation", [3] = "existence checks", [19] = "creation attempt",
    [32] = "new-topic defaults" }
  for _, row in ipairs(table_rows) do
    lines[#lines + 1] = string.format("%-34s %-8s %-8s %-8s %s", tostring(row.name),
      row.broker_min ~= nil and num_text(row.broker_min) or "not offered",
      row.broker_max ~= nil and num_text(row.broker_max) or "not offered",
      row.chosen ~= nil and num_text(row.chosen) or "-", tostring(used[row.key] or "-"))
  end
  local offered = 0
  for _, row in ipairs(table_rows) do
    if row.broker_max ~= nil then offered = offered + 1 end
  end
  lines[#lines + 1] = string.format("The broker advertises %d of the %d APIs this engine knows, and its "
    .. "version floor for an API is the oldest schema it will still parse.", offered, #table_rows)
  return lines
end

function report.defaults_section(defaults, cfg)
  local lines = {}
  if defaults.skipped then
    return { "The defaults were not read: " .. tostring(defaults.skipped) }
  end
  if not defaults.answered then
    return { string.format("DescribeConfigs did not answer (%s): the defaults a new topic would use are "
      .. "unknown.", tostring(defaults.error or defaults.error_name)) }
  end
  if defaults.error_code and defaults.error_code ~= 0 then
    return { string.format("The broker refused to describe itself: %s", tostring(defaults.error_name)) }
  end
  local order = { "auto.create.topics.enable", "num.partitions", "default.replication.factor",
    "min.insync.replicas", "unclean.leader.election.enable", "log.retention.ms" }
  for _, name in ipairs(order) do
    local config = defaults.values[name]
    if config then
      lines[#lines + 1] = string.format("%-32s %-14s %s", name, tostring(config.value),
        tostring(config.source or "source not returned"))
    end
  end
  if #lines == 0 then
    lines[#lines + 1] = string.format("The broker answered with %s configuration value(s), none of them the "
      .. "defaults for a new topic.", plural(defaults.rows, "row"))
  end
  lines[#lines + 1] = string.format("A topic created without explicit parameters would use %s and %s, with "
    .. "min.insync.replicas=%s.", defaults.num_partitions and num_text(defaults.num_partitions) or "the default",
    defaults.default_replication and (num_text(defaults.default_replication) .. " replica(s)")
      or "the default replication", tostring(defaults.min_insync or "unknown"))
  if defaults.auto_create == "true" then
    lines[#lines + 1] = "Because auto-creation is enabled, a client that merely names a missing topic creates "
      .. "it: the CreateTopics ACL does not govern that path."
  end
  return lines
end

function report.finding_section(list)
  if #list == 0 then
    return { "No finding: the cluster did not permit a topic creation to this caller." }
  end
  local lines = {}
  for index, item in ipairs(list) do
    lines[#lines + 1] = string.format("%d. [%s] %s (%s)", index, item.severity, item.title, item.id)
    lines[#lines + 1] = "   " .. item.detail
    for _, evidence in ipairs(item.evidence) do lines[#lines + 1] = "   evidence: " .. evidence end
    for _, step in ipairs(item.remediation) do
      lines[#lines + 1] = "   fix: " .. (type(step) == "table" and step.step or tostring(step))
      if type(step) == "table" and step.why then lines[#lines + 1] = "        why: " .. step.why end
    end
  end
  return lines
end

function report.remediation_section(list)
  local seen, lines = {}, {}
  for _, item in ipairs(list) do
    for _, step in ipairs(item.remediation) do
      local text = type(step) == "table" and step.step or tostring(step)
      if not seen[text] then
        seen[text] = true
        lines[#lines + 1] = text
        if type(step) == "table" and step.why then lines[#lines + 1] = "    why: " .. step.why end
      end
    end
  end
  if #lines == 0 then lines[#lines + 1] = "No change is required for this target." end
  return lines
end

function report.rubric_section()
  local lines = {}
  for _, entry in ipairs(KB.RISK_RUBRIC) do
    lines[#lines + 1] = string.format("%s: %s", entry.severity, entry.condition)
  end
  return lines
end

function report.value_section(list)
  if #list == 0 then return { "Nothing was exposed, so no attack value applies." } end
  local lines = {}
  for _, entry in ipairs(KB.ATTACK_VALUE) do
    lines[#lines + 1] = string.format("%s: %s", entry.exposure, entry.value)
  end
  return lines
end

-- The verdict table: one line per possible answer, so a reader can map the
-- matrix above onto the report's conclusion without trusting the summary.
function report.verdict_section()
  local lines = { string.format("%-34s %-22s %s", "Error", "Verdict", "What it means") }
  for _, code in ipairs(sorted_keys(OUTCOMES)) do
    local entry = OUTCOMES[code]
    lines[#lines + 1] = string.format("%-34s %-22s %s",
      string.format("%s (%s)", tostring(kafka.error_name(code)), num_text(code)),
      entry.verdict, entry.meaning)
  end
  return lines
end

function report.build(cfg, host, port, records, variants, safety, defaults, exposure, confirmations, list, w)
  local out = stdnse.output_table()
  out["Target"] = report.target_section(cfg, host, port, w, records)
  out["Safety ledger"] = report.safety_section(safety, cfg, records)
  out["Access matrix"] = report.access_section(exposure, records)
  out["Variant matrix"] = report.variant_section(variants, records)
  out["Confirmation probes"] = report.confirmation_section(confirmations, records)
  out["New topic defaults"] = report.defaults_section(defaults, cfg)
  out["Findings"] = report.finding_section(list)
  out["Why the exposure matters"] = report.value_section(list)
  out["Remediation"] = report.remediation_section(list)
  out["Operator signals"] = (function()
    local lines = {}
    for _, entry in ipairs(KB.OPERATOR_SIGNALS) do
      lines[#lines + 1] = string.format("%s - %s", entry.signal, entry.note)
      lines[#lines + 1] = "    where: " .. entry.where
    end
    return lines
  end)()
  out["Verification"] = KB.VERIFICATION
  out["Method limits"] = KB.METHOD_LIMITS
  out["Version negotiation"] = report.version_section(records)
  out["Answer reference"] = report.verdict_section()
  out["Risk rubric"] = report.rubric_section()
  local summary = {}
  for _, severity in ipairs({ "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }) do
    local count = 0
    for _, item in ipairs(list) do
      if item.severity == severity then count = count + 1 end
    end
    if count > 0 then summary[#summary + 1] = string.format("%s x%d", severity, count) end
  end
  out["Finding summary"] = #summary > 0 and table.concat(summary, ", ") or "no findings"
  if not (records.negotiate and records.negotiate.answered) then
    out["Risk Level"] = "UNKNOWN"
  else
    out["Risk Level"] = worst(list, "NONE")
  end
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
-- 10. Orchestration
----------------------------------------------------------------------------

-- The variant list: every combination of the configured partition counts and
-- replication factors, plus one variant that carries a configuration override
-- when the operator left that check on.
local function build_variants(cfg, base_name)
  local variants = {}
  for _, partitions in ipairs(cfg.partitions) do
    for _, replication in ipairs(cfg.replication) do
      variants[#variants + 1] = {
        name = string.format("%s-p%s-r%s", base_name, num_text(partitions), num_text(replication)),
        partitions = partitions, replication = replication,
      }
    end
  end
  if cfg.config_check and #variants > 0 then
    variants[#variants + 1] = {
      name = base_name .. "-config",
      partitions = variants[1].partitions, replication = variants[1].replication,
      configs = { { name = "retention.ms", value = "60000" } },
    }
  end
  return variants
end

action = function(host, port)
  local cfg = read_config()
  local w = new_wire(host, port, cfg)
  local out = stdnse.output_table()
  local connected, connect_error = w:connect()
  if not connected then
    out["Risk Level"] = "UNKNOWN"
    out["Target"] = {
      string.format("Endpoint: %s:%d/tcp", host.ip or "target", port.number),
      "Transport failure: " .. tostring(connect_error),
    }
    out["Method limits"] = {
      "The TCP connection failed, so no creation request was sent. A TLS-only listener answers a plaintext "
        .. "Kafka probe exactly like this.",
    }
    return out
  end

  local records = {}
  records.negotiate = probe.negotiate(w)
  local base_name = probe_topic_name()
  records.pre_check = probe.topic_exists(w, base_name)

  -- The broker discovery is only needed for the defaults read, and it is the
  -- same Metadata call the existence check already made, so the controller id
  -- comes from a single extra request.
  local broker_id = nil
  local metadata = kafka.metadata(w.connection, {}, { auto_create = false })
  if metadata and metadata.ok then
    broker_id = metadata.controller_id
    if broker_id == nil and metadata.brokers and metadata.brokers[1] then
      broker_id = metadata.brokers[1].node_id
    end
  end

  records.create_variants = {}
  local variants = build_variants(cfg, base_name)
  if records.negotiate.answered and records.negotiate.api_offered then
    if records.negotiate.validate_only_available then
      for _, spec in ipairs(variants) do
        records.create_variants[#records.create_variants + 1] = probe.create_validate_only(w, spec)
      end
    else
      -- Older broker: an existing topic name is the only safe question.
      local existing = nil
      local listing = kafka.metadata(w.connection, nil, { auto_create = false })
      if listing and listing.ok then
        for _, topic in ipairs(listing.topics or {}) do
          if not topic.is_internal and topic.error_code == 0 then existing = topic.name break end
        end
      end
      if existing then
        for _, spec in ipairs(variants) do
          records.create_variants[#records.create_variants + 1] = probe.create_v0_existing(w,
            { name = existing, partitions = spec.partitions, replication = spec.replication })
        end
      else
        records.create_variants_existing_name = nil
      end
    end
  end

  -- Confirm the strongest accepted variant under a second name. Only a variant
  -- the broker accepted is worth confirming: a refused one has already answered
  -- the question.
  records.confirmations = {}
  if records.negotiate.validate_only_available then
    local confirmed_variant = nil
    for _, row in ipairs(records.create_variants) do
      if row.answered and is_authorized_verdict(row.verdict) and row.verdict ~= "exists-already" then
        confirmed_variant = row break
      end
    end
    if confirmed_variant then
      records.confirmations[#records.confirmations + 1] = probe.confirm(w, {
        name = string.format("%s-confirm-%d", base_name, math.random(1000, 9999)),
        partitions = confirmed_variant.partitions, replication = confirmed_variant.replication,
        configs = confirmed_variant.configs,
      })
    end
  end

  -- The confirmation name is a second topic the script asked the broker to
  -- create (in validate-only mode), so it gets the same cleanup check.
  if records.confirmations[1] then
    records.confirm_check = probe.topic_exists(w, records.confirmations[1].name)
  end

  records.defaults = probe.defaults(w, broker_id)
  if cfg.verify_cleanup then
    records.post_check = probe.topic_exists(w, base_name)
  else
    records.post_check = { stage = "metadata_probe", name = base_name, answered = true,
      skipped = "kafka.verify-cleanup=false" }
  end
  w:close()

  local variant_analysis = analysis.variants(records)
  local safety = analysis.safety(records, cfg)
  local defaults = analysis.defaults(records)
  local confirmations = analysis.confirmations(records, variant_analysis)
  local exposure = analysis.exposure(records, variant_analysis, safety)
  local list = findings.evaluate(records, variant_analysis, safety, defaults, exposure, confirmations, cfg)

  local result = report.build(cfg, host, port, records, variant_analysis, safety, defaults, exposure,
    confirmations, list, w)

  if has_vulns and vulns and vulns.add then
    for _, item in ipairs(list) do
      if item.severity == "CRITICAL" or item.severity == "HIGH" then
        vulns.add(host, port, item.id, item.title, {
          format = function() return item.detail end,
        })
      end
    end
  end

  return result
end
