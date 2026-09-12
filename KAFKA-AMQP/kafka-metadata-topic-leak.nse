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
Maps everything the Metadata API of a Kafka cluster reveals to a caller it has
not authenticated, and turns that map into an exposure report.

Metadata is the API every Kafka client calls first, and by default it answers
before any credential is checked. The answer contains the whole cluster: every
topic with its name, its internal flag, its partition count, and for every
partition the leader, the replica set, the in-sync set, the offline set, the
leader epoch, and - where the broker version carries them - the stable topic id
and the topic's own authorized-operation mask.

The script reads that answer three ways:

  * as an inventory: which topics exist, which of them are internal, how many
    partitions and replicas each one has, and which are unhealthy;
  * as a configuration leak: with DescribeConfigs it asks for the broker and
    topic settings that shape how much data exists and how long it is kept
    (retention, segment size, min.insync.replicas, cleanup policy, auto-create);
  * as an authorization boundary: by naming topics one at a time it observes
    which names the caller is allowed to see, and by asking for a name the
    cluster cannot host (with allow_auto_topic_creation forced to false) it
    measures whether a refusal is an authorization error or an existence error.

The last distinction is the point of the report. An unauthenticated caller that
can enumerate topics learns the shape of the business; a caller that can also
read the configuration learns how much of it is in flight, how long it is kept
and whether anything enforces durability. Both are read-only observations and
nothing here writes to the cluster.

Topic names themselves are analysed against a pattern set for payment, identity,
health, human-resources and credential material, because a leaked topic list is
a leaked list of the systems that matter.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-metadata-topic-leak <target>
-- nmap -p 9092 --script kafka-metadata-topic-leak --script-args kafka.topics=orders,payments,kafka.verbose=true <target>
--
-- @args kafka.timeout        Per-request timeout in milliseconds
--                            (default 5000, range 500-60000).
-- @args kafka.client-id      Client id used in every request header
--                            (default "nmap-kafka-metadata-audit").
-- @args kafka.topics         Comma separated topic names to request by name in
--                            addition to the full listing. Default: the first
--                            ten topics the full listing returned.
-- @args kafka.max-topics     Maximum topics carried into the report
--                            (default 200, range 1-2000).
-- @args kafka.configs        "true" (default) reads broker and topic
--                            configurations with DescribeConfigs.
-- @args kafka.max-configs    Maximum configuration rows printed per resource
--                            (default 20, range 1-200).
-- @args kafka.unknown-topic-probe
--                            "true" asks the cluster about one name that cannot
--                            exist, with allow_auto_topic_creation set to
--                            false, to tell an authorization refusal apart from
--                            an existence error. Default: true. The probe never
--                            asks the broker to create anything.
-- @args kafka.patterns       Comma separated extra name patterns to look for in
--                            topic names (default: a built-in sensitive set).
-- @args kafka.verbose        "true" adds the per-stage transcript.
--
-- @output
-- 9092/tcp open  kafka
-- | kafka-metadata-topic-leak:
-- |   Cluster: nse-mock-cluster, controller node 1, 3 brokers
-- |   Topics visible without authentication: 12 (2 internal)
-- |   payments-eu: 24 partitions, replication 3, ISR 2/3 (under-replicated)
-- |   Configuration read: retention.ms=604800000, min.insync.replicas=1
-- |   Sensitive names: payments-eu (payment), customer-pii (identity)
-- |_  Risk Level: CRITICAL
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

local SCRIPT_RISK = "CRITICAL"
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

local function split_list(raw, limit)
  if raw == nil or raw == "" then return nil end
  local out = {}
  for piece in string.gmatch(raw, "[^,%s]+") do
    if limit and #out >= limit then break end
    out[#out + 1] = piece
  end
  return #out > 0 and out or nil
end

local function read_config()
  local cfg = {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000),
    client_id = arg_string("kafka.client-id", "nmap-kafka-metadata-audit", 120),
    topics = split_list(arg_string("kafka.topics", nil, 4000), 200),
    max_topics = arg_number("kafka.max-topics", 200, 1, 2000),
    configs = arg_bool("kafka.configs", true),
    max_configs = arg_number("kafka.max-configs", 20, 1, 200),
    unknown_probe = arg_bool("kafka.unknown-topic-probe", true),
    patterns = split_list(arg_string("kafka.patterns", nil, 600)),
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

-- A sorted list of the keys of a map, so two runs of the script print the same
-- report in the same order.
local function sorted_keys(map)
  local keys = {}
  for key in pairs(map or {}) do keys[#keys + 1] = key end
  table.sort(keys)
  return keys
end

-- Topic ids arrive as sixteen raw bytes. They are rendered here rather than by
-- the engine's numeric helper, which takes a number and not a byte string.
local HEX_DIGITS = "0123456789abcdef"

local function hex_bytes(text)
  if not text or #text == 0 then return "-" end
  local out = {}
  for index = 1, #text do
    local b = string.byte(text, index)
    local hi = math.floor(b / 16) % 16 + 1
    local lo = b % 16 + 1
    out[#out + 1] = string.sub(HEX_DIGITS, hi, hi) .. string.sub(HEX_DIGITS, lo, lo)
  end
  return table.concat(out)
end

local function count_of(map)
  local total = 0
  for _ in pairs(map or {}) do total = total + 1 end
  return total
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

  -- Every request goes through here, so a transient broker-side error is
  -- retried once and a permanent one is reported with its name.
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
-- 4. Probes
----------------------------------------------------------------------------
--
-- Each probe keeps two things apart: what the broker answered, and whether the
-- caller was allowed to ask. A refusal is a result, not a failure, and the
-- report is explicit about which of the two it is looking at.

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
  for _, entry in ipairs({ { 3, "metadata" }, { 32, "describe_configs" }, { 60, "describe_cluster" },
    { 16, "list_groups" }, { 19, "create_topics" }, { 20, "delete_topics" }, { 36, "sasl_handshake" } }) do
    local record = versions[entry[1]]
    if record then out[entry[2] .. "_version"] = record.broker_max end
  end
  return out
end

-- The full listing: a null topic array is the protocol's "everything" wildcard
-- from Metadata v1 onwards, and the request asks for the two authorized
-- operation masks so the report can say whether the caller was even told what
-- it may do.
function probe.metadata_all(w)
  local result = w:call("metadata_all", function()
    return kafka.metadata(w.connection, nil, {
      auto_create = false, cluster_authorized_operations = true,
      topic_authorized_operations = true,
    })
  end)
  if not result or not result.ok then
    return { stage = "metadata_all", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = {
    stage = "metadata_all", answered = true, version = result.version,
    flexible = result.flexible, topics = result.topics or {}, brokers = result.brokers or {},
    cluster_id = result.cluster_id, controller_id = result.controller_id,
    throttle_ms = result.throttle_ms, error_code = result.error_code,
    error_name = result.error_name,
    cluster_authorized_operations = result.cluster_authorized_operations,
    trailing_bytes = result.trailing_bytes,
    requested = "all",
  }
  local with_data, errors = 0, 0
  for _, topic in ipairs(out.topics) do
    if topic.error_code and topic.error_code ~= 0 then errors = errors + 1 else with_data = with_data + 1 end
  end
  out.topics_with_data, out.topics_with_error = with_data, errors
  -- A negative cluster mask is the broker's way of saying it did not compute
  -- the authorized-operation set, which is what an authorizer that filters the
  -- listing returns to a principal it does not trust.
  local mask = out.cluster_authorized_operations
  out.mask_withheld = mask ~= nil and (mask < 0 or mask >= 2147483648)
  if with_data > 0 then
    out.access = "granted"
  elseif errors > 0 or kafka.is_authz_error(out.error_code) then
    out.access = "denied"
  elseif out.mask_withheld then
    out.access = "filtered"
  else
    out.access = "empty"
  end
  return out
end

-- Naming topics one at a time is how the script observes the per-topic
-- authorization boundary: a name that is listed in the full response but comes
-- back as TOPIC_AUTHORIZATION_FAILED when named individually tells the caller
-- that an ACL exists on that topic and that the caller is not on it.
function probe.metadata_by_name(w, names)
  if not names or #names == 0 then
    return { stage = "metadata_by_name", answered = true, skipped = "no topic name was selected", topics = {} }
  end
  local result = w:call("metadata_by_name", function()
    return kafka.metadata(w.connection, names, {
      auto_create = false, cluster_authorized_operations = false,
      topic_authorized_operations = true,
    })
  end)
  if not result or not result.ok then
    return { stage = "metadata_by_name", answered = false, requested = names,
      error = result and result.error or "no response", version = result and result.version, topics = {} }
  end
  local out = {
    stage = "metadata_by_name", answered = true, version = result.version,
    requested = names, topics = result.topics or {},
    cluster_id = result.cluster_id, controller_id = result.controller_id,
    brokers = result.brokers or {},
  }
  local granted, denied = 0, 0
  for _, topic in ipairs(out.topics) do
    if topic.error_code == 0 then granted = granted + 1
    elseif kafka.is_authz_error(topic.error_code) then denied = denied + 1 end
  end
  out.granted, out.denied = granted, denied
  out.access = granted > 0 and "granted" or (denied > 0 and "denied" or "error")
  return out
end

-- One name the cluster cannot possibly host, requested with the protocol's own
-- "do not create anything" flag. The error code that comes back separates three
-- very different clusters:
--   UNKNOWN_TOPIC_OR_PARTITION (3) -> the caller may ask, the name does not exist
--   TOPIC_AUTHORIZATION_FAILED (29) -> authorization happens before existence,
--                                      so the caller learned nothing about the
--                                      name but everything about the ACL model
--   INVALID_TOPIC_EXCEPTION (17) -> the name is rejected before either check
-- A topic that appears at all despite allow_auto_topic_creation=false is a
-- broker that ignores the flag, which is reported on its own.
local function probe_name()
  local seed = os.time() % 1000000
  return string.format("nmap-metadata-probe-%d-%d", seed, math.random(1000, 9999))
end

function probe.metadata_unknown(w)
  local name = probe_name()
  local result = w:call("metadata_unknown", function()
    return kafka.metadata(w.connection, { name }, {
      auto_create = false, cluster_authorized_operations = false,
      topic_authorized_operations = false,
    })
  end)
  if not result or not result.ok then
    return { stage = "metadata_unknown", answered = false, requested = name,
      error = result and result.error or "no response", version = result and result.version }
  end
  local entry = (result.topics or {})[1]
  local out = {
    stage = "metadata_unknown", answered = true, version = result.version, requested = name,
    error_code = entry and entry.error_code, error_name = entry and entry.error_name,
    partitions = entry and #(entry.partitions or {}) or 0,
    materialised = entry ~= nil and entry.error_code == 0,
  }
  if out.materialised then
    out.access = "created"
  elseif kafka.is_authz_error(out.error_code) then
    out.access = "denied"
  else
    out.access = "answered"
  end
  return out
end

function probe.describe_cluster(w)
  local result = w:call("describe_cluster", function()
    return kafka.describe_cluster(w.connection, { include_authorized_operations = true, endpoint_type = 1 })
  end)
  if not result or not result.ok then
    return { stage = "describe_cluster", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = {
    stage = "describe_cluster", answered = true, version = result.version,
    error_code = result.error_code, error_name = result.error_name,
    cluster_id = result.cluster_id, controller_id = result.controller_id,
    endpoint_type = result.endpoint_type, brokers = result.brokers,
    cluster_authorized_operations = result.cluster_authorized_operations,
  }
  out.access = (result.error_code == 0) and "granted" or "denied"
  return out
end

-- DescribeConfigs takes a list of resources: the script asks for the broker
-- itself and for a bounded number of topics. Broker-level settings are the ones
-- that reveal how much data can exist at once; topic-level settings are the ones
-- that reveal how long it is kept and how durable it has to be.
function probe.describe_configs(w, broker_ids, topic_names)
  local resources = {}
  for _, broker_id in ipairs(broker_ids or {}) do
    resources[#resources + 1] = { type = 4, name = num_text(broker_id) }
  end
  local capped = 0
  for _, name in ipairs(topic_names or {}) do
    if capped >= probe.MAX_CONFIG_TOPICS then break end
    resources[#resources + 1] = { type = 2, name = name }
    capped = capped + 1
  end
  if #resources == 0 then
    return { stage = "describe_configs", answered = true, skipped = "no resource to ask about", results = {} }
  end
  local result = w:call("describe_configs", function()
    return kafka.describe_configs(w.connection, resources, { include_synonyms = true })
  end)
  if not result or not result.ok then
    return { stage = "describe_configs", answered = false, requested = #resources,
      error = result and result.error or "no response", version = result and result.version, results = {} }
  end
  local out = {
    stage = "describe_configs", answered = true, version = result.version,
    results = result.results or {}, requested = #resources, throttle_ms = result.throttle_ms,
  }
  local granted, denied, rows = 0, 0, 0
  for _, resource in ipairs(out.results) do
    if resource.error_code == 0 then
      granted = granted + 1
      rows = rows + #(resource.configs or {})
    elseif kafka.is_authz_error(resource.error_code) then
      denied = denied + 1
    end
  end
  out.resources_answered, out.resources_denied, out.config_rows = granted, denied, rows
  out.access = granted > 0 and "granted" or (denied > 0 and "denied" or "error")
  return out
end

-- The group count is not the subject of this script, but the offsets topic is
-- an internal topic like any other and its partition count is a broker setting
-- published to anyone who asks, so the corollary is worth stating exactly once.
function probe.list_groups(w)
  local result = w:call("list_groups", function()
    return kafka.list_groups(w.connection)
  end)
  if not result or not result.ok then
    return { stage = "list_groups", answered = false, groups = {},
      error = result and result.error or "no response", version = result and result.version }
  end
  return {
    stage = "list_groups", answered = true, version = result.version, groups = result.groups or {},
    error_code = result.error_code, error_name = result.error_name,
    access = #(result.groups or {}) > 0 and "granted"
      or ((result.error_code and result.error_code ~= 0) and "denied" or "empty"),
  }
end

probe.MAX_CONFIG_TOPICS = 20


----------------------------------------------------------------------------
-- 5. Analysis
----------------------------------------------------------------------------

local analysis = {}

-- Kafka's AclOperation enum, as the bitmask Metadata returns. The mask is not a
-- capability the caller holds: it is the set of operations that *could* be
-- granted on the resource, which is why the report prints it as an attribute of
-- the topic and never as a permission of the scanner.
local ACL_OPS = {
  { code = 1, name = "ANY" }, { code = 2, name = "ALL" }, { code = 3, name = "READ" },
  { code = 4, name = "WRITE" }, { code = 5, name = "CREATE" }, { code = 6, name = "DELETE" },
  { code = 7, name = "ALTER" }, { code = 8, name = "DESCRIBE" }, { code = 9, name = "CLUSTER_ACTION" },
  { code = 10, name = "DESCRIBE_CONFIGS" }, { code = 11, name = "ALTER_CONFIGS" },
  { code = 12, name = "IDEMPOTENT_WRITE" }, { code = 13, name = "CREATE_TOKENS" },
  { code = 14, name = "DESCRIBE_TOKENS" },
}

function analysis.ops_text(mask)
  if mask == nil then return "not returned by this broker version" end
  if mask >= 2147483648 then mask = mask - 4294967296 end
  if mask < 0 then return "not computed (the broker withheld the mask)" end
  local names = {}
  for _, op in ipairs(ACL_OPS) do
    local weighted = 2 ^ op.code
    if math.floor((mask / weighted) % 2) == 1 then names[#names + 1] = op.name end
  end
  if #names == 0 then return "none" end
  return fmt_list(names, 10)
end

-- The health of a topic is three separate numbers, and they mean different
-- things: an in-sync set smaller than the replica set is a durability problem,
-- an offline replica is a capacity problem, and an empty in-sync set is an
-- outage.
function analysis.partition_health(topic)
  local row = { partitions = 0, under_replicated = 0, offline = 0, no_leader = 0,
    empty_isr = 0, replication_min = nil, replication_max = nil, isr_min = nil, leaders = {},
    leader_epochs = {}, bad_partitions = {} }
  for _, partition in ipairs(topic.partitions or {}) do
    row.partitions = row.partitions + 1
    local replicas = #(partition.replicas or {})
    local isr = #(partition.isr or {})
    local offline = #(partition.offline_replicas or {})
    row.replication_min = (row.replication_min == nil) and replicas or math.min(row.replication_min, replicas)
    row.replication_max = (row.replication_max == nil) and replicas or math.max(row.replication_max, replicas)
    row.isr_min = (row.isr_min == nil) and isr or math.min(row.isr_min, isr)
    if isr < replicas then row.under_replicated = row.under_replicated + 1 end
    if offline > 0 then row.offline = row.offline + 1 end
    if isr == 0 then row.empty_isr = row.empty_isr + 1 end
    if partition.leader_id == nil or partition.leader_id < 0 then
      row.no_leader = row.no_leader + 1
    else
      row.leaders[partition.leader_id] = (row.leaders[partition.leader_id] or 0) + 1
    end
    if partition.leader_epoch and partition.leader_epoch >= 0 then
      row.leader_epochs[partition.leader_epoch] = true
    end
    if isr < replicas or offline > 0 or isr == 0 then
      row.bad_partitions[#row.bad_partitions + 1] = string.format("%s/%s (replicas %s, isr %s, offline %s)",
        tostring(topic.name), num_text(partition.index), fmt_list(partition.replicas, 6),
        fmt_list(partition.isr, 6), fmt_list(partition.offline_replicas, 6))
    end
  end
  return row
end

local INTERNAL_NOTES = {
  ["__consumer_offsets"] = "the partition count of this topic is the cluster's group-coordinator count "
    .. "(offsets.topic.num.partitions), and its partitions are the brokers that coordinate consumer groups",
  ["__transaction_state"] = "its partition count is transaction.state.log.num.partitions, and its presence "
    .. "says the cluster runs transactional producers",
  ["__cluster_metadata"] = "a KRaft metadata log: this cluster is running without ZooKeeper",
  ["_schemas"] = "the Confluent Schema Registry store: its content is the schema history of every topic",
  ["connect-configs"] = "Kafka Connect configuration store: connector settings, including credentials",
  ["connect-offsets"] = "Kafka Connect offset store: the position of every connector source",
  ["connect-status"] = "Kafka Connect status store: which connectors are running",
  ["__debezium-heartbeat"] = "a Debezium heartbeat topic: a change-data-capture pipeline is in place",
  ["__amazon_msk_canary"] = "the MSK broker canary: the cluster runs on Amazon MSK",
  ["__redhat_rhbk"] = "a Red Hat build of Kafka management topic",
}

local INTERNAL_PREFIXES = {
  { prefix = "__", note = "reserved for internal topics on most distributions" },
  { prefix = "_", note = "single-underscore names are used by the tooling around Kafka" },
}

local SENSITIVE_PATTERNS = {
  { token = "payment", category = "payment" }, { token = "billing", category = "payment" },
  { token = "invoice", category = "payment" }, { token = "card", category = "payment" },
  { token = "pan", category = "payment" }, { token = "iban", category = "payment" },
  { token = "customer", category = "identity" }, { token = "user", category = "identity" },
  { token = "account", category = "identity" }, { token = "pii", category = "identity" },
  { token = "profile", category = "identity" }, { token = "gdpr", category = "identity" },
  { token = "health", category = "health" }, { token = "patient", category = "health" },
  { token = "medical", category = "health" }, { token = "clinic", category = "health" },
  { token = "hr", category = "human-resources" }, { token = "salary", category = "human-resources" },
  { token = "payroll", category = "human-resources" }, { token = "employee", category = "human-resources" },
  { token = "auth", category = "credentials" }, { token = "token", category = "credentials" },
  { token = "secret", category = "credentials" }, { token = "credential", category = "credentials" },
  { token = "session", category = "credentials" }, { token = "otp", category = "credentials" },
  { token = "audit", category = "audit" }, { token = "security", category = "audit" },
  { token = "compliance", category = "audit" }, { token = "fraud", category = "audit" },
}

local ENVIRONMENT_MARKERS = {
  { token = "prod", note = "production" }, { token = "prd", note = "production" },
  { token = "staging", note = "staging" }, { token = "stage", note = "staging" },
  { token = "uat", note = "user acceptance testing" }, { token = "preprod", note = "pre-production" },
  { token = "dev", note = "development" }, { token = "test", note = "testing" },
  { token = "sandbox", note = "sandbox" },
}

function analysis.inventory(records, cfg)
  local metadata = records.metadata_all or {}
  local topics = metadata.topics or {}
  local out = {
    rows = {}, listed = 0, shown = 0, internal = 0, user = 0, with_error = 0,
    partitions = 0, replicas = 0, replication_histogram = {}, leader_load = {},
    topic_ids = {}, epochs = {}, unhealthy = {}, truncated = false,
    under_replicated = 0, offline = 0, empty_isr = 0, no_leader = 0,
  }
  for index, topic in ipairs(topics) do
    out.listed = out.listed + 1
    if topic.error_code and topic.error_code ~= 0 then
      out.with_error = out.with_error + 1
    end
    if index > cfg.max_topics then
      out.truncated = true
    else
      local health = analysis.partition_health(topic)
      local row = {
        name = topic.name, is_internal = topic.is_internal,
        error_code = topic.error_code, error_name = topic.error_name,
        partition_count = health.partitions, replication_min = health.replication_min,
        replication_max = health.replication_max, isr_min = health.isr_min,
        under_replicated = health.under_replicated, offline = health.offline,
        empty_isr = health.empty_isr, no_leader = health.no_leader,
        leaders = health.leaders, leader_epochs = health.leader_epochs,
        topic_id = topic.topic_id, authorized_operations = topic.authorized_operations,
        bad_partitions = health.bad_partitions, health = health,
        internal_note = topic.is_internal and INTERNAL_NOTES[topic.name] or nil,
      }
      if topic.topic_id and #topic.topic_id > 0 then
        out.topic_ids[hex_bytes(topic.topic_id)] = topic.name
      end
      for epoch in pairs(health.leader_epochs or {}) do out.epochs[epoch] = true end
      for leader, count in pairs(health.leaders or {}) do
        out.leader_load[leader] = (out.leader_load[leader] or 0) + count
      end
      out.partitions = out.partitions + health.partitions
      if row.replication_max then
        out.replicas = out.replicas + (row.replication_max * health.partitions)
        local key = num_text(row.replication_max)
        out.replication_histogram[key] = (out.replication_histogram[key] or 0) + health.partitions
      end
      out.under_replicated = out.under_replicated + health.under_replicated
      out.offline = out.offline + health.offline
      out.empty_isr = out.empty_isr + health.empty_isr
      out.no_leader = out.no_leader + health.no_leader
      if topic.is_internal then out.internal = out.internal + 1 else out.user = out.user + 1 end
      if health.bad_partitions[1] or (topic.error_code and topic.error_code ~= 0) then
        out.unhealthy[#out.unhealthy + 1] = row
      end
      out.rows[#out.rows + 1] = row
      out.shown = out.shown + 1
    end
  end
  out.brokers = metadata.brokers or {}
  out.cluster_id = metadata.cluster_id
  out.controller_id = metadata.controller_id
  out.racks = {}
  for _, broker in ipairs(out.brokers) do
    if broker.rack then out.racks[broker.rack] = (out.racks[broker.rack] or 0) + 1 end
  end
  return out
end

-- The naming analysis works on the exact strings the broker returned: a topic
-- name is chosen by whoever created the topic, and it is the only part of the
-- metadata that describes the business rather than the deployment.
function analysis.naming(inventory, cfg)
  local patterns = {}
  for _, entry in ipairs(SENSITIVE_PATTERNS) do patterns[#patterns + 1] = entry end
  for _, token in ipairs(cfg.patterns or {}) do
    patterns[#patterns + 1] = { token = token, category = "operator-supplied" }
  end
  local out = { matches = {}, categories = {}, environments = {}, internal_by_prefix = {} }
  for _, row in ipairs(inventory.rows or {}) do
    local lower = string.lower(row.name or "")
    for _, entry in ipairs(patterns) do
      if lower:find(entry.token, 1, true) then
        out.matches[#out.matches + 1] = {
          topic = row.name, token = entry.token, category = entry.category,
          partitions = row.partition_count, internal = row.is_internal,
        }
        out.categories[entry.category] = (out.categories[entry.category] or 0) + 1
        break
      end
    end
    for _, entry in ipairs(ENVIRONMENT_MARKERS) do
      if lower:find(entry.token, 1, true) then
        out.environments[row.name] = entry.note
        break
      end
    end
    for _, entry in ipairs(INTERNAL_PREFIXES) do
      if string.sub(lower, 1, #entry.prefix) == entry.prefix then
        out.internal_by_prefix[entry.prefix] = out.internal_by_prefix[entry.prefix] or { topics = {}, note = entry.note }
        out.internal_by_prefix[entry.prefix].topics[#out.internal_by_prefix[entry.prefix].topics + 1] = row.name
        break
      end
    end
  end
  return out
end

-- Configuration rows are interpreted, not merely printed: a retention of seven
-- days on a topic with twenty-four partitions is a statement about how much
-- data the cluster is expected to hold, and min.insync.replicas=1 on a topic
-- with replication factor three is a statement about what happens when a
-- broker dies.
local CAPACITY_KEYS = {
  { name = "retention.ms", kind = "duration",
    meaning = "how long a record stays readable after it is written" },
  { name = "retention.bytes", kind = "bytes", meaning = "how much data a partition may hold" },
  { name = "segment.bytes", kind = "bytes", meaning = "the size of one log segment" },
  { name = "segment.ms", kind = "duration", meaning = "how often a segment is rolled" },
  { name = "cleanup.policy", kind = "text", meaning = "whether records are deleted or compacted" },
  { name = "min.insync.replicas", kind = "count",
    meaning = "how many replicas must acknowledge a write when the producer asks for acks=all" },
  { name = "max.message.bytes", kind = "bytes", meaning = "the largest record the broker accepts" },
  { name = "unclean.leader.election.enable", kind = "flag",
    meaning = "whether an out-of-sync replica may become leader and lose data" },
  { name = "compression.type", kind = "text", meaning = "the effective compression of the log" },
  { name = "message.timestamp.type", kind = "text", meaning = "whether the broker or the producer stamps time" },
  { name = "auto.create.topics.enable", kind = "flag",
    meaning = "whether naming a topic that does not exist creates it" },
  { name = "num.partitions", kind = "count", meaning = "the partition count of an auto-created topic" },
  { name = "default.replication.factor", kind = "count",
    meaning = "the replication factor of an auto-created topic" },
  { name = "offsets.topic.num.partitions", kind = "count",
    meaning = "the partition count of __consumer_offsets, which is the group-coordinator count" },
  { name = "transaction.state.log.num.partitions", kind = "count",
    meaning = "the partition count of __transaction_state" },
  { name = "log.dirs", kind = "text", meaning = "the filesystem layout of the broker" },
  { name = "listeners", kind = "text", meaning = "the endpoints the broker binds" },
  { name = "advertised.listeners", kind = "text", meaning = "the endpoints the broker hands to clients" },
  { name = "authorizer.class.name", kind = "text",
    meaning = "which authorizer, if any, is loaded on this broker" },
  { name = "ssl.client.auth", kind = "text", meaning = "whether clients must present a certificate" },
}

local CAPACITY_INDEX = {}
for _, entry in ipairs(CAPACITY_KEYS) do CAPACITY_INDEX[entry.name] = entry end

local function human_bytes(value)
  local number = tonumber(value)
  if not number or number < 0 then return tostring(value) end
  local units = { { "TiB", 1099511627776 }, { "GiB", 1073741824 }, { "MiB", 1048576 }, { "KiB", 1024 } }
  for _, unit in ipairs(units) do
    if number >= unit[2] then return string.format("%.1f %s", number / unit[2], unit[1]) end
  end
  return num_text(number) .. " B"
end

local function human_duration(value)
  local number = tonumber(value)
  if not number or number < 0 then return tostring(value) end
  if number == 0 then return "no expiry" end
  local units = { { "d", 86400000 }, { "h", 3600000 }, { "m", 60000 }, { "s", 1000 } }
  for _, unit in ipairs(units) do
    if number >= unit[2] and number % unit[2] == 0 then
      return string.format("%d%s", number / unit[2], unit[1])
    end
  end
  return num_text(number) .. "ms"
end

function analysis.capacity(records, cfg)
  local describe = records.describe_configs or {}
  local out = {
    resources = {}, broker = {}, topics = {}, sensitive = {}, notable = {},
    answered = describe.answered, version = describe.version, rows = describe.config_rows or 0,
    resources_answered = describe.resources_answered or 0,
    resources_denied = describe.resources_denied or 0, skipped = describe.skipped,
    error = describe.error,
  }
  for _, resource in ipairs(describe.results or {}) do
    local entry = {
      name = resource.resource_name, type = resource.resource_type,
      error_code = resource.error_code, error_name = resource.error_name,
      configs = resource.configs or {},
    }
    out.resources[#out.resources + 1] = entry
    local bucket = (resource.resource_type_code == 4) and out.broker or out.topics
    for _, config in ipairs(entry.configs) do
      local value = config.value
      local rendered = value
      if value ~= nil then
        local meta = CAPACITY_INDEX[config.name]
        if meta and meta.kind == "bytes" then rendered = human_bytes(value)
        elseif meta and meta.kind == "duration" then rendered = human_duration(value) end
      end
      local row = {
        resource = entry.name, resource_type = entry.type, name = config.name, value = value,
        rendered = rendered, source = config.source, source_code = config.source_code,
        read_only = config.read_only, is_sensitive = config.is_sensitive,
        secret_bearing = config.secret_bearing, documentation = config.documentation,
        synonyms = config.synonyms,
      }
      local meta = CAPACITY_INDEX[config.name]
      if meta then row.meaning = meta.meaning end
      -- A value that came from a dynamic source was set by an operator; a value
      -- from DEFAULT_CONFIG is Kafka's own default.
      row.operator_set = config.source == "DYNAMIC_TOPIC_CONFIG" or config.source == "DYNAMIC_BROKER_CONFIG"
        or config.source == "DYNAMIC_DEFAULT_BROKER_CONFIG" or config.source == "STATIC_BROKER_CONFIG"
      if row.is_sensitive or (config.secret_bearing and not row.read_only) then
        row.redacted = true
        out.sensitive[#out.sensitive + 1] = row
      end
      if meta or row.operator_set or row.is_sensitive then
        bucket[#bucket + 1] = row
      end
      out.notable[#out.notable + 1] = row
    end
  end
  -- The two derived numbers the findings quote: how many partitions the cluster
  -- reports in total, and whether anything enforces durability.
  out.insync_values = {}
  for _, row in ipairs(out.notable) do
    if row.name == "min.insync.replicas" then out.insync_values[#out.insync_values + 1] = row end
  end
  out.auto_create = nil
  for _, row in ipairs(out.notable) do
    if row.name == "auto.create.topics.enable" then out.auto_create = row.value end
    if row.name == "num.partitions" then out.num_partitions = row.value end
    if row.name == "default.replication.factor" then out.default_replication_factor = row.value end
    if row.name == "authorizer.class.name" then out.authorizer = row.value end
    if row.name == "ssl.client.auth" then out.client_auth = row.value end
  end
  return out
end

-- The authorization boundary: what the caller saw when it asked for everything,
-- and what it saw when it asked for one name at a time.
function analysis.boundary(records, inventory)
  local by_name = records.metadata_by_name or {}
  local out = { listed = {}, refused_by_name = {}, hidden_by_name = {}, masks = {},
    inconsistent = false, listed_but_refused = 0, unlisted_but_described = 0, denied_by_name = {} }
  for _, row in ipairs(inventory.rows or {}) do
    out.listed[row.name] = true
    if row.authorized_operations ~= nil then
      out.masks[#out.masks + 1] = { name = row.name, mask = row.authorized_operations,
        text = analysis.ops_text(row.authorized_operations) }
    end
  end
  for _, topic in ipairs(by_name.topics or {}) do
    if topic.error_code and topic.error_code ~= 0 then
      if kafka.is_authz_error(topic.error_code) then
        out.denied_by_name[#out.denied_by_name + 1] = { name = topic.name,
          error_name = topic.error_name, listed = out.listed[topic.name] == true }
      end
      if out.listed[topic.name] then
        out.listed_but_refused = out.listed_but_refused + 1
        out.refused_by_name[#out.refused_by_name + 1] = string.format("%s (%s)", tostring(topic.name),
          tostring(topic.error_name))
      end
      out.inconsistent = true
    elseif not out.listed[topic.name] then
      out.unlisted_but_described = out.unlisted_but_described + 1
      out.hidden_by_name[#out.hidden_by_name + 1] = topic.name
    elseif topic.authorized_operations ~= nil then
      out.masks[#out.masks + 1] = { name = topic.name, mask = topic.authorized_operations,
        text = analysis.ops_text(topic.authorized_operations), source = "named request" }
    end
  end
  return out
end

function analysis.exposure(records)
  local rows = {}
  local function add(name, record, detail)
    if not record then return end
    rows[#rows + 1] = {
      name = name, access = record.answered == false and "unanswered" or (record.access or "unknown"),
      version = record.version, detail = detail, error_name = record.error_name,
      record = record,
    }
  end
  local metadata = records.metadata_all or {}
  add("ApiVersions", records.negotiate, records.negotiate and records.negotiate.answered
    and plural(records.negotiate.api_count or 0, "API") or nil)
  add("Metadata (all topics)", metadata, metadata.answered
    and (plural(metadata.topics_with_data or 0, "topic") .. " with data") or nil)
  add("Metadata (by name)", records.metadata_by_name, records.metadata_by_name and records.metadata_by_name.answered
    and (records.metadata_by_name.skipped or (plural(records.metadata_by_name.granted or 0, "topic") .. " granted"))
    or nil)
  add("Metadata (unknown name)", records.metadata_unknown, records.metadata_unknown and records.metadata_unknown.answered
    and (tostring(records.metadata_unknown.error_name) .. " for a name that cannot exist") or nil)
  add("DescribeCluster", records.describe_cluster, records.describe_cluster and records.describe_cluster.answered
    and ("cluster id " .. tostring(records.describe_cluster.cluster_id or "withheld")) or nil)
  add("DescribeConfigs", records.describe_configs, records.describe_configs and records.describe_configs.answered
    and (records.describe_configs.skipped or plural(records.describe_configs.config_rows or 0, "configuration value"))
    or nil)
  add("ListGroups", records.list_groups, records.list_groups and records.list_groups.answered
    and plural(#((records.list_groups or {}).groups or {}), "group") or nil)
  -- An empty listing is ambiguous on its own: a cluster with no topics and a
  -- cluster that filtered every topic away both answer nothing. The second
  -- DescribeCluster answer disambiguates it, because an authorizer that filters
  -- Metadata also refuses the cluster-level read.
  local metadata = records.metadata_all or {}
  local cluster = records.describe_cluster or {}
  if metadata.answered and (metadata.access == "empty" or metadata.access == "filtered")
    and cluster.access == "denied" then
    local filtered = true
    for _, row in ipairs(rows) do
      if row.name == "Metadata (all topics)" then row.access = "filtered" row.filtered = filtered end
    end
  end
  local granted, denied, unanswered = 0, 0, 0
  for _, row in ipairs(rows) do
    if row.access == "granted" or row.access == "answered" then granted = granted + 1
    elseif row.access == "denied" or row.access == "error" then denied = denied + 1
    elseif row.access == "unanswered" then unanswered = unanswered + 1 end
  end
  return { rows = rows, granted = granted, denied = denied, unanswered = unanswered }
end


----------------------------------------------------------------------------
-- 6. Knowledge base
----------------------------------------------------------------------------

local KB = {}

KB.REMEDIATION = {
  {
    step = "Require authentication on every client listener: set 'listener.name.<LISTENER>.sasl.enabled.mechanisms' "
      .. "and 'listener.name.<LISTENER>.plain.sasl.jaas.config' (or the SCRAM/Kerberos equivalent) so a client "
      .. "must authenticate before KafkaApis handles Metadata.",
    why = "Metadata is answered before any authorization check runs, so it is the SASL exchange and not the "
      .. "ACL that decides whether an unauthenticated caller sees the topic list at all.",
  },
  {
    step = "Attach ACLs to the topics that must stay invisible: "
      .. "'kafka-acls.sh --add --allow-principal User:<svc> --operation Read --topic <name>' and, just as "
      .. "important, grant DESCRIBE only where it is needed, because a caller without DESCRIBE on a topic is "
      .. "not supposed to see it in a listing either.",
    why = "Metadata listing is filtered by DESCRIBE permission on the topic resource; a cluster with no ACLs "
      .. "publishes every topic to every principal, and a cluster with ACLs on the wrong resource publishes "
      .. "them anyway.",
  },
  {
    step = "Disable anonymous access for admin APIs by removing 'allow.everyone.if.no.acl.found=true' (the "
      .. "default is false on brokers with an authorizer loaded, and true in many hand-written configurations) "
      .. "and by setting 'authorizer.class.name' explicitly.",
    why = "The setting decides what an ACL-less request means: with it true, a request nobody wrote an ACL for "
      .. "is allowed, which is exactly the state this report describes.",
  },
  {
    step = "Restrict DescribeConfigs at the broker resource: grant DESCRIBE_CONFIGS only to operators, and "
      .. "keep broker-level configuration behind a separate listener.",
    why = "Retention, message size, segment size and above all the credentials in a statically configured "
      .. "broker tell a reader how much data exists, how long it is kept and how to reach the keystore.",
  },
  {
    step = "Set 'auto.create.topics.enable=false' and 'num.partitions'/'default.replication.factor' explicitly "
      .. "so topic creation is an administrative action rather than a side effect of a client typo.",
    why = "Auto-creation turns any name a client asks about into a real topic, which both pollutes the cluster "
      .. "and hands a scanner an existence oracle.",
  },
  {
    step = "Raise durability settings where the probe found weak ones: 'min.insync.replicas=2' with "
      .. "replication factor 3, 'unclean.leader.election.enable=false', and no topic left with a single "
      .. "replica.",
    why = "The health findings are not access findings, but they are read from the same unauthenticated "
      .. "response, and a cluster that publishes an unhealthy topology to everyone is also the cluster that "
      .. "loses data when the wrong broker fails.",
  },
}

KB.VERIFICATION = {
  "kafka-topics.sh --bootstrap-server <broker> --list  (run without credentials: after the change this must "
    .. "fail with an authentication error instead of printing the topic list)",
  "kafka-configs.sh --bootstrap-server <broker> --describe --entity-type brokers --entity-name <id>  "
    .. "(compare the values this script printed with what an operator sees)",
  "kafka-acls.sh --bootstrap-server <broker> --list  (confirm that DESCRIBE is granted only where intended)",
  "grep -E 'Anonymous|authenticated' <broker server.log>  (confirm the requests are now attributed to a "
    .. "principal)",
  "kafka-topics.sh --bootstrap-server <broker> --describe --topic <name>  (confirm the partition/replica "
    .. "numbers this script reported)",
  "nmap -p 9092 --script kafka-metadata-topic-leak <target>  (the same probe, expected to report 'denied' "
    .. "rows in the access matrix)",
}

KB.METHOD_LIMITS = {
  "Metadata is answered from the broker's own metadata cache, so a topic whose creation is still propagating "
    .. "may be missing from the listing and appear on a second run.",
  "The script reads configuration but never writes it: DescribeConfigs is the only configuration API it "
    .. "calls, and no request in this script carries a write, an alter or an incremental change.",
  "DescribeConfigs is asked only for the broker resources and for at most "
    .. "kafka.max-configs topics, because the API takes a resource list and the scan should not read the "
    .. "configuration of a cluster it was pointed at once.",
  "The unknown-name probe uses one randomly generated name and always sets allow_auto_topic_creation=false, so "
    .. "on a broker that honours the flag nothing is created. A topic that appears anyway is reported, because "
    .. "it means the flag was ignored.",
  "Topic names are matched as lower-case substrings, so a name like 'panorama' matches the 'pan' pattern of the "
    .. "payment category; the match is evidence of a naming convention, not of the content of the topic.",
  "The authorized-operation mask is what the broker says could be granted on the resource. It is not the "
    .. "permission of the caller that read it, and the report says so in every row that prints it.",
  "A cluster behind a load balancer or an MSK-style endpoint answers Metadata for a subset of brokers, so the "
    .. "replica sets can name node ids that the endpoint never advertises.",
}

KB.RISK_RUBRIC = {
  { severity = "CRITICAL", condition = "the full topic listing and the cluster/ topic configuration were both "
    .. "answered without authentication, or a sensitive configuration value was returned in the clear" },
  { severity = "HIGH", condition = "the listing is readable and either internal topics, sensitive names or "
    .. "unhealthy replicas were in it" },
  { severity = "MEDIUM", condition = "the listing is readable but no configuration and no internal topic was "
    .. "exposed" },
  { severity = "LOW", condition = "only the inventory was partial, or only non-sensitive attributes leaked" },
  { severity = "INFO", condition = "the caller was refused, or nothing was answered" },
}

KB.ATTACK_VALUE = {
  { exposure = "topic inventory",
    value = "the list of business processes, one topic per pipeline, with the size of each one" },
  { exposure = "internal topic partition counts",
    value = "the group-coordinator count, whether transactions are used, and whether a schema registry or "
      .. "connector cluster is attached" },
  { exposure = "configuration values",
    value = "how much data exists (retention x partitions), how it is compressed, and which keystore the "
      .. "broker would use" },
  { exposure = "replica topology",
    value = "which hosts hold which data, and therefore which one to take down to make a partition "
      .. "unavailable" },
  { exposure = "authorization boundary",
    value = "a map of which topics are protected and which are not, since a refusal is itself information "
      .. "about the ACL model" },
}

----------------------------------------------------------------------------
-- 7. Findings
----------------------------------------------------------------------------

local findings = {}

function findings.evaluate(records, inventory, naming, capacity, boundary, exposure, cfg)
  local list = {}
  local metadata = records.metadata_all or {}

  -- 1. The listing itself.
  if metadata.answered and inventory.shown > 0 then
    local evidence = {
      string.format("topics: %d (%d internal, %d user)", inventory.shown, inventory.internal, inventory.user),
      string.format("partitions: %d, replicas: %d", inventory.partitions, inventory.replicas),
      string.format("brokers in the answer: %d, racks: %d", #(inventory.brokers or {}),
        count_of(inventory.racks)),
      string.format("topic ids returned: %d, leader epochs seen: %d", count_of(inventory.topic_ids),
        count_of(inventory.epochs)),
    }
    local severity = (#(inventory.rows) > 0) and "CRITICAL" or "MEDIUM"
    list[#list + 1] = finding("KAFKA-TOPIC-INVENTORY-DISCLOSURE",
      "The complete topic inventory is published without authentication",
      severity,
      string.format("Metadata answered a full listing to a caller that never authenticated: %s, %s and %s, "
        .. "with the leader, the replica set, the in-sync set and the offline set of every partition. The "
        .. "listing is the cluster's business model: one topic per process, and the partition count of each "
        .. "one is a measure of how much work that process does. Nothing in the answer distinguishes a "
        .. "scanner from a legitimate client.",
        plural(inventory.shown, "topic"), plural(inventory.partitions, "partition"),
        plural(inventory.replicas, "replica placement")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[2], KB.REMEDIATION[3] })
  end

  -- 2. Internal topics: each of them names a subsystem.
  local internal_rows = {}
  for _, row in ipairs(inventory.rows or {}) do
    if row.is_internal then
      internal_rows[#internal_rows + 1] = string.format("%s: %s%s", row.name,
        plural(row.partition_count, "partition"),
        row.internal_note and (" - " .. row.internal_note) or "")
    end
  end
  if #internal_rows > 0 then
    list[#list + 1] = finding("KAFKA-INTERNAL-TOPIC-EXPOSURE",
      "Internal topics are exposed with their topology",
      (metadata.answered and metadata.access == "granted") and "HIGH" or "MEDIUM",
      string.format("%s were visible. Internal topics are not data: they are the cluster's own bookkeeping, "
        .. "and their names and partition counts describe which subsystems are attached and how they are "
        .. "sized. __consumer_offsets in particular publishes the number of group coordinators, which is a "
        .. "capacity fact an attacker uses to judge how much of the cluster a group-level denial of service "
        .. "would take down.", plural(#internal_rows, "internal topic")),
      internal_rows, { KB.REMEDIATION[2], KB.REMEDIATION[3] })
  end

  -- 3. Configuration.
  if capacity.answered and (capacity.resources_answered or 0) > 0 then
    local evidence = {}
    for _, row in ipairs(capacity.notable or {}) do
      if #evidence < 12 then
        evidence[#evidence + 1] = string.format("%s[%s] %s=%s (%s)", tostring(row.resource),
          tostring(row.resource_type), tostring(row.name), tostring(row.rendered),
          tostring(row.source or "source unknown"))
      end
    end
    list[#list + 1] = finding("KAFKA-TOPIC-CONFIG-DISCLOSURE",
      "Broker and topic configuration is readable without authentication",
      "HIGH",
      string.format("DescribeConfigs answered %s over %s. The values are operational: retention says how long "
        .. "a record can be read after it was written, retention.bytes and segment.bytes say how much data a "
        .. "partition is expected to hold, min.insync.replicas says whether a write survives a broker loss, "
        .. "and the listener and log.dirs values describe the deployment itself. Together they are the "
        .. "capacity model of the cluster.",
        plural(capacity.rows or 0, "configuration value"), plural(capacity.resources_answered or 0, "resource")),
      evidence, { KB.REMEDIATION[4] })
  elseif capacity.answered and capacity.skipped then
    list[#list + 1] = finding("KAFKA-CONFIG-READ-NOT-ATTEMPTED",
      "Configuration was not read", "INFO", tostring(capacity.skipped), {}, { KB.REMEDIATION[4] })
  elseif (records.describe_configs or {}).answered == false then
    list[#list + 1] = finding("KAFKA-CONFIG-READ-DENIED",
      "DescribeConfigs was refused to the unauthenticated caller",
      "INFO",
      string.format("DescribeConfigs did not answer (%s). The API is ACL-checked for DESCRIBE_CONFIGS on "
        .. "each resource, so a refusal here while Metadata is open means the authorizer knows about the "
        .. "resource but the metadata path is not filtered the same way.",
        tostring((records.describe_configs or {}).error)), {}, { KB.REMEDIATION[2] })
  end

  -- 4. Secrets in configuration.
  if #(capacity.sensitive or {}) > 0 then
    local rows = {}
    for index = 1, math.min(#capacity.sensitive, 8) do
      local row = capacity.sensitive[index]
      local shown = row.value
      if row.value and #tostring(row.value) > 64 then shown = string.sub(tostring(row.value), 1, 61) .. "..." end
      rows[#rows + 1] = string.format("%s[%s] %s = %s", tostring(row.resource), tostring(row.resource_type),
        tostring(row.name), tostring(shown))
    end
    list[#list + 1] = finding("KAFKA-CONFIG-SECRET-DISCLOSURE",
      "A configuration value that carries a secret was returned unauthenticated",
      "CRITICAL",
      string.format("%s marked sensitive (or named like a credential) came back with its value attached to an "
        .. "unauthenticated request. Kafka marks such values 'sensitive' so that DescribeConfigs can withhold "
        .. "them; a broker that predates the flag, or a client reading a resource whose configuration was "
        .. "written into a static file, still returns them. The value itself is printed only in part, and it "
        .. "should be rotated regardless of what it turns out to be.",
        plural(#capacity.sensitive, "configuration value")),
      rows, { KB.REMEDIATION[4], KB.REMEDIATION[1] })
  end

  -- 5. Name intelligence.
  if #(naming.matches or {}) > 0 then
    local rows = {}
    for index = 1, math.min(#naming.matches, 10) do
      local match = naming.matches[index]
      rows[#rows + 1] = string.format("%s (matched '%s', category %s)", tostring(match.topic),
        tostring(match.token), tostring(match.category))
    end
    local categories = sorted_keys(naming.categories)
    list[#list + 1] = finding("KAFKA-SENSITIVE-TOPIC-NAME-DISCLOSURE",
      "Topic names describe sensitive business processes",
      "HIGH",
      string.format("The listing contains %s whose names match a sensitive pattern, in these categories: %s. "
        .. "A topic name is not data, but it is the index to the data: it says which system to look for next, "
        .. "and a scanner that only sees names has already learned which parts of the business are on this "
        .. "cluster.", plural(#naming.matches, "topic"), fmt_list(categories, 8)),
      rows, { KB.REMEDIATION[1], KB.REMEDIATION[2] })
  end

  -- 6. Replica topology.
  if metadata.answered and #(inventory.brokers or {}) > 0 then
    local broker_rows = {}
    for _, broker in ipairs(inventory.brokers) do
      broker_rows[#broker_rows + 1] = string.format("node %s at %s:%s%s", num_text(broker.node_id),
        tostring(broker.host), num_text(broker.port),
        broker.rack and (" (rack " .. tostring(broker.rack) .. ")") or "")
    end
    for _, row in ipairs(inventory.rows or {}) do
      if #broker_rows < 16 then
        broker_rows[#broker_rows + 1] = string.format("%s led by %s, replicas on %s", tostring(row.name),
          fmt_list(sorted_keys(row.leaders or {}), 6),
          fmt_list(row.health.replication_min and { string.format("%d replica(s)", row.health.replication_min) }
            or {}, 4))
      end
    end
    list[#list + 1] = finding("KAFKA-REPLICA-TOPOLOGY-DISCLOSURE",
      "Broker endpoints and replica placement are disclosed",
      "LOW",
      string.format("%s were named with their host, port and rack, and every partition carried its replica "
        .. "set. Replica placement is the map an attacker needs to make data unavailable: it says which host "
        .. "holds which partition, and with the rack assignments it also says how much of the redundancy is "
        .. "inside a single failure domain.",
        plural(#(inventory.brokers or {}), "broker")), broker_rows, { KB.REMEDIATION[1], KB.REMEDIATION[4] })
  end

  -- 7. Stable identifiers.
  if count_of(inventory.topic_ids) > 0 then
    local rows = {}
    for id, name in pairs(inventory.topic_ids) do
      if #rows < 6 then rows[#rows + 1] = string.format("%s -> %s", id, tostring(name)) end
    end
    list[#list + 1] = finding("KAFKA-TOPIC-ID-DISCLOSURE",
      "Stable topic ids are published",
      "LOW",
      string.format("%s carried a topic id. The id is what survives a rename: a caller that recorded it can "
        .. "follow a topic through a rename or a recreation, which is why brokers return it only in the newer "
        .. "Metadata versions.", plural(count_of(inventory.topic_ids), "topic")),
      rows, { KB.REMEDIATION[2] })
  end

  -- 8. The authorized-operation masks.
  if #(boundary.masks or {}) > 0 then
    local rows = {}
    for index = 1, math.min(#boundary.masks, 8) do
      local row = boundary.masks[index]
      rows[#rows + 1] = string.format("%s: %s", tostring(row.name), tostring(row.text))
    end
    list[#list + 1] = finding("KAFKA-AUTHORIZED-OPERATIONS-DISCLOSURE",
      "Per-topic authorized operation masks are disclosed",
      "LOW",
      string.format("The broker returned the operation mask of %s. The mask is the set of operations that "
        .. "could be granted on the resource, so it is a description of the ACL model rather than of the "
        .. "caller's rights - and it is only computed when a caller asks for it, which means it is published "
        .. "on request to anyone who can reach the API.",
        plural(#boundary.masks, "topic")), rows, { KB.REMEDIATION[2] })
  end

  -- 9. The listing that is not filtered by the ACL that applies to the names.
  if boundary.listed_but_refused > 0 then
    list[#list + 1] = finding("KAFKA-LISTING-NOT-FILTERED-BY-ACL",
      "Topics that are refused by name were still listed",
      "MEDIUM",
      string.format("%s appeared in the list of all topics and were refused when asked for by name. The "
        .. "listing path and the single-topic path therefore disagree: a caller learns that a topic exists, "
        .. "and only then learns that it may not look at it. The refusal is correct; the disclosure in the "
        .. "listing is not.",
        plural(boundary.listed_but_refused, "topic")),
      boundary.refused_by_name, { KB.REMEDIATION[2], KB.REMEDIATION[3] })
  end

  -- 10. The unknown-name probe.
  local unknown = records.metadata_unknown or {}
  if unknown.answered and unknown.materialised then
    list[#list + 1] = finding("KAFKA-AUTO-CREATE-FLAG-IGNORED",
      "A name the caller asked about was created despite the request flag",
      "CRITICAL",
      string.format("Metadata was called for '%s' with allow_auto_topic_creation=false, and the cluster "
        .. "answered with a real topic. The request flag exists exactly to stop this: a scanner (or a client "
        .. "with a typo) must not be able to create topics. Review auto.create.topics.enable and the "
        .. "broker's handling of the flag before treating this as anything other than an emergency.",
        tostring(unknown.requested)),
      { string.format("%s -> %s", tostring(unknown.requested), tostring(unknown.error_name)),
        string.format("partitions in the answer: %d", unknown.partitions) },
      { KB.REMEDIATION[5], KB.REMEDIATION[1] })
  elseif unknown.answered and kafka.is_authz_error(unknown.error_code) then
    list[#list + 1] = finding("KAFKA-AUTHORIZATION-PRECEDES-EXISTENCE",
      "The broker authorizes a topic name before it checks whether it exists",
      "INFO",
      string.format("Metadata for '%s' (a name that cannot exist) was refused with %s rather than reported as "
        .. "unknown. That ordering is deliberate and safe: the caller cannot tell an existing topic from a "
        .. "missing one. It is recorded here because it also means the audit learned nothing about whether "
        .. "auto-creation is enabled.",
        tostring(unknown.requested), tostring(unknown.error_name)),
      { string.format("error for an impossible name: %s", tostring(unknown.error_name)) },
      { KB.REMEDIATION[5] })
  elseif unknown.answered then
    list[#list + 1] = finding("KAFKA-TOPIC-EXISTENCE-ORACLE",
      "The broker tells an unauthenticated caller which topic names exist",
      "MEDIUM",
      string.format("Metadata for the impossible name '%s' answered %s, which is the same code the cluster "
        .. "uses for a name that simply does not exist yet. An unauthenticated caller can therefore test "
        .. "names: ask for a candidate, and the error code says whether the cluster hosts it. Combined with "
        .. "auto-creation this is how topics appear by accident.",
        tostring(unknown.requested), tostring(unknown.error_name)),
      { string.format("%s -> %s", tostring(unknown.requested), tostring(unknown.error_name)) },
      { KB.REMEDIATION[5], KB.REMEDIATION[2] })
  end

  -- 11. Durability and availability of what was disclosed.
  if inventory.under_replicated and inventory.under_replicated > 0 then
    local rows = {}
    for _, row in ipairs(inventory.unhealthy or {}) do
      if row.under_replicated > 0 and #rows < 8 then
        for index = 1, math.min(#row.bad_partitions, 3) do
          rows[#rows + 1] = row.bad_partitions[index]
        end
      end
    end
    list[#list + 1] = finding("KAFKA-UNDER-REPLICATED-PARTITIONS",
      "Under-replicated partitions are published",
      "MEDIUM",
      string.format("%s across %s have an in-sync set smaller than their replica set. An under-replicated "
        .. "partition is one broker failure away from data loss (or from being unable to elect a leader), and "
        .. "the fact is published to anyone who asks for the metadata.",
        plural(inventory.under_replicated, "partition"), plural(#(inventory.unhealthy or {}), "topic")),
      rows, { KB.REMEDIATION[6] })
  end

  local offline = 0
  local offline_rows = {}
  for _, row in ipairs(inventory.rows or {}) do
    offline = offline + (row.offline or 0)
    if row.offline > 0 then
      offline_rows[#offline_rows + 1] = string.format("%s: %s with an offline replica", tostring(row.name),
        plural(row.offline, "partition"))
    end
  end
  if offline > 0 then
    list[#list + 1] = finding("KAFKA-OFFLINE-REPLICAS-PUBLISHED",
      "Partitions with offline replicas are published",
      "HIGH",
      string.format("%s list at least one offline replica. An offline replica is data that exists on a broker "
        .. "the cluster cannot reach: the exposure is operational, and it is also the exact map of which "
        .. "host is missing and therefore which partition cannot be written with acks=all.",
        plural(offline, "partition")), offline_rows, { KB.REMEDIATION[6] })
  end

  local empty_isr, empty_rows = 0, {}
  for _, row in ipairs(inventory.rows or {}) do
    empty_isr = empty_isr + (row.empty_isr or 0)
    if row.empty_isr > 0 then
      empty_rows[#empty_rows + 1] = string.format("%s: %s with an empty in-sync set", tostring(row.name),
        plural(row.empty_isr, "partition"))
    end
  end
  if empty_isr > 0 then
    list[#list + 1] = finding("KAFKA-PARTITIONS-WITHOUT-ISR",
      "Partitions with an empty in-sync set are published",
      "HIGH",
      string.format("%s have no in-sync replica at all, which means no broker holds a complete copy: the "
        .. "partition is unavailable for writes and will be unavailable for reads until a replica comes back "
        .. "or an unclean election is allowed. The cluster is announcing its own outage in an unauthenticated "
        .. "response.", plural(empty_isr, "partition")), empty_rows, { KB.REMEDIATION[6] })
  end

  -- 12. Leader concentration: a topology observation with an availability edge.
  local worst_leader, worst_count = nil, 0
  for leader, count in pairs(inventory.leader_load or {}) do
    if count > worst_count then worst_leader, worst_count = leader, count end
  end
  if worst_leader and inventory.partitions > 0 and worst_count * 100 >= inventory.partitions * 60 then
    list[#list + 1] = finding("KAFKA-LEADER-CONCENTRATION",
      "Most partitions are led by one broker",
      "LOW",
      string.format("node %s leads %d of %d partitions (%.0f%%). Leadership is client-visible and it is what "
        .. "decides the effect of losing that broker: the replicas survive, but every client re-elects a "
        .. "leader at once, which is the storm a large cluster feels as an outage.",
        num_text(worst_leader), worst_count, inventory.partitions,
        (worst_count * 100) / inventory.partitions),
      { string.format("partition leaders by node: %s", (function()
        local parts = {}
        for _, leader in ipairs(sorted_keys(inventory.leader_load)) do
          parts[#parts + 1] = string.format("%s x%d", num_text(leader), inventory.leader_load[leader])
        end
        return table.concat(parts, ", ")
      end)()) }, { KB.REMEDIATION[6] })
  end

  -- 13. Replication factor one.
  local unreplicated = {}
  for _, row in ipairs(inventory.rows or {}) do
    if row.replication_max == 1 and not row.is_internal then
      unreplicated[#unreplicated + 1] = string.format("%s: %s at replication factor 1", tostring(row.name),
        plural(row.partition_count, "partition"))
    end
  end
  if #unreplicated > 0 then
    local single = #(inventory.brokers or {}) <= 1
    list[#list + 1] = finding("KAFKA-UNREPLICATED-TOPICS",
      "Topics are published with a single replica",
      "INFO",
      string.format("%s have replication factor 1. On a single-broker cluster that is a design choice; on a "
        .. "cluster with %s it is a durability decision, and the metadata publishes it to whoever asks.",
        plural(#unreplicated, "topic"), plural(#(inventory.brokers or {}), "broker")),
      unreplicated, single and { KB.REMEDIATION[5] } or { KB.REMEDIATION[6] })
  end

  -- 14. The settings that weaken the durability of everything above.
  for _, row in ipairs(capacity.insync_values or {}) do
    if tonumber(row.value) == 1 then
      list[#list + 1] = finding("KAFKA-MIN-INSYNC-REPLICAS-WEAK",
        "min.insync.replicas is 1",
        "MEDIUM",
        string.format("Resource %s sets min.insync.replicas=%s. With this value an acks=all write needs one "
          .. "replica to acknowledge it, so a producer that believes it is durable is not: the setting has "
          .. "to be 2 or more with a replication factor of 3 for acks=all to mean anything.",
          tostring(row.resource), tostring(row.rendered)),
        { string.format("%s: min.insync.replicas=%s (%s)", tostring(row.resource), tostring(row.value),
          tostring(row.source)) }, { KB.REMEDIATION[6] })
      break
    end
  end
  for _, row in ipairs(capacity.notable or {}) do
    if row.name == "unclean.leader.election.enable" and row.value == "true" then
      list[#list + 1] = finding("KAFKA-UNCLEAN-LEADER-ELECTION-ENABLED",
        "Unclean leader election is enabled",
        "MEDIUM",
        string.format("Resource %s sets unclean.leader.election.enable=true: an out-of-sync replica may "
          .. "become leader, which restores availability by discarding the records the in-sync set had that "
          .. "the elected replica did not. That is a deliberate trade, and it is also a setting that decides "
          .. "whether the offline-replica findings above end in data loss.",
          tostring(row.resource)),
        { string.format("%s: unclean.leader.election.enable=true", tostring(row.resource)) },
        { KB.REMEDIATION[6] })
      break
    end
  end

  if capacity.auto_create == "true" then
    list[#list + 1] = finding("KAFKA-AUTO-CREATE-ENABLED",
      "Auto topic creation is enabled",
      "MEDIUM",
      string.format("The broker reports auto.create.topics.enable=true: any client that names a topic the "
        .. "cluster does not have causes it to be created with %s and %s. That is both a resource-exhaustion "
        .. "path (a client can create topics until the cluster is full) and the reason an existence oracle "
        .. "exists at all.",
        capacity.num_partitions and (num_text(capacity.num_partitions) .. " partitions") or "the default",
        capacity.default_replication_factor
          and (num_text(capacity.default_replication_factor) .. " replica(s)") or "the default replication"),
      { "auto.create.topics.enable=true (broker configuration)" }, { KB.REMEDIATION[5] })
  end

  if exposure.granted > 0 and not (records.describe_configs or {}).answered then
    list[#list + 1] = finding("KAFKA-AUTHORIZER-MODEL-UNKNOWN",
      "The authorizer model could not be read",
      "INFO",
      string.format("%s answered without authentication while DescribeConfigs did not, so the report cannot "
        .. "say whether an authorizer is loaded. On a cluster with no authorizer the metadata path is open by "
        .. "design; on a cluster with one, the open path is a configuration error.", plural(exposure.granted, "API")),
      { "authorizer.class.name could not be read" }, { KB.REMEDIATION[3] })
  end

  local filtered_listing = false
  for _, row in ipairs(exposure.rows or {}) do
    if row.filtered then filtered_listing = true end
  end
  if metadata.answered and (metadata.access == "filtered" or filtered_listing) then
    list[#list + 1] = finding("KAFKA-METADATA-FILTERED",
      "The metadata listing was filtered down to nothing",
      "NONE",
      string.format("Metadata answered, but the broker returned no topic and withheld the cluster "
        .. "authorized-operation mask (%s). That is what an authorizer looks like from outside: the request "
        .. "is served, the principal is evaluated, and the listing is filtered to the resources it may "
        .. "describe. Nothing was disclosed on this path, and the report records the distinction because an "
        .. "empty answer from a filtered cluster and an empty answer from an empty cluster are not the same "
        .. "observation.", kafka.cluster_ops_text(metadata.cluster_authorized_operations)),
      { "topics returned: 0, cluster authorized operations: "
        .. kafka.cluster_ops_text(metadata.cluster_authorized_operations) }, { KB.REMEDIATION[2] })
  end

  if not metadata.answered then
    list[#list + 1] = finding("KAFKA-METADATA-NOT-AVAILABLE",
      "The metadata API was not answered",
      "INFO",
      string.format("Metadata did not answer (%s), so no topic was read and this report makes no claim about "
        .. "the cluster's inventory. A listener that requires authentication, a TLS-only listener and a "
        .. "filtered network path all look like this from outside.",
        tostring(metadata.error)),
      { tostring(metadata.error) }, { KB.REMEDIATION[1] })
  end

  return list
end


----------------------------------------------------------------------------
-- 8. Report
----------------------------------------------------------------------------

local report = {}

function report.target_section(cfg, host, port, w, records)
  local lines = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id: %s", cfg.client_id),
    string.format("Timeout: %dms, retry on transient errors: %s", cfg.timeout, fmt_bool(cfg.retry)),
    string.format("Budget: %s, configuration read: %s, unknown-name probe: %s",
      plural(cfg.max_topics, "topic"), fmt_bool(cfg.configs), fmt_bool(cfg.unknown_probe)),
  }
  if cfg.topics then lines[#lines + 1] = "Topics requested by name (operator supplied): "
    .. fmt_list(cfg.topics, 10) end
  if cfg.patterns then lines[#lines + 1] = "Extra name patterns: " .. fmt_list(cfg.patterns, 10) end
  local negotiate = records.negotiate or {}
  local versions = negotiate.versions or {}
  local rows = {}
  for _, key in ipairs({ 3, 32, 60, 16, 19, 20, 36, 18 }) do
    local entry = versions[key]
    if entry and entry.broker_max then
      rows[#rows + 1] = string.format("%s v%d", kafka.api_name(key), entry.broker_max)
    end
  end
  if #rows > 0 then lines[#lines + 1] = "Version negotiation selected: " .. fmt_list(rows, 8) end
  if negotiate.answered == false then
    lines[#lines + 1] = "ApiVersions was not answered; every later row is limited by that."
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

function report.access_section(exposure, records)
  local lines = { string.format("%-28s %-12s %-8s %s", "Request", "Access", "Version", "What came back") }
  for _, row in ipairs(exposure.rows or {}) do
    lines[#lines + 1] = string.format("%-28s %-12s %-8s %s", row.name, tostring(row.access),
      row.version and ("v" .. num_text(row.version)) or "-", tostring(row.detail or "-"))
  end
  lines[#lines + 1] = string.format("Summary: %d answered, %d refused, %d unanswered",
    exposure.granted or 0, exposure.denied or 0, exposure.unanswered or 0)
  local metadata = records.metadata_all or {}
  if metadata.answered and metadata.trailing_bytes and metadata.trailing_bytes > 0 then
    lines[#lines + 1] = string.format("The Metadata response carried %d unparsed trailing byte(s).",
      metadata.trailing_bytes)
  end
  return lines
end

function report.cluster_section(inventory, records)
  local lines = {}
  local metadata = records.metadata_all or {}
  if not metadata.answered then
    return { "No cluster description: Metadata was not answered." }
  end
  lines[#lines + 1] = string.format("Cluster id: %s", tostring(inventory.cluster_id or "withheld"))
  lines[#lines + 1] = string.format("Controller: %s",
    inventory.controller_id and num_text(inventory.controller_id) or "not returned by this version")
  local describe = records.describe_cluster or {}
  if describe.answered then
    lines[#lines + 1] = string.format("DescribeCluster v%s: %s, endpoint type %s",
      num_text(describe.version), tostring(describe.error_name or "no error"),
      num_text(describe.endpoint_type or 0))
    if describe.cluster_authorized_operations ~= nil then
      lines[#lines + 1] = "Cluster authorized operations: "
        .. kafka.cluster_ops_text(describe.cluster_authorized_operations)
    end
  else
    lines[#lines + 1] = string.format("DescribeCluster did not answer (%s)",
      tostring(describe.error or "no response"))
  end
  if inventory.cluster_authorized_operations ~= nil then
    local mask = (metadata.cluster_authorized_operations ~= nil)
      and metadata.cluster_authorized_operations or inventory.cluster_authorized_operations
    lines[#lines + 1] = "Metadata cluster authorized operations: " .. kafka.cluster_ops_text(mask)
  end
  lines[#lines + 1] = string.format("Brokers: %d", #(inventory.brokers or {}))
  for _, broker in ipairs(inventory.brokers or {}) do
    lines[#lines + 1] = string.format("  node %s: %s:%s%s", num_text(broker.node_id), tostring(broker.host),
      num_text(broker.port), broker.rack and (" rack " .. tostring(broker.rack)) or " (no rack reported)")
  end
  if count_of(inventory.racks) > 0 then
    local rack_rows = {}
    for _, rack in ipairs(sorted_keys(inventory.racks)) do
      rack_rows[#rack_rows + 1] = string.format("%s x%d", tostring(rack), inventory.racks[rack])
    end
    lines[#lines + 1] = "Racks: " .. fmt_list(rack_rows, 8)
  end
  local groups = records.list_groups or {}
  if groups.answered then
    lines[#lines + 1] = string.format("Consumer groups visible to the same caller: %s",
      plural(#(groups.groups or {}), "group"))
  end
  return lines
end

function report.inventory_section(inventory, cfg)
  local lines = {}
  if inventory.listed == 0 then
    lines[#lines + 1] = "No topic was listed."
    if inventory.with_error and inventory.with_error > 0 then
      lines[#lines + 1] = string.format("%d requested name(s) came back with an error instead of metadata.",
        inventory.with_error)
    end
    return lines
  end
  lines[#lines + 1] = string.format("%s listed (%d internal, %d user), %s, %s",
    plural(inventory.listed, "topic"), inventory.internal, inventory.user,
    plural(inventory.partitions, "partition"), plural(inventory.replicas, "replica placement"))
  if inventory.truncated then
    lines[#lines + 1] = string.format("Only the first %d topics are printed; raise kafka.max-topics to see "
      .. "the rest.", cfg.max_topics)
  end
  lines[#lines + 1] = string.format("%-34s %5s %6s %5s %5s  %s", "Topic", "Parts", "Repl", "ISR", "Bad",
    "Attributes")
  for _, row in ipairs(inventory.rows) do
    local attributes = {}
    if row.is_internal then attributes[#attributes + 1] = "internal" end
    if row.error_code and row.error_code ~= 0 then
      attributes[#attributes + 1] = "error " .. tostring(row.error_name)
    end
    if row.under_replicated > 0 then
      attributes[#attributes + 1] = string.format("%d under-replicated", row.under_replicated)
    end
    if row.offline > 0 then attributes[#attributes + 1] = string.format("%d with offline replica", row.offline) end
    if row.empty_isr > 0 then attributes[#attributes + 1] = string.format("%d without ISR", row.empty_isr) end
    if row.no_leader > 0 then attributes[#attributes + 1] = string.format("%d without leader", row.no_leader) end
    if row.replication_min == 1 and not row.is_internal then attributes[#attributes + 1] = "unreplicated" end
    lines[#lines + 1] = string.format("%-34s %5s %6s %5s %5s  %s", string.sub(tostring(row.name), 1, 34),
      num_text(row.partition_count),
      row.replication_max and (row.replication_min == row.replication_max and num_text(row.replication_max)
        or (num_text(row.replication_min) .. "-" .. num_text(row.replication_max))) or "?",
      num_text(row.isr_min or 0), num_text(row.under_replicated + row.offline + row.empty_isr),
      #attributes > 0 and table.concat(attributes, ", ") or "-")
  end
  if #(inventory.replication_histogram or {}) > 0 then
    local parts = {}
    for _, key in ipairs(sorted_keys(inventory.replication_histogram)) do
      parts[#parts + 1] = string.format("replication %s x%s", tostring(key),
        num_text(inventory.replication_histogram[key]))
    end
    table.sort(parts)
    lines[#lines + 1] = "Partitions by replication factor: " .. table.concat(parts, ", ")
  end
  if #(inventory.leader_load or {}) > 0 then
    local parts = {}
    for _, leader in ipairs(sorted_keys(inventory.leader_load)) do
      parts[#parts + 1] = string.format("node %s leads %s", num_text(leader),
        plural(inventory.leader_load[leader], "partition"))
    end
    lines[#lines + 1] = "Leadership: " .. fmt_list(parts, 10)
  end
  local bad_total = 0
  for _, row in ipairs(inventory.rows) do
    bad_total = bad_total + (row.under_replicated or 0) + (row.offline or 0) + (row.empty_isr or 0)
  end
  lines[#lines + 1] = string.format("Partitions needing attention: %d", bad_total)
  return lines
end

function report.internal_section(inventory)
  local lines = {}
  for _, row in ipairs(inventory.rows or {}) do
    if row.is_internal then
      lines[#lines + 1] = string.format("%s: %s, replication %s", tostring(row.name),
        plural(row.partition_count, "partition"), tostring(row.replication_max or "?"))
      lines[#lines + 1] = "    " .. (row.internal_note or
        "an internal topic whose name is not in this script's knowledge base")
    end
  end
  if #lines == 0 then lines[#lines + 1] = "No internal topic was disclosed." end
  return lines
end

function report.config_section(capacity, cfg)
  local lines = {}
  if capacity.skipped then
    return { "Configuration was not read: " .. tostring(capacity.skipped),
      "DescribeConfigs is a read-only API, but it takes a resource list, so the script only calls it when "
        .. "the operator asked for it." }
  end
  if not capacity.answered then
    return { capacity.skipped or (capacity.error and tostring(capacity.error)) or "DescribeConfigs was not answered." }
  end
  if #(capacity.resources or {}) == 0 then
    return { string.format("DescribeConfigs answered without returning a resource (%s).",
      tostring(capacity.error or "no resource in the response")) }
  end
  local by_resource = {}
  for _, row in ipairs(capacity.notable or {}) do
    local key = string.format("%s [%s]", tostring(row.resource), tostring(row.resource_type))
    by_resource[key] = by_resource[key] or {}
    by_resource[key][#by_resource[key] + 1] = row
  end
  for _, key in ipairs(sorted_keys(by_resource)) do
    local rows = by_resource[key]
    lines[#lines + 1] = key
    local printed, hidden = 0, 0
    for _, row in ipairs(rows) do
      if printed >= cfg.max_configs then
        hidden = hidden + 1
      else
        local value = tostring(row.rendered)
        if row.value ~= nil and #value > 60 then value = string.sub(value, 1, 57) .. "..." end
        lines[#lines + 1] = string.format("    %-34s %-24s %s%s", tostring(row.name), value,
          tostring(row.source or "source not returned"),
          row.is_sensitive and " [sensitive]" or (row.operator_set and " [operator-set]" or " [default]"))
        if row.meaning then lines[#lines + 1] = "        meaning: " .. row.meaning end
        printed = printed + 1
      end
    end
    if hidden > 0 then lines[#lines + 1] = string.format("    (%d further value(s); raise kafka.max-configs)",
      hidden) end
  end
  if #(capacity.sensitive or {}) > 0 then
    lines[#lines + 1] = string.format("Values that should have been withheld: %s",
      fmt_list((function()
        local names = {}
        for _, row in ipairs(capacity.sensitive) do
          names[#names + 1] = tostring(row.resource) .. "/" .. tostring(row.name)
        end
        return names
      end)(), 8))
  end
  return lines
end

function report.naming_section(naming)
  local lines = {}
  if #(naming.matches or {}) == 0 then
    lines[#lines + 1] = "No topic name matched the sensitive patterns in this script's knowledge base."
  else
    for _, match in ipairs(naming.matches) do
      lines[#lines + 1] = string.format("%s: matched '%s' (%s), %s", tostring(match.topic),
        tostring(match.token), tostring(match.category), plural(match.partitions, "partition"))
    end
    local categories = {}
    for _, category in ipairs(sorted_keys(naming.categories)) do
      categories[#categories + 1] = string.format("%s x%d", tostring(category), naming.categories[category])
    end
    lines[#lines + 1] = "Categories: " .. fmt_list(categories, 8)
  end
  if count_of(naming.environments) > 0 then
    local parts = {}
    for _, topic in ipairs(sorted_keys(naming.environments)) do
      parts[#parts + 1] = string.format("%s (%s)", tostring(topic), tostring(naming.environments[topic]))
    end
    lines[#lines + 1] = "Environment markers: " .. fmt_list(parts, 8)
  end
  for _, prefix in ipairs(sorted_keys(naming.internal_by_prefix)) do
    local entry = naming.internal_by_prefix[prefix]
    lines[#lines + 1] = string.format("Names starting with '%s': %d - %s", tostring(prefix),
      #entry.topics, entry.note)
  end
  return lines
end

function report.boundary_section(boundary, records, cfg)
  local lines = {}
  local by_name = records.metadata_by_name or {}
  if by_name.answered == false then
    lines[#lines + 1] = string.format("The per-name request was not answered (%s).",
      tostring(by_name.error))
  elseif by_name.skipped then
    lines[#lines + 1] = by_name.skipped
  else
    lines[#lines + 1] = string.format("Requested by name: %s; granted %s, refused %s",
      plural(#(by_name.requested or {}), "name"), num_text(by_name.granted or 0), num_text(by_name.denied or 0))
  end
  if #(boundary.masks or {}) > 0 then
    for index = 1, math.min(#boundary.masks, 12) do
      local row = boundary.masks[index]
      lines[#lines + 1] = string.format("mask %s: %s", tostring(row.name), tostring(row.text))
    end
  end
  for _, row in ipairs(boundary.refused_by_name or {}) do
    lines[#lines + 1] = "listed but refused by name: " .. row
  end
  for _, name in ipairs(boundary.hidden_by_name or {}) do
    lines[#lines + 1] = "describable by name but absent from the listing: " .. tostring(name)
  end
  local unknown = records.metadata_unknown or {}
  if not cfg.unknown_probe then
    lines[#lines + 1] = "The unknown-name probe was disabled (kafka.unknown-topic-probe=false)."
  elseif unknown.answered then
    lines[#lines + 1] = string.format("Unknown name '%s' (allow_auto_topic_creation=false) answered %s",
      tostring(unknown.requested), tostring(unknown.error_name or unknown.error_code))
    if unknown.materialised then
      lines[#lines + 1] = "The name came back as a real topic: the request flag was not honoured."
    elseif kafka.is_authz_error(unknown.error_code) then
      lines[#lines + 1] = "Authorization is evaluated before existence, so the caller cannot tell an existing "
        .. "topic from a missing one."
    else
      lines[#lines + 1] = "The error code is the cluster's 'no such topic' answer, which makes the API an "
        .. "existence oracle for unauthenticated callers."
    end
  else
    lines[#lines + 1] = string.format("The unknown-name probe was not answered (%s).",
      tostring(unknown.error or "no response"))
  end
  return lines
end

function report.finding_section(list)
  if #list == 0 then
    return { "No finding: the metadata API published nothing to an unauthenticated caller." }
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

function report.build(cfg, host, port, records, inventory, naming, capacity, boundary, exposure, list, w)
  local out = stdnse.output_table()
  out["Target"] = report.target_section(cfg, host, port, w, records)
  out["Access matrix"] = report.access_section(exposure, records)
  out["Cluster"] = report.cluster_section(inventory, records)
  out["Topic inventory"] = report.inventory_section(inventory, cfg)
  out["Internal topics"] = report.internal_section(inventory)
  out["Configuration"] = report.config_section(capacity, cfg)
  out["Name intelligence"] = report.naming_section(naming)
  out["Authorization boundary"] = report.boundary_section(boundary, records, cfg)
  out["Findings"] = report.finding_section(list)
  out["Why the exposure matters"] = report.value_section(list)
  out["Remediation"] = report.remediation_section(list)
  out["Verification"] = KB.VERIFICATION
  out["Method limits"] = KB.METHOD_LIMITS
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
-- 9. Orchestration
----------------------------------------------------------------------------

-- The names asked for one at a time: the operator's list when one was given,
-- otherwise a bounded sample of what the full listing returned.
local function select_names(cfg, inventory)
  if cfg.topics then return cfg.topics end
  local names = {}
  for _, row in ipairs(inventory.rows or {}) do
    if not row.is_internal and #names < 10 then names[#names + 1] = row.name end
  end
  if #names == 0 then
    for _, row in ipairs(inventory.rows or {}) do
      if #names < 10 then names[#names + 1] = row.name end
    end
  end
  return names
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
      "The TCP connection failed, so the metadata API was never reached. A TLS-only listener answers a "
        .. "plaintext Kafka probe exactly like this.",
    }
    return out
  end

  local records = {}
  records.negotiate = probe.negotiate(w)
  records.metadata_all = probe.metadata_all(w)
  local inventory = analysis.inventory(records, cfg)
  records.metadata_by_name = probe.metadata_by_name(w, select_names(cfg, inventory))
  records.metadata_unknown = cfg.unknown_probe and probe.metadata_unknown(w)
    or { stage = "metadata_unknown", answered = true, skipped = "kafka.unknown-topic-probe=false" }
  records.describe_cluster = probe.describe_cluster(w)
  if cfg.configs then
    local broker_ids, topic_names = {}, {}
    for _, broker in ipairs(inventory.brokers or {}) do broker_ids[#broker_ids + 1] = broker.node_id end
    for _, row in ipairs(inventory.rows or {}) do
      if #topic_names < probe.MAX_CONFIG_TOPICS then topic_names[#topic_names + 1] = row.name end
    end
    records.describe_configs = probe.describe_configs(w, broker_ids, topic_names)
  else
    records.describe_configs = { stage = "describe_configs", answered = true,
      skipped = "kafka.configs=false", results = {} }
  end
  records.list_groups = probe.list_groups(w)
  w:close()

  inventory = analysis.inventory(records, cfg)
  local naming = analysis.naming(inventory, cfg)
  local capacity = analysis.capacity(records, cfg)
  local boundary = analysis.boundary(records, inventory)
  local exposure = analysis.exposure(records)
  local list = findings.evaluate(records, inventory, naming, capacity, boundary, exposure, cfg)

  local result = report.build(cfg, host, port, records, inventory, naming, capacity, boundary, exposure, list, w)

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
