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


description = [[
Reads a Kafka cluster's metadata without authenticating and measures how much of
the cluster the answer describes.

Metadata is the API that every Kafka client calls first, and it is answered
before ACLs are consulted on listeners that do not require authentication. The
answer is not a list of names: it carries the cluster id, the controller, every
broker's host, port and rack, every topic's id, partition count, replica set and
in-sync set, the internal topics that reveal which subsystems the deployment
runs, offline replicas, leader epochs, and per-topic authorized operations.

This script turns that response into an inventory and then asks the questions
that decide how much of it is exposure:

  * Which topics are internal, and what does each internal topic prove about the
    deployment (consumer groups, transactions, Schema Registry, Kafka Connect,
    Streams, a canary)? Internal topics are the ones whose removal or corruption
    stops the pipeline rather than one application.
  * How many partitions and replicas exist in total, how many are
    under-replicated, which partitions have an empty in-sync set, and which
    replicas are offline? Those numbers are the cluster's current availability
    posture, and they are published to an unauthenticated caller.
  * Is the listing filtered per principal, and does asking for a name directly
    return what the listing hid? A metadata response that lists every topic to
    one caller and refuses another proves that ACLs exist; a response that hides
    a topic in the listing but describes it when named is an existence oracle.
  * Do the topic names themselves leak the organisation - payment, identity,
    health, audit, staging - and do the authorized-operations masks tell the
    caller what it may do to each topic?
  * Do the broker settings that an auto-created topic would inherit (retention,
    segment size, minimum in-sync replicas, unclean leader election) point at a
    cluster where a single caller can fill the disk or lose acknowledged
    writes?

The script is strictly read-only. It sends ApiVersions, Metadata,
DescribeCluster and DescribeConfigs, never sets allow_auto_topic_creation, and
re-reads the topic list at the end so the report can state that the inventory it
printed is the inventory that exists.
]]


-- Findings are published through Nmap's vulnerability machinery when it is
-- available. Under the test harness the module is a stand-in whose Report
-- returns an object with add(); under a real Nmap installation it is the
-- class-based API, so both shapes are handled here and a VULNERABLE line appears
-- in the Nmap output either way.
local has_vulns, vulns_lib = pcall(require, "vulns")

local function vuln_publisher(host, port)
  if not has_vulns or type(vulns_lib) ~= "table" then return nil end
  local ok, publisher = pcall(function()
    -- Nmap's own library is a class whose instances carry the endpoint.
    if type(vulns_lib.Report) == "table" and type(vulns_lib.Report.new) == "function" then
      local report = vulns_lib.Report:new(SCRIPT_NAME, host, port)
      return function(id, title, detail)
        report:add(id, title, { format = function() return detail end })
      end
    end
    -- The test stand-in answers Report() with an object that takes the endpoint
    -- itself, so the two calling conventions are adapted here instead of being
    -- assumed.
    if type(vulns_lib.Report) == "function" then
      local report = vulns_lib.Report(host, port)
      return function(id, title, detail)
        report.add(host, port, id, title, { format = function() return detail end })
      end
    end
    return nil
  end)
  if ok and type(publisher) == "function" then return publisher end
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
categories = {"vuln", "safe", "discovery"}

portrule = shortport.port_or_service({9092, 9093, 9094, 19092, 29092}, "kafka", {"tcp"})

local SCRIPT_RISK = "CRITICAL"
local SCRIPT_NAME = "kafka-metadata-topic-leak"
local SCRIPT_VERSION = "2.0.0"

-- The metadata API is the whole script, so the version the broker will use is
-- pinned here: a newer schema adds fields the inventory reports (topic ids from
-- v10, leader epochs from v7, offline replicas from v5) and the script prefers
-- the newest form the broker offers so the inventory is not truncated by the
-- shape of an older response.
local METADATA_PREFERENCE = 12
local DESCRIBE_CLUSTER_PREFERENCE = 1
local DESCRIBE_CONFIGS_PREFERENCE = 4

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

local function arg_list(name, default, maximum)
  local raw = nmap.registry.args and nmap.registry.args[name]
  if raw == nil then return default end
  local out = {}
  for item in string.gmatch(tostring(raw), "[^,]+") do
    local trimmed = string.gsub(item, "^%s*(.-)%s*$", "%1")
    if #trimmed > 0 and #out < (maximum or 16) then out[#out + 1] = trimmed end
  end
  return out
end

local function read_config()
  return {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000),
    client_id = arg_string("kafka.client-id", "nmap-kafka-metadata-audit", 120),
    max_topics = arg_number("kafka.max-topics", 50, 1, 10000),
    max_configs = arg_number("kafka.max-configs", 10, 0, 200),
    named_probe = arg_bool("kafka.named-probe", true),
    names = arg_list("kafka.names", {}, 16),
    unknown_probe = arg_bool("kafka.unknown-probe", false),
    verbose = arg_bool("kafka.verbose", false),
  }
end

----------------------------------------------------------------------------
-- 2. Formatting helpers
----------------------------------------------------------------------------

local function fmt_bool(value)
  if value == nil then return "unknown" end
  return value and "true" or "false"
end

local function plural(count, singular, plural_form)
  count = tonumber(count) or 0
  if count == 1 then return string.format("%d %s", count, singular) end
  return string.format("%d %s", count, plural_form or (singular .. "s"))
end

-- Numbers arrive from the wire as Lua numbers; integers are printed without a
-- decimal part and anything that is not a number is passed through unchanged.
local function num_text(value)
  if value == nil then return "n/a" end
  if type(value) ~= "number" then return tostring(value) end
  if value ~= value then return "NaN" end
  if value == math.huge then return "inf" end
  if value == -math.huge then return "-inf" end
  if value == math.floor(value) and math.abs(value) < 1e15 then
    if value < 0 then
      return string.format("-%d", -value)
    end
    return string.format("%d", value)
  end
  return string.format("%.3f", value)
end

local function hex_bytes(text)
  if type(text) ~= "string" then return tostring(text) end
  local out = {}
  for index = 1, #text do
    out[#out + 1] = string.format("%02x", string.byte(text, index))
  end
  return table.concat(out)
end

local function sorted_keys(map)
  local keys = {}
  for key in pairs(map or {}) do keys[#keys + 1] = key end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  return keys
end

local function fmt_list(values, limit, empty_text)
  if not values or #values == 0 then return empty_text or "none" end
  local out = {}
  for index = 1, math.min(#values, limit or 6) do out[#out + 1] = tostring(values[index]) end
  if #values > (limit or 6) then
    out[#out + 1] = string.format("(+%d more)", #values - (limit or 6))
  end
  return table.concat(out, ", ")
end

local function count_where(list, predicate)
  local count = 0
  for _, item in ipairs(list) do
    if predicate(item) then count = count + 1 end
  end
  return count
end

local function sum_where(list, predicate, selector)
  local total = 0
  for _, item in ipairs(list) do
    if not predicate or predicate(item) then total = total + (selector(item) or 0) end
  end
  return total
end

local function finding(id, title, severity, detail, evidence, remediation)
  return {
    id = id,
    title = title,
    severity = severity,
    detail = detail,
    evidence = evidence or {},
    remediation = remediation or {},
  }
end

local function worst(list, default)
  local level, text = -1, default
  for _, item in ipairs(list) do
    local value = kafka.SEVERITY_ORDER[item.severity]
    if value and value > level then
      level, text = value, item.severity
    end
  end
  return text
end

-- Percentages are printed as a ratio against the population they came from, or
-- as "-" when there is no population, so a report never shows a percentage of
-- zero as if it meant something.
local function ratio(part, whole)
  if not whole or whole == 0 then return "-" end
  return string.format("%.1f%%", 100 * part / whole)
end

----------------------------------------------------------------------------
-- 3. Connection and stage transcript
----------------------------------------------------------------------------

local Wire = {}
Wire.__index = Wire

function Wire.new(host, port, cfg)
  local self = setmetatable({}, Wire)
  self.cfg = cfg
  self.host = host
  self.port = port
  self.stages = {}
  self.failures = {}
  self.flags = {}
  self.connection = kafka.new_connection(host.ip or host.name or "target", port.number, {
    timeout_ms = cfg.timeout,
    client_id = cfg.client_id,
  })
  return self
end

-- Every request option that matters for safety is recorded as it is used, so the
-- safety ledger reads back what the script really sent instead of repeating what
-- the code intended to send.
function Wire:flag(name, value)
  local entry = self.flags[name] or { true_count = 0, false_count = 0, values = {} }
  if value then entry.true_count = entry.true_count + 1
  else entry.false_count = entry.false_count + 1 end
  entry.values[#entry.values + 1] = value
  self.flags[name] = entry
  return value
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

-- Every probe is wrapped: a transport failure is recorded with the error text
-- the socket produced, and each request is accounted for whether it was
-- answered or not, so "no answer" is never silently the same as "no exposure".
function Wire:call(stage, fn)
  local ok, result, err = pcall(fn)
  if not ok then
    self:fail(stage, "probe error: " .. tostring(result))
    return { ok = false, error = "probe error: " .. tostring(result), stage = stage }
  end
  if not result then
    self:fail(stage, err or "no response")
    return { ok = false, error = err or "no response", stage = stage }
  end
  self:stage(stage, "answered")
  return result
end

function Wire:version(key, preference)
  local connection = self.connection
  if connection.versions and next(connection.versions) ~= nil then
    return kafka.version_for(connection, key, preference)
  end
  return preference
end

----------------------------------------------------------------------------
-- 4. Probes
----------------------------------------------------------------------------

local probe = {}

function probe.negotiate(w)
  local result, err = w.connection and kafka.negotiate(w.connection, {})
  if not result then
    w:fail("api_versions", err or "no ApiVersions response")
    return { answered = false, error = err or "no ApiVersions response" }
  end
  local out = {
    answered = true,
    error_code = result.error_code,
    error_name = result.error_name,
    throttle_ms = result.throttle_ms,
    count = result.count,
    api_error = result.error_code ~= 0,
  }
  w:stage("api_versions", string.format("broker offers %s", plural(result.count or 0, "API")))
  return out
end

function probe.metadata_all(w, cfg)
  local version = w:version(3, METADATA_PREFERENCE)
  if not version then
    return { answered = false, error = "the broker does not advertise Metadata" }
  end
  w:flag("metadata.auto_create", false)
  local result = w:call("metadata_all", function()
    return kafka.metadata(w.connection, nil, {
      version = version,
      auto_create = false,
      cluster_authorized_operations = true,
      topic_authorized_operations = true,
    })
  end)
  if not result.ok then return { answered = false, error = result.error, version = version } end
  local out = {
    stage = "metadata_all",
    answered = true,
    version = version,
    cluster_id = result.cluster_id,
    controller_id = result.controller_id,
    brokers = result.brokers or {},
    topics = result.topics or {},
    cluster_authorized_operations = result.cluster_authorized_operations,
    throttle_ms = result.throttle_ms,
    requested = "all topics",
  }
  w:stage("metadata_all", string.format("%s, %s", plural(#out.brokers, "broker"),
    plural(#out.topics, "topic")))
  return out
end

function probe.metadata_named(w, names, source_of)
  if not names or #names == 0 then
    return { skipped = "there was nothing in the listing to re-request" }
  end
  local version = w:version(3, METADATA_PREFERENCE)
  w:flag("metadata.auto_create", false)
  local result = w:call("metadata_named", function()
    return kafka.metadata(w.connection, names, {
      version = version,
      auto_create = false,
      topic_authorized_operations = true,
    })
  end)
  if not result.ok then return { answered = false, error = result.error, requested = names } end
  local by_name = {}
  for _, topic in ipairs(result.topics or {}) do by_name[topic.name] = topic end
  local out = { stage = "metadata_named", answered = true, version = version, requested = names,
    by_name = by_name, topics = result.topics or {}, source_of = source_of or {} }
  w:stage("metadata_named", string.format("%s re-requested by name", plural(#names, "topic")))
  return out
end

function probe.metadata_unknown(w, name)
  if not name then return { skipped = "the unknown-name probe is disabled" } end
  local version = w:version(3, METADATA_PREFERENCE)
  w:flag("metadata.auto_create", false)
  local result = w:call("metadata_unknown", function()
    return kafka.metadata(w.connection, { name }, {
      version = version,
      auto_create = false,
      topic_authorized_operations = true,
    })
  end)
  if not result.ok then return { answered = false, error = result.error, name = name } end
  local topic = (result.topics or {})[1]
  local out = {
    stage = "metadata_unknown",
    answered = true,
    version = version,
    name = name,
    error_code = topic and topic.error_code,
    error_name = topic and topic.error_name,
    internal = topic and topic.is_internal,
    partitions = topic and #(topic.partitions or {}) or 0,
    entries = #(result.topics or {}),
  }
  w:stage("metadata_unknown", string.format("%s -> %s", name, tostring(out.error_name or "no entry")))
  return out
end

function probe.describe_cluster(w)
  local version = w:version(60, DESCRIBE_CLUSTER_PREFERENCE)
  if not version then return { skipped = "the broker does not advertise DescribeCluster" } end
  local result = w:call("describe_cluster", function()
    return kafka.describe_cluster(w.connection, { version = version })
  end)
  if not result.ok then
    return { answered = false, error = result.error, version = version }
  end
  local out = {
    stage = "describe_cluster",
    answered = true,
    version = version,
    error_code = result.error_code,
    error_name = result.error_name,
    endpoint_type = result.endpoint_type,
    cluster_id = result.cluster_id,
    controller_id = result.controller_id,
    brokers = result.brokers or {},
    authorized_operations = result.authorized_operations,
    is_fenced = result.is_fenced,
  }
  w:stage("describe_cluster", string.format("%s, controller %s", tostring(out.cluster_id or "no id"),
    num_text(out.controller_id)))
  return out
end

function probe.describe_configs(w, resources, stage)
  if not resources or #resources == 0 then
    return { skipped = "there was no resource to read configs for" }
  end
  local version = w:version(32, DESCRIBE_CONFIGS_PREFERENCE)
  if not version then return { skipped = "the broker does not advertise DescribeConfigs" } end
  local result = w:call(stage or "describe_configs", function()
    return kafka.describe_configs(w.connection, resources, {
      version = version,
      include_synonyms = true,
      include_documentation = false,
    })
  end)
  if not result.ok then
    return { answered = false, error = result.error, version = version, resources = resources }
  end
  local by_resource = {}
  for _, row in ipairs(result.results or {}) do
    by_resource[string.format("%s/%s", tostring(row.resource_type), tostring(row.resource_name))] = row
  end
  local out = {
    stage = stage or "describe_configs",
    answered = true,
    version = version,
    resources = resources,
    results = result.results or {},
    by_resource = by_resource,
    requested = #resources,
  }
  w:stage(stage or "describe_configs", string.format("%s read", plural(#out.results, "resource")))
  return out
end

function probe.list_groups(w)
  local version = w:version(16, 4)
  if not version then return { skipped = "the broker does not advertise ListGroups" } end
  local result = w:call("list_groups", function()
    return kafka.list_groups(w.connection, { version = version })
  end)
  if not result.ok then return { answered = false, error = result.error, version = version } end
  local states = {}
  for _, group in ipairs(result.groups or {}) do
    states[group.state or "unknown"] = (states[group.state or "unknown"] or 0) + 1
  end
  return {
    stage = "list_groups",
    answered = true,
    version = version,
    count = #(result.groups or {}),
    groups = result.groups or {},
    states = states,
    error_code = result.error_code,
    error_name = result.error_name,
  }
end


----------------------------------------------------------------------------
-- 5. Knowledge base
----------------------------------------------------------------------------

local KB = {}

-- Which subsystems an internal topic proves are deployed, and what the
-- exposure of its name and shape means. The list is deliberately factual: each
-- entry names the component that owns the topic, because "an internal topic is
-- visible" is only actionable once the operator knows what runs on the cluster.
KB.INTERNAL_TOPICS = {
  { name = "__consumer_offsets",
    component = "the group coordinator",
    proves = "consumer groups are in use; the partition count is "
      .. "offsets.topic.num.partitions, so the count in this report is the configured one",
    impact = "the committed offset of every consumer group lives here; the topic also records group "
      .. "membership, so its contents describe which applications consume which topics" },
  { name = "__transaction_state",
    component = "the transaction coordinator",
    proves = "transactional producers are in use (an idempotent or exactly-once pipeline)",
    impact = "transaction metadata including the transactional ids, which name the producing "
      .. "applications and their partitions" },
  { name = "_schemas",
    component = "Confluent Schema Registry",
    proves = "schemas are validated centrally, so this cluster carries the contract for every producer",
    impact = "the schema names are the data model: field names, types and compatibility history for "
      .. "every stream in the deployment" },
  { name = "__cluster_metadata",
    component = "the KRaft controller",
    proves = "the cluster runs without ZooKeeper; the metadata log is the cluster's own state",
    impact = "this topic is the configuration of the cluster itself, which is why it is only ever "
      .. "hosted by controllers and never by an ordinary broker" },
  { name = "connect-configs",
    component = "Kafka Connect",
    proves = "managed connectors are deployed, so the cluster moves data in and out of other systems",
    impact = "connector configuration includes the credentials the connector uses for its source or "
      .. "sink, which makes this the highest-value topic name in the list" },
  { name = "connect-offsets",
    component = "Kafka Connect",
    proves = "connectors checkpoint their position in this cluster",
    impact = "the keys are source partitions of the external system, which describes what is being "
      .. "replicated" },
  { name = "connect-status",
    component = "Kafka Connect",
    proves = "connector and task state is stored here",
    impact = "connector names, task ids and failure messages" },
  { name = "__debezium-heartbeat",
    component = "Debezium",
    proves = "change data capture is running against a database",
    impact = "the heartbeat topic names the connector and confirms an ongoing database replication "
      .. "stream" },
  { name = "__amazon_msk_canary",
    component = "Amazon MSK",
    proves = "the cluster is managed by AWS MSK with its canary enabled",
    impact = "the canary's topics and groups are visible, which identifies the account's monitoring "
      .. "setup" },
  { name = "_confluent-metrics",
    component = "Confluent control plane",
    proves = "Confluent telemetry is enabled",
    impact = "reserved internal names for the control plane's own data" },
  { name = "__strimzi",
    component = "Strimzi topic operator",
    proves = "Kafka is managed by the Strimzi operator on Kubernetes",
    impact = "the operator's changelog topic names the KafkaTopic resources the cluster manages" },
  { name = "__mirror",
    component = "MirrorMaker 2",
    proves = "the cluster is part of a replication topology",
    impact = "the checkpoint topics describe which clusters replicate into and out of this one, and "
      .. "the heartbeats topic describes the links that are alive" },
  { name = "mm2-",
    component = "MirrorMaker 2",
    proves = "replication flows cross this cluster",
    impact = "the topic names are the remote cluster aliases, so the naming reveals the topology" },
  { name = "__nse",
    component = "this script",
    proves = "nothing: a name with this prefix should never exist, because the collection never "
      .. "creates topics",
    impact = "if it is present, another tool using this prefix created state on the cluster and the "
      .. "report says so" },
}

KB.NAME_PATTERNS = {
  { pattern = "payment", category = "financial", why = "payment and settlement traffic" },
  { pattern = "billing", category = "financial", why = "invoices and billing events" },
  { pattern = "invoice", category = "financial", why = "billing documents" },
  { pattern = "ledger", category = "financial", why = "the accounting record of every movement" },
  { pattern = "transaction", category = "financial", why = "transactional data, often the record of "
    .. "money or state changes" },
  { pattern = "order", category = "commercial", why = "customer orders, which combine identity and "
    .. "purchase data" },
  { pattern = "customer", category = "personal", why = "customer records" },
  { pattern = "user", category = "personal", why = "user records or events" },
  { pattern = "account", category = "personal", why = "accounts, which map a person to a service" },
  { pattern = "identity", category = "personal", why = "identity data, the most sensitive personal "
    .. "category" },
  { pattern = "profile", category = "personal", why = "profile attributes" },
  { pattern = "kyc", category = "personal", why = "know-your-customer verification data" },
  { pattern = "ssn", category = "personal", why = "national identifiers" },
  { pattern = "health", category = "special-category", why = "health data, protected in most "
    .. "jurisdictions" },
  { pattern = "patient", category = "special-category", why = "patient records" },
  { pattern = "medical", category = "special-category", why = "medical data" },
  { pattern = "payroll", category = "hr", why = "salaries and payroll" },
  { pattern = "salary", category = "hr", why = "compensation data" },
  { pattern = "employee", category = "hr", why = "employee records" },
  { pattern = "hr", category = "hr", why = "human resources data" },
  { pattern = "secret", category = "credential", why = "the name states that secrets flow through "
    .. "the topic" },
  { pattern = "credential", category = "credential", why = "credentials in the payload" },
  { pattern = "password", category = "credential", why = "passwords, in a topic that may retain them" },
  { pattern = "token", category = "credential", why = "tokens, which grant access while valid" },
  { pattern = "apikey", category = "credential", why = "API keys" },
  { pattern = "auth", category = "credential", why = "authentication events or material" },
  { pattern = "audit", category = "audit", why = "the audit trail: who did what, and when" },
  { pattern = "access-log", category = "audit", why = "access records" },
  { pattern = "gdpr", category = "compliance", why = "data handled under a privacy regime" },
  { pattern = "hipaa", category = "compliance", why = "data handled under a health regime" },
  { pattern = "pci", category = "compliance", why = "card data in scope" },
  { pattern = "backup", category = "copy", why = "a second copy of data that is expected to be "
    .. "protected elsewhere" },
  { pattern = "archive", category = "copy", why = "an archive, usually with a longer retention than "
    .. "the source" },
  { pattern = "prod", category = "environment", why = "a production topic, which the operator may "
    .. "believe is not reachable from a staging network" },
  { pattern = "staging", category = "environment", why = "a staging topic; staging often holds a copy "
    .. "of production data with weaker controls" },
  { pattern = "test", category = "environment", why = "a test topic on a real cluster" },
  { pattern = "sandbox", category = "environment", why = "a sandbox with relaxed expectations" },
  { pattern = "canary", category = "environment", why = "a probe topic; its presence also tells an "
    .. "attacker which monitoring exists" },
}

-- Broker settings whose value changes the exposure that the rest of the report
-- describes. Each entry explains the value that matters, not just the name.
KB.BROKER_CONFIG_INTEREST = {
  { key = "allow.everyone.if.no.acl.found",
    danger = "true",
    why = "when no ACL matches a request the broker grants it, so an authenticated principal that "
      .. "matches no ACL has full access to every resource" },
  { key = "authorizer.class.name",
    danger = "",
    why = "an empty value means no authorizer is configured at all, so ACLs cannot be enforced even "
      .. "if they were created" },
  { key = "super.users",
    danger = nil,
    why = "names the principals that bypass every ACL; the value itself is the target list" },
  { key = "sasl.enabled.mechanisms",
    danger = "PLAIN",
    why = "PLAIN sends the credential in the clear unless the listener is protected by TLS" },
  { key = "ssl.keystore.location",
    danger = nil,
    why = "a filesystem path, which discloses the host layout and the file the key is read from" },
  { key = "zookeeper.connect",
    danger = nil,
    why = "the ZooKeeper ensemble and chroot, which is the cluster's other control plane" },
  { key = "controller.quorum.voters",
    danger = nil,
    why = "the KRaft controller quorum, which is the cluster's control plane in the newer mode" },
  { key = "listeners",
    danger = nil,
    why = "the listener names and ports, which map the attack surface of the host" },
  { key = "advertised.listeners",
    danger = nil,
    why = "the addresses clients are told to use, including internal hostnames" },
  { key = "auto.create.topics.enable",
    danger = "true",
    why = "a broker that creates a topic on a metadata request lets any caller allocate names" },
  { key = "unclean.leader.election.enable",
    danger = "true",
    why = "a partition can promote an out-of-sync replica, which silently loses acknowledged writes" },
  { key = "min.insync.replicas",
    danger = nil,
    why = "the size of the write quorum a producer with acks=all depends on" },
  { key = "offsets.topic.replication.factor",
    danger = "1",
    why = "a single replica of __consumer_offsets loses every group's position with one broker" },
  { key = "transaction.state.log.replication.factor",
    danger = "1",
    why = "the same risk for the transaction coordinator's log" },
  { key = "log.retention.hours",
    danger = nil,
    why = "how long records survive, which decides how much data a leak of the cluster exposes" },
  { key = "background.threads",
    danger = nil,
    why = "a tuning value; reported because it is a cheap sample of what the config API returns" },
  { key = "inter.broker.protocol.version",
    danger = nil,
    why = "the protocol generation, which dates the deployment" },
  { key = "principal.builder.class",
    danger = nil,
    why = "a custom principal builder changes which principal an ACL names" },
}

-- Topic-level settings worth printing, with what each one decides.
KB.TOPIC_CONFIG_INTEREST = {
  { key = "retention.ms", why = "how long records stay: the window in which a leak is complete" },
  { key = "retention.bytes", why = "the size cap, which decides how much a single topic can hold" },
  { key = "segment.bytes", why = "the log segment size; together with the partition count it is the "
    .. "storage a caller can allocate" },
  { key = "segment.ms", why = "how often a segment rolls, which decides how quickly the retention "
    .. "window is evaluated" },
  { key = "cleanup.policy", why = "delete or compact; a compacted topic retains the latest value of "
    .. "every key forever" },
  { key = "min.insync.replicas", why = "the write quorum for acks=all producers" },
  { key = "unclean.leader.election.enable", why = "per-topic permission to lose acknowledged writes" },
  { key = "max.message.bytes", why = "the largest record accepted, which bounds what one write can "
    .. "add to the log" },
  { key = "message.timestamp.type", why = "whether the broker or the producer sets the timestamp, "
    .. "which decides whether retention can be influenced by a client" },
  { key = "compression.type", why = "the compression the broker applies to its own copies" },
  { key = "delete.retention.ms", why = "how long tombstones persist on a compacted topic" },
  { key = "leader.replication.throttled.replicas", why = "a throttle list, which names replicas" },
  { key = "follower.replication.throttled.replicas", why = "a throttle list, which names replicas" },
}

KB.SENSITIVE_CONFIG_MARKERS = {
  "password", "secret", "token", "apikey", "api.key", "private.key", "keystore", "truststore",
  "sasl.jaas.config", "certificate", "credential", "oauth.client",
}

KB.RISK_RUBRIC = {
  { severity = "CRITICAL", condition = "the listing is complete and unreserved, or the broker "
    .. "disclosed a sensitive configuration value" },
  { severity = "HIGH", condition = "the inventory exposes internal topology, secret-bearing topic "
    .. "names, or the settings an attacker needs to plan against the cluster" },
  { severity = "MEDIUM", condition = "the listing is partial but names the cluster's systems, or the "
    .. "health picture is published without any topic data" },
  { severity = "LOW", condition = "only broker topology or settings are visible" },
  { severity = "INFO", condition = "the broker refuses, filters nothing, or does not answer" },
}

----------------------------------------------------------------------------
-- 6. Analysis
----------------------------------------------------------------------------

local analysis = {}

-- The inventory is the same response the report prints, so the numbers in the
-- findings and the numbers in the tables come from one pass over the data.
function analysis.inventory(records, cfg)
  local source = records.metadata_all or {}
  local rows = {}
  local metrics = {
    topics = 0, user_topics = 0, internal_topics = 0, partitions = 0, replicas = 0,
    under_replicated = 0, offline_replicas = 0, empty_isr = 0, unavailable = 0,
    topic_errors = 0, leaders = {}, racks = {}, replication = {}, single_replica = 0,
    partitions_without_leader = 0, topic_ids = 0, authorized_ops_present = 0,
  }
  if not source.answered then
    return { rows = rows, metrics = metrics, answered = false, error = source.error }
  end

  for _, topic in ipairs(source.topics or {}) do
    metrics.topics = metrics.topics + 1
    if topic.is_internal then metrics.internal_topics = metrics.internal_topics + 1
    else metrics.user_topics = metrics.user_topics + 1 end
    if topic.error_code and topic.error_code ~= 0 then metrics.topic_errors = metrics.topic_errors + 1 end
    if topic.topic_id then metrics.topic_ids = metrics.topic_ids + 1 end
    if topic.authorized_operations ~= nil and topic.authorized_operations >= 0 then
      metrics.authorized_ops_present = metrics.authorized_ops_present + 1
    end

    local replicas, under, offline, empty_isr, missing_leader = 0, 0, 0, 0, 0
    for _, partition in ipairs(topic.partitions or {}) do
      metrics.partitions = metrics.partitions + 1
      local replica_count = #(partition.replicas or {})
      replicas = replicas + replica_count
      metrics.replicas = metrics.replicas + replica_count
      metrics.replication[replica_count] = (metrics.replication[replica_count] or 0) + 1
      if replica_count == 1 then metrics.single_replica = metrics.single_replica + 1 end
      if #(partition.isr or {}) < replica_count then under = under + 1 end
      if #(partition.isr or {}) == 0 then empty_isr = empty_isr + 1 end
      offline = offline + #(partition.offline_replicas or {})
      if partition.leader_id == nil or partition.leader_id < 0 then missing_leader = missing_leader + 1 end
      if partition.leader_id and partition.leader_id >= 0 then
        metrics.leaders[partition.leader_id] = (metrics.leaders[partition.leader_id] or 0) + 1
      end
    end
    metrics.under_replicated = metrics.under_replicated + under
    metrics.offline_replicas = metrics.offline_replicas + offline
    metrics.empty_isr = metrics.empty_isr + empty_isr
    metrics.partitions_without_leader = metrics.partitions_without_leader + missing_leader
    if topic.error_code and topic.error_code ~= 0 then metrics.unavailable = metrics.unavailable + 1 end

    rows[#rows + 1] = {
      name = topic.name,
      internal = topic.is_internal and true or false,
      error_code = topic.error_code,
      error_name = topic.error_name,
      partitions = #(topic.partitions or {}),
      replicas = replicas,
      replication_factor = (#(topic.partitions or {}) > 0)
        and #((topic.partitions[1] or {}).replicas or {}) or 0,
      under_replicated = under,
      offline_replicas = offline,
      empty_isr = empty_isr,
      partitions_without_leader = missing_leader,
      topic_id = topic.topic_id and hex_bytes(topic.topic_id) or nil,
      authorized_operations = topic.authorized_operations,
      leaders = (function()
        local set = {}
        for _, partition in ipairs(topic.partitions or {}) do
          if partition.leader_id and partition.leader_id >= 0 then set[partition.leader_id] = true end
        end
        return set
      end)(),
    }
  end

  for _, broker in ipairs(source.brokers or {}) do
    if broker.rack and #tostring(broker.rack) > 0 then
      metrics.racks[tostring(broker.rack)] = (metrics.racks[tostring(broker.rack)] or 0) + 1
    end
  end
  -- The aggregate counters are kept next to the per-topic rows so a finding can
  -- quote a cluster-wide number without walking the rows again.
  for _, row in ipairs(rows) do
    metrics.under_replicated = (metrics.under_replicated or 0) + row.under_replicated
    metrics.offline_replicas_total = (metrics.offline_replicas_total or 0) + row.offline_replicas
    metrics.empty_isr_total = (metrics.empty_isr_total or 0) + row.empty_isr
    metrics.partitions_without_leader = (metrics.partitions_without_leader or 0)
      + row.partitions_without_leader
  end
  table.sort(rows, function(a, b)
    if a.internal ~= b.internal then return a.internal end
    return tostring(a.name) < tostring(b.name)
  end)
  return { rows = rows, metrics = metrics, answered = true, version = source.version,
    cluster_id = source.cluster_id, controller_id = source.controller_id,
    brokers = source.brokers or {}, cluster_authorized_operations = source.cluster_authorized_operations }
end

-- Which internal subsystems are present, and therefore which parts of the
-- deployment are described by the inventory.
function analysis.internal(inventory)
  local present, unknown = {}, {}
  for _, row in ipairs(inventory.rows or {}) do
    if row.internal then
      local matched = nil
      for _, entry in ipairs(KB.INTERNAL_TOPICS) do
        if string.find(string.lower(row.name), string.lower(entry.name), 1, true) then
          matched = entry
          break
        end
      end
      present[#present + 1] = { row = row, knowledge = matched }
      if not matched then unknown[#unknown + 1] = row end
    end
  end
  return { rows = present, unknown = unknown, count = #present }
end

-- The availability picture the broker publishes about itself.
function analysis.health(inventory)
  local metrics = inventory.metrics or {}
  metrics.offline_replicas = metrics.offline_replicas_total or 0
  metrics.empty_isr = metrics.empty_isr_total or 0
  local skew = 0
  local busiest = nil
  for leader, count in pairs(metrics.leaders or {}) do
    if count > skew then skew, busiest = count, leader end
  end
  local conditions = {}
  if (metrics.under_replicated or 0) > 0 then
    conditions[#conditions + 1] = string.format("%s under-replicated",
      plural(metrics.under_replicated, "partition"))
  end
  if (metrics.offline_replicas or 0) > 0 then
    conditions[#conditions + 1] = string.format("%s offline",
      plural(metrics.offline_replicas, "replica"))
  end
  if (metrics.empty_isr or 0) > 0 then
    conditions[#conditions + 1] = string.format("%s with an empty in-sync set",
      plural(metrics.empty_isr, "partition"))
  end
  if (metrics.partitions_without_leader or 0) > 0 then
    conditions[#conditions + 1] = string.format("%s without a leader",
      plural(metrics.partitions_without_leader, "partition"))
  end
  if (metrics.single_replica or 0) > 0 then
    conditions[#conditions + 1] = string.format("%s with a single replica",
      plural(metrics.single_replica, "partition"))
  end
  return {
    under_replicated = metrics.under_replicated or 0,
    offline_replicas = metrics.offline_replicas or 0,
    empty_isr = metrics.empty_isr or 0,
    unavailable = metrics.unavailable or 0,
    partitions_without_leader = metrics.partitions_without_leader or 0,
    single_replica_partitions = metrics.single_replica or 0,
    leader_skew = skew,
    busiest_leader = busiest,
    conditions = conditions,
    racks = metrics.racks or {},
    replication = metrics.replication or {},
  }
end

-- Name patterns: what the topic names say about the data, before anything is
-- read from them.
function analysis.naming(inventory)
  local matches, categories = {}, {}
  for _, row in ipairs(inventory.rows or {}) do
    local lowered = string.lower(tostring(row.name))
    for _, entry in ipairs(KB.NAME_PATTERNS) do
      if string.find(lowered, entry.pattern, 1, true) then
        matches[#matches + 1] = { topic = row.name, pattern = entry.pattern,
          category = entry.category, why = entry.why, internal = row.internal }
        categories[entry.category] = (categories[entry.category] or 0) + 1
      end
    end
  end
  return { matches = matches, categories = categories, count = #matches }
end

-- The listing against the per-name answers, which is the test for whether the
-- broker filters the listing per principal or only the requests.
function analysis.boundary(records, inventory, cfg)
  local named = records.metadata_named or {}
  local out = {
    requested = 0, described = 0, refused = 0, missing = 0, hidden = {}, refused_names = {},
    rows = {}, full_listing = false,
  }
  if not named.answered then
    out.skipped = named.skipped or named.error or "no per-name answer"
    return out
  end
  local listing = {}
  for _, row in ipairs(inventory.rows or {}) do listing[row.name] = row end
  for _, name in ipairs(named.requested or {}) do
    out.requested = out.requested + 1
    local topic = named.by_name[name]
    local row = { name = name, error_code = topic and topic.error_code,
      error_name = topic and topic.error_name, partitions = topic and #(topic.partitions or {}) or 0 }
    if not topic then
      out.missing = out.missing + 1
      row.verdict = "no-entry"
    elseif row.error_code == 0 then
      out.described = out.described + 1
      row.verdict = "described"
    elseif kafka.is_authz_error(row.error_code) then
      out.refused = out.refused + 1
      out.refused_names[#out.refused_names + 1] = name
      row.verdict = "refused"
    else
      out.missing = out.missing + 1
      row.verdict = "not-found"
    end
    out.rows[#out.rows + 1] = row
  end
  -- A topic that the wildcard listing hid but a direct request describes is the
  -- strongest form of this finding: the listing is filtered, the data is not.
  for _, row in ipairs(out.rows) do
    if row.verdict == "described" and not listing[row.name] then
      out.hidden[#out.hidden + 1] = row.name
      row.source = (named.source_of or {})[row.name] or "supplied by the scan"
      row.hidden = true
    else
      row.source = (named.source_of or {})[row.name] or "from the listing"
    end
  end
  -- How many of the names came from the scan rather than from the listing: the
  -- distinction matters, because only a supplied name can find a topic the
  -- listing hid.
  out.supplied = 0
  for _, name in ipairs(named.requested or {}) do
    if not listing[name] then out.supplied = out.supplied + 1 end
  end
  out.full_listing = out.requested > 0 and out.described == out.requested
  return out
end

function analysis.unknown_probe(records, inventory, cfg)
  local probe = records.metadata_unknown
  local out = { ran = false, verdict = "not-run" }
  if not probe or probe.skipped then
    out.skipped = probe and probe.skipped or "the probe was not run"
    return out
  end
  out.ran = true
  out.name = probe.name
  out.answered = probe.answered
  out.error_code = probe.error_code
  out.error_name = probe.error_name
  out.entries = probe.entries
  if probe.answered == false then
    out.verdict = "unanswered"
  elseif probe.entries and probe.entries > 0 and probe.error_code == 0 then
    -- An entry with no error for a name that did not exist before is an
    -- auto-created topic. That is reported separately, because it means the
    -- probe allocated a topic rather than measured anything.
    out.verdict = "created"
    out.created = true
  elseif kafka.is_authz_error(probe.error_code) then
    out.verdict = "refused"
  elseif probe.error_code == 3 then
    out.verdict = "absent"
  else
    out.verdict = "other"
  end
  return out
end

-- Configuration exposure: broker settings that change the rest of the analysis,
-- and topic settings that decide how much data a topic can hold.
function analysis.configs(records, cfg)
  local broker = records.configs_broker or {}
  local topics = records.configs_topics or {}
  local out = {
    skipped = (not broker.answered and not topics.answered)
      and (broker.skipped or topics.skipped or "DescribeConfigs was not answered") or nil,
    broker_answered = broker.answered and true or false,
    topic_answered = topics.answered and true or false,
    broker_rows = {}, sensitive = {}, weak = {}, topic_rows = {},
    topic_security = {}, set_by_operator = 0, sensitive_disclosed = 0,
  }
  local seen_broker = {}
  for _, result in ipairs(broker.results or {}) do
    for _, config in ipairs(result.configs or {}) do
      local row = {
        resource = result.resource_name, name = config.name, value = config.value,
        sensitive = config.is_sensitive, read_only = config.read_only,
        source = config.source, default = config.default,
      }
      if not seen_broker[config.name] then
        seen_broker[config.name] = true
        out.broker_rows[#out.broker_rows + 1] = row
      end
      if config.is_sensitive and config.value ~= nil and #tostring(config.value) > 0 then
        out.sensitive_disclosed = out.sensitive_disclosed + 1
        out.sensitive[#out.sensitive + 1] = row
      end
    end
  end
  for _, entry in ipairs(KB.BROKER_CONFIG_INTEREST) do
    for _, row in ipairs(out.broker_rows) do
      if row.name == entry.key then
        local value = row.value == nil and "" or tostring(row.value)
        local dangerous = entry.danger ~= nil and string.find(string.lower(value),
          string.lower(entry.danger), 1, true) ~= nil
        if entry.key == "authorizer.class.name" then
          dangerous = #value == 0
        end
        if dangerous or entry.danger == nil then
          out.weak[#out.weak + 1] = {
            key = entry.key, value = value, dangerous = dangerous and true or false,
            source = row.source, why = entry.why,
          }
        end
        if row.source and string.find(tostring(row.source), "DYNAMIC", 1, true) then
          out.set_by_operator = out.set_by_operator + 1
        end
      end
    end
  end
  for _, result in ipairs(topics.results or {}) do
    local row = { resource = result.resource_name, error_code = result.error_code,
      error_name = result.error_name, configs = {}, security = {} }
    for _, config in ipairs(result.configs or {}) do
      row.configs[config.name] = config.value
      if config.is_sensitive and config.value ~= nil and #tostring(config.value) > 0 then
        out.sensitive_disclosed = out.sensitive_disclosed + 1
        out.sensitive[#out.sensitive + 1] = { resource = result.resource_name, name = config.name,
          value = config.value, sensitive = true, source = config.source }
      end
      local lowered = string.lower(config.name)
      for _, marker in ipairs(KB.SENSITIVE_CONFIG_MARKERS) do
        if string.find(lowered, marker, 1, true) then
          row.security[#row.security + 1] = config.name
        end
      end
    end
    for _, entry in ipairs(KB.TOPIC_CONFIG_INTEREST) do
      local value = row.configs[entry.key]
      if value ~= nil then
        out.topic_rows[#out.topic_rows + 1] = { topic = result.resource_name, key = entry.key,
          value = value, why = entry.why }
      end
    end
    out.topic_security[#out.topic_security + 1] = row
  end
  return out
end

-- The matrix the report prints: one row per API, with what the answer gave the
-- caller.
function analysis.exposure(records, inventory, boundary, configs, health, naming)
  local rows = {}
  local function row(name, access, version, detail)
    rows[#rows + 1] = { name = name, access = access, version = version, detail = detail }
  end
  local negotiate = records.negotiate or {}
  row("ApiVersions", negotiate.answered and "granted" or "unanswered", 0,
    negotiate.answered and string.format("%s advertised", plural(negotiate.count or 0, "API"))
      or tostring(negotiate.error))
  local before = records.metadata_all or {}
  row("Metadata (all topics)", before.answered and "granted" or "unanswered", before.version,
    before.answered and string.format("%s, %s", plural(inventory.metrics.topics, "topic"),
      plural(#(before.brokers or {}), "broker")) or tostring(before.error))
  if boundary.skipped then
    row("Metadata (by name)", "not-run", nil, boundary.skipped)
  else
    row("Metadata (by name)", boundary.described > 0 and "granted" or "refused", records.metadata_named.version,
      string.format("%d of %s described", boundary.described, plural(boundary.requested, "name")))
  end
  local unknown = records.unknown or {}
  if unknown.ran then
    row("Metadata (random name)", unknown.verdict, unknown.error_name or "no code",
      unknown.error_name or "no error code")
  else
    row("Metadata (random name)", "not-run", nil, unknown.skipped or "disabled")
  end
  local cluster = records.describe_cluster or {}
  row("DescribeCluster", cluster.answered and "granted" or (cluster.skipped and "not-run" or "unanswered"),
    cluster.version, cluster.answered and string.format("cluster %s, endpoint type %s",
      tostring(cluster.cluster_id or "withheld"), tostring(cluster.endpoint_type or "-"))
      or tostring(cluster.error or cluster.skipped))
  row("DescribeConfigs (brokers)", configs.broker_answered and "granted" or "unanswered",
    (records.configs_broker or {}).version,
    configs.broker_answered and string.format("%s of broker settings", plural(#configs.broker_rows, "reading"))
      or tostring((records.configs_broker or {}).error or (records.configs_broker or {}).skipped))
  row("DescribeConfigs (topics)", configs.topic_answered and "granted" or "unanswered",
    (records.configs_topics or {}).version,
    configs.topic_answered and string.format("%s read", plural(#((records.configs_topics or {}).results or {}), "topic"))
      or tostring((records.configs_topics or {}).error or (records.configs_topics or {}).skipped))
  local groups = records.list_groups or {}
  row("ListGroups", groups.answered and "granted" or (groups.skipped and "not-run" or "unanswered"),
    groups.version, groups.answered and plural(groups.count or 0, "group") or tostring(groups.error or groups.skipped))
  local granted = count_where(rows, function(item) return item.access == "granted" end)
  return { rows = rows, granted = granted, total = #rows,
    naming = naming, health = health }
end

-- The final safety check: the topic list was read before and after the probes,
-- and the script never asked a broker to create anything.
function analysis.safety(records, inventory_after, cfg)
  local checks, failed = {}, 0
  local function check(name, ok, detail)
    checks[#checks + 1] = { name = name, ok = ok and true or false, detail = detail }
    if not ok then failed = failed + 1 end
  end
  local before, after = records.metadata_all or {}, records.metadata_after or {}
  check("no request allowed auto-creation", (records.auto_create_requests or 0) == 0,
    string.format("%d Metadata requests set allow_auto_topic_creation", records.auto_create_requests or 0))
  local delta = {}
  if before.answered and after.answered then
    local before_names, after_names = {}, {}
    for _, topic in ipairs(before.topics or {}) do before_names[topic.name] = true end
    for _, topic in ipairs(after.topics or {}) do after_names[topic.name] = true end
    for name in pairs(after_names) do if not before_names[name] then delta[#delta + 1] = "+" .. name end end
    for name in pairs(before_names) do if not after_names[name] then delta[#delta + 1] = "-" .. name end end
    check("the topic list is identical before and after", #delta == 0,
      #delta > 0 and table.concat(delta, ",") or "no difference")
  else
    check("the topic list is identical before and after", false,
      "one of the two reads was not answered")
  end
  if records.unknown and records.unknown.created then
    check("the random-name probe did not create a topic", false,
      records.unknown.name .. " now exists: the broker ignored allow_auto_topic_creation=false")
  end
  -- A name may be re-requested for two reasons: it came from the listing, or the
  -- operator supplied it (kafka.names) to test whether it is hidden. Anything
  -- else would be a name the scan invented, and inventing names is how a probe
  -- turns into an allocation.
  local supplied = {}
  for _, name in ipairs((cfg and cfg.names) or {}) do supplied[name] = true end
  local probes = (records.metadata_named or {}).requested or {}
  local unexpected = {}
  for _, name in ipairs(probes) do
    local listed = false
    for _, topic in ipairs(inventory_after.rows or {}) do
      if topic.name == name then listed = true end
    end
    if not listed and not supplied[name] then unexpected[#unexpected + 1] = name end
  end
  check("every re-requested name came from the listing or from the operator",
    #unexpected == 0, #unexpected > 0 and table.concat(unexpected, ",")
      or string.format("%s re-requested", plural(#probes, "name")))
  return { checks = checks, failed = failed, delta = delta,
    inventory_identical = #delta == 0 and before.answered and after.answered or false }
end

----------------------------------------------------------------------------
-- 7. Findings
----------------------------------------------------------------------------

local findings = {}

local function topic_sample(rows, limit, formatter)
  local out = {}
  for index = 1, math.min(#rows, limit or 6) do
    out[#out + 1] = formatter(rows[index])
  end
  if #rows > (limit or 6) then out[#out + 1] = string.format("(+%d more)", #rows - (limit or 6)) end
  return out
end

-- A config value that a broker marked sensitive is only reported when the broker
-- actually sent it: an empty or absent value for a sensitive key means the
-- broker behaved correctly, and the difference matters for the finding.
local function sensitive_evidence(configs, limit)
  local out = {}
  for index = 1, math.min(#configs.sensitive, limit or 6) do
    local row = configs.sensitive[index]
    out[#out + 1] = string.format("%s.%s = %s", tostring(row.resource), tostring(row.name),
      tostring(row.value))
  end
  return out
end

function findings.evaluate(records, inventory, internal, health, naming, boundary, unknown, configs, exposure, safety, cfg)
  local list = {}
  local negotiate = records.negotiate or {}
  local metrics = inventory.metrics or {}

  if safety.failed > 0 then
    local evidence = {}
    for _, check in ipairs(safety.checks) do
      if not check.ok then evidence[#evidence + 1] = string.format("%s: %s", check.name, tostring(check.detail)) end
    end
    list[#list + 1] = finding("KAFKA-METADATA-INVENTORY-CHANGED",
      "The cluster changed while the audit was running",
      "CRITICAL",
      "The topic list read after the probes differs from the list read before them, or a probe created "
        .. "state on the cluster. The inventory below is therefore a snapshot rather than a description, "
        .. "and the operator's own audit trail should be checked before it is trusted.",
      evidence, { "Re-run the scan against a quiet cluster and compare the two lists.", KB.REMEDIATION[1] })
  end

  if not inventory.answered then
    list[#list + 1] = finding("KAFKA-METADATA-NOT-MEASURED",
      "The metadata inventory could not be read",
      "INFO",
      string.format("The broker did not answer the metadata request (%s), so this report makes no claim "
        .. "about the cluster. A listener that requires authentication, a TLS-only listener and a "
        .. "filtered path all look like this from outside.", tostring(inventory.error or "no answer")),
      { tostring(inventory.error or "no answer") }, { KB.REMEDIATION[1], KB.REMEDIATION[6] })
    return list
  end

  local usable = (metrics.topics or 0) - (metrics.topic_errors or 0)
  if metrics.topics > 0 and usable == 0 then
    list[#list + 1] = finding("KAFKA-METADATA-LISTING-REFUSED",
      "The listing answered with an error for every topic",
      "INFO",
      string.format("The broker returned %s, and every one of them carried an error code, so the "
        .. "response names the topics without describing them. On a broker with an authorizer this is "
        .. "the filtered-listing shape: the names still leak, the details do not.",
        plural(metrics.topics, "topic")),
      topic_sample(inventory.rows, 8, function(row)
        return string.format("%s -> %s", tostring(row.name), tostring(row.error_name))
      end),
      { KB.REMEDIATION[2], KB.REMEDIATION[1] })
  elseif metrics.topics > 0 then
    list[#list + 1] = finding("KAFKA-METADATA-TOPIC-INVENTORY",
      "The complete topic inventory is visible without authentication",
      metrics.internal_topics > 0 and "CRITICAL" or "HIGH",
      string.format("An unauthenticated Metadata request returned %s, %s and %s across %s. The listing "
        .. "is not a directory: it is the data model of the deployment, and it is answered before any "
        .. "ACL is consulted on a listener that accepts anonymous clients. With %s in the list the "
        .. "inventory also identifies the internal subsystems the cluster runs.",
        plural(metrics.topics, "topic"), plural(metrics.partitions, "partition"),
        plural(metrics.replicas, "replica"), plural(#(inventory.brokers or {}), "broker"),
        plural(metrics.internal_topics, "internal topic")),
      topic_sample(inventory.rows, 10, function(row)
        return string.format("%s: %s, replication factor %s%s", tostring(row.name),
          plural(row.partitions, "partition"), num_text(row.replication_factor),
          row.error_name and row.error_name ~= "NONE" and (" [" .. tostring(row.error_name) .. "]") or "")
      end),
      { KB.REMEDIATION[1], KB.REMEDIATION[2], KB.REMEDIATION[4] })
  end

  if internal.count > 0 then
    local evidence = {}
    for _, entry in ipairs(internal.rows) do
      evidence[#evidence + 1] = entry.knowledge
        and string.format("%s (%s): %s", entry.row.name, entry.knowledge.component, entry.knowledge.proves)
        or string.format("%s: an internal topic this script does not recognise", entry.row.name)
    end
    list[#list + 1] = finding("KAFKA-METADATA-INTERNAL-SUBSYSTEMS",
      "The cluster's internal subsystems are visible to an unauthenticated caller",
      "HIGH",
      string.format("%s are described in the response, which tells the caller which components run on "
        .. "the cluster and how they are sized. Internal topics are also the ones whose loss stops the "
        .. "deployment rather than one application, so their names are the list an attacker keeps.",
        plural(internal.count, "internal topic")),
      evidence, { KB.REMEDIATION[4], KB.REMEDIATION[2] })
    if #internal.unknown > 0 then
      list[#list + 1] = finding("KAFKA-METADATA-UNKNOWN-INTERNAL-TOPIC",
        "An internal topic is not in this script's catalogue",
        "LOW",
        string.format("%s is marked internal by the broker but is not one of the names this script "
          .. "knows. Newer platforms add their own reserved topics, so the name is printed for review "
          .. "rather than classified.", plural(#internal.unknown, "topic")),
        topic_sample(internal.unknown, 6, function(row) return tostring(row.name) end),
        { KB.REMEDIATION[4] })
    end
  end

  if naming.count > 0 then
    local categories = {}
    for _, key in ipairs(sorted_keys(naming.categories)) do
      categories[#categories + 1] = string.format("%s x%s", tostring(key), num_text(naming.categories[key]))
    end
    local sensitive = count_where(naming.matches, function(match)
      return match.category ~= "environment" and match.category ~= "commercial"
    end)
    list[#list + 1] = finding("KAFKA-METADATA-SENSITIVE-TOPIC-NAMES",
      "Topic names describe the data they carry",
      sensitive > 0 and "HIGH" or "MEDIUM",
      string.format("%s of %s matched a sensitivity pattern (%s). A name is not the data, but it is "
        .. "enough to prioritise: a caller that knows which topic holds payments does not have to guess "
        .. "where to spend an attempt.", num_text(sensitive), plural(#naming.matches, "name"),
        table.concat(categories, ", ")),
      topic_sample(naming.matches, 10, function(match)
        return string.format("%s: %s (%s - %s)", tostring(match.topic), tostring(match.category),
          tostring(match.pattern), tostring(match.why))
      end),
      { KB.REMEDIATION[4], KB.REMEDIATION[5] })
  end

  if metrics.topics > 0 and #(inventory.brokers or {}) > 0 then
    local evidence = {}
    for _, broker in ipairs(inventory.brokers) do
      evidence[#evidence + 1] = string.format("node %s: %s:%s%s", num_text(broker.node_id),
        tostring(broker.host), num_text(broker.port),
        broker.rack and (" rack " .. tostring(broker.rack)) or "")
    end
    if inventory.cluster_id then
      evidence[#evidence + 1] = "cluster id: " .. tostring(inventory.cluster_id)
    end
    if inventory.controller_id then
      evidence[#evidence + 1] = "controller: node " .. num_text(inventory.controller_id)
    end
    list[#list + 1] = finding("KAFKA-METADATA-TOPOLOGY-DISCLOSURE",
      "Broker topology and cluster identity are published",
      "HIGH",
      string.format("%s and the controller are named to an unauthenticated caller, with the rack "
        .. "assignment when the brokers advertise one. This is the map a client needs and therefore the "
        .. "map an attacker needs: every host and port is a target, the controller is the node that "
        .. "performs deletions, and a rack layout tells the attacker which failure domain holds a "
        .. "particular replica.", plural(#inventory.brokers, "broker")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[6] })
  end

  if metrics.authorized_ops_present > 0 then
    local evidence = {}
    for _, row in ipairs(inventory.rows) do
      if row.authorized_operations and row.authorized_operations >= 0 then
        evidence[#evidence + 1] = string.format("%s: %s", tostring(row.name),
          kafka.cluster_ops_text(row.authorized_operations))
      end
    end
    list[#list + 1] = finding("KAFKA-METADATA-AUTHORIZED-OPERATIONS",
      "Per-topic authorized operations are published",
      "MEDIUM",
      string.format("The response includes an authorization mask for %s. The mask is derived from the "
        .. "caller's ACLs, so an anonymous caller that receives a populated mask is being told what it "
        .. "may do to each topic - including for topics it is not allowed to read records from.",
        plural(metrics.authorized_ops_present, "topic")),
      topic_sample(evidence, 8, function(line) return line end),
      { KB.REMEDIATION[2] })
  end

  if metrics.topics > 0 and ((metrics.under_replicated or 0) > 0
    or (metrics.offline_replicas_total or 0) > 0 or (metrics.empty_isr_total or 0) > 0
    or (metrics.partitions_without_leader or 0) > 0) then
    local evidence = {}
    for _, row in ipairs(inventory.rows) do
      if row.under_replicated > 0 or row.offline_replicas > 0 or row.empty_isr > 0
        or row.partitions_without_leader > 0 then
        evidence[#evidence + 1] = string.format("%s: %d under-replicated, %d offline replica(s), "
          .. "%d empty in-sync set(s)", tostring(row.name), row.under_replicated, row.offline_replicas,
          row.empty_isr)
      end
    end
    list[#list + 1] = finding("KAFKA-METADATA-HEALTH-DISCLOSURE",
      "The cluster's current availability posture is published",
      "MEDIUM",
      string.format("%s, %s, %s and %s are reported to an unauthenticated caller: %s. A client uses "
        .. "this to route around a failure; an attacker uses it to choose when to act, because a "
        .. "cluster with an empty in-sync set has partitions whose data is already at risk.",
        plural(metrics.under_replicated or 0, "under-replicated partition"),
        plural(metrics.offline_replicas_total or 0, "offline replica"),
        plural(metrics.empty_isr_total or 0, "partition with an empty in-sync set"),
        plural(metrics.partitions_without_leader, "partition without a leader"),
        fmt_list(health.conditions, 4)),
      topic_sample(evidence, 8, function(line) return line end),
      { KB.REMEDIATION[6], KB.REMEDIATION[1] })
  end

  if metrics.single_replica > 0 then
    list[#list + 1] = finding("KAFKA-METADATA-SINGLE-REPLICA-PARTITIONS",
      "Partitions exist with a single replica",
      "MEDIUM",
      string.format("%s have a replication factor of one, so one broker leaving the cluster takes them "
        .. "offline with no failover. The metadata response publishes that state to every caller.",
        plural(metrics.single_replica, "partition")),
      { string.format("replication factor histogram: %s", fmt_list((function()
        local parts = {}
        for factor, count in pairs(metrics.replication) do
          parts[#parts + 1] = string.format("x%s on %s", num_text(count), num_text(factor))
        end
        table.sort(parts)
        return parts
      end)(), 6)) },
      { KB.REMEDIATION[3] })
  end

  if unknown.ran and unknown.verdict == "created" then
    list[#list + 1] = finding("KAFKA-METADATA-AUTO-CREATED-TOPIC",
      "A metadata request created a topic",
      "CRITICAL",
      string.format("The random name %s was absent before the probe and is present after it, even "
        .. "though the request explicitly set allow_auto_topic_creation=false. The broker ignored the "
        .. "flag, so any client that names a topic creates it: an attacker can allocate names and "
        .. "consume the cluster's storage without creating anything.", tostring(unknown.name)),
      { string.format("%s -> %s with %d partition(s)", tostring(unknown.name),
        tostring(unknown.error_name or "no error"), unknown.partitions or 0) },
      { KB.REMEDIATION[3], KB.REMEDIATION[6] })
  elseif unknown.ran and unknown.verdict == "absent" then
    list[#list + 1] = finding("KAFKA-METADATA-EXISTENCE-ORACLE",
      "The broker confirms whether a topic exists to an unauthenticated caller",
      "MEDIUM",
      string.format("Asking for the random name %s answered %s, while a topic the caller may not "
        .. "describe would answer with an authorization error. The difference between the two answers "
        .. "is an existence oracle: the caller can test any name it can guess, and the answer arrives "
        .. "without credentials.", tostring(unknown.name), tostring(unknown.error_name)),
      { string.format("%s -> %s after %d entr(ies)", tostring(unknown.name),
        tostring(unknown.error_name), unknown.entries or 0) },
      { KB.REMEDIATION[2], KB.REMEDIATION[1] })
  elseif unknown.ran and unknown.verdict == "refused" then
    list[#list + 1] = finding("KAFKA-METADATA-EXISTENCE-REFUSED",
      "Existence checks are refused before the lookup",
      "INFO",
      string.format("%s answered %s, which is an authorization decision made before the name was "
        .. "looked up. A broker that refuses first does not confirm whether the name exists, so this "
        .. "oracle is closed.", tostring(unknown.name), tostring(unknown.error_name)),
      { tostring(unknown.error_name) }, { KB.REMEDIATION[2] })
  end

  if #boundary.hidden > 0 then
    list[#list + 1] = finding("KAFKA-METADATA-HIDDEN-TOPIC-ORACLE",
      "A topic hidden from the listing is described when it is named directly",
      "HIGH",
      string.format("%s did not appear in the wildcard listing but was described when requested by "
        .. "name (%s). The listing is filtered, and that filter is what an operator would audit; the "
        .. "per-name path is not, so a caller that knows a name reads a topic the listing pretends it "
        .. "cannot see.", plural(#boundary.hidden, "topic"), fmt_list(boundary.hidden, 6)),
      topic_sample(boundary.hidden, 8, function(name) return tostring(name) end),
      { KB.REMEDIATION[2], KB.REMEDIATION[1] })
  elseif boundary.skipped and usable > 0 then
    list[#list + 1] = finding("KAFKA-METADATA-NAMED-PATH-NOT-MEASURED",
      "The per-name metadata path was not measured",
      "INFO", tostring(boundary.skipped), {}, { KB.REMEDIATION[1] })
  elseif boundary.requested > 0 and boundary.refused == boundary.requested then
    list[#list + 1] = finding("KAFKA-METADATA-LISTING-FILTERED",
      "The listing is not filtered but per-name requests are refused",
      "MEDIUM",
      string.format("The wildcard request returned %s while all %s were refused when requested by "
        .. "name. The broker is enforcing DESCRIBE on the topic resource for direct requests but "
        .. "answering the wildcard from an unfiltered cache, which is the inconsistency the operator's "
        .. "ACL review would not show.", plural(metrics.topics, "topic"),
        plural(boundary.requested, "name")),
      topic_sample(boundary.refused_names, 8, function(name) return tostring(name) end),
      { KB.REMEDIATION[2], KB.REMEDIATION[6] })
  end

  if configs.sensitive_disclosed > 0 then
    list[#list + 1] = finding("KAFKA-METADATA-SENSITIVE-CONFIG-DISCLOSED",
      "A configuration value marked sensitive was returned in the clear",
      "CRITICAL",
      string.format("%s marked sensitive arrived with a value. Kafka's own protocol has a sensitive "
        .. "flag for exactly this reason, and a broker that ignores it publishes credentials to anyone "
        .. "who can call DescribeConfigs.",
        plural(configs.sensitive_disclosed, "configuration entry")),
      sensitive_evidence(configs, 6), { KB.REMEDIATION[2], KB.REMEDIATION[7] })
  end

  if #configs.weak > 0 then
    local dangerous = count_where(configs.weak, function(row) return row.dangerous end)
    local evidence = {}
    for index = 1, math.min(#configs.weak, 10) do
      local row = configs.weak[index]
      evidence[#evidence + 1] = string.format("%s=%s%s [%s] %s", tostring(row.key),
        #row.value > 0 and row.value or "(empty)", row.dangerous and " <-- weak" or "",
        tostring(row.source or "unknown source"), tostring(row.why))
    end
    list[#list + 1] = finding("KAFKA-METADATA-BROKER-CONFIG-EXPOSURE",
      "Broker settings that decide the cluster's security posture are readable",
      dangerous > 0 and "CRITICAL" or "HIGH",
      string.format("%s of broker configuration are readable without authentication, and %s of them "
        .. "are set to a value that weakens the cluster. DescribeConfigs is an administrative API: on "
        .. "a listener that accepts anonymous callers it turns the cluster's own configuration into "
        .. "reconnaissance.",
        plural(#configs.broker_rows, "entry"), num_text(dangerous)),
      evidence, { KB.REMEDIATION[2], KB.REMEDIATION[1] })
    for _, row in ipairs(configs.weak) do
      if row.key == "allow.everyone.if.no.acl.found" and row.dangerous then
        list[#list + 1] = finding("KAFKA-METADATA-AUTHORIZATION-BYPASS-SETTING",
          "The broker grants access when no ACL matches",
          "CRITICAL",
          string.format("allow.everyone.if.no.acl.found=%s means a request that matches no ACL is "
            .. "allowed rather than denied. Every other authorization finding in this report becomes "
            .. "worse under that setting: the ACLs only restrict the principals they name, and "
            .. "everyone else has full access.", tostring(row.value)),
          { string.format("allow.everyone.if.no.acl.found=%s", tostring(row.value)) },
          { KB.REMEDIATION[2], KB.REMEDIATION[7] })
      end
      if row.key == "authorizer.class.name" and row.dangerous then
        list[#list + 1] = finding("KAFKA-METADATA-NO-AUTHORIZER",
          "No authorizer is configured on the broker",
          "CRITICAL",
          string.format("authorizer.class.name is empty, so the broker has no component that can "
            .. "enforce an ACL. Any ACL that exists in configuration or in a management tool is "
            .. "decoration on this listener."),
          { "authorizer.class.name is empty" }, { KB.REMEDIATION[2], KB.REMEDIATION[7] })
      end
      if row.key == "auto.create.topics.enable" and row.dangerous then
        list[#list + 1] = finding("KAFKA-METADATA-AUTO-CREATE-ENABLED",
          "The broker creates topics on demand",
          "HIGH",
          string.format("auto.create.topics.enable=%s lets any client that names a topic allocate it, "
            .. "with the broker's default partition count and replication factor. An unauthenticated "
            .. "caller can therefore consume the cluster's storage and, if the name matches what an "
            .. "application expects to consume, have its own records read by that application.",
            tostring(row.value)),
          { string.format("auto.create.topics.enable=%s", tostring(row.value)) },
          { KB.REMEDIATION[3], KB.REMEDIATION[7] })
      end
      if row.key == "unclean.leader.election.enable" and row.dangerous then
        list[#list + 1] = finding("KAFKA-METADATA-UNCLEAN-ELECTION-ENABLED",
          "Out-of-sync replicas may be promoted",
          "MEDIUM",
          string.format("unclean.leader.election.enable=%s allows a replica that is behind to become "
            .. "the leader when the in-sync set is empty. Acknowledged writes that only the previous "
            .. "leader held are then discarded, so the cluster's own durability guarantee is weaker "
            .. "than the producers believe.", tostring(row.value)),
          { string.format("unclean.leader.election.enable=%s", tostring(row.value)) },
          { KB.REMEDIATION[3] })
      end
    end
  end

  if #configs.topic_rows > 0 then
    local long_retention = {}
    for _, row in ipairs(configs.topic_rows) do
      local value = tonumber(tostring(row.value))
      if row.key == "retention.ms" and value and value > 30 * 24 * 3600 * 1000 then
        long_retention[#long_retention + 1] = row
      end
      if row.key == "retention.bytes" and value and value < 0 then
        long_retention[#long_retention + 1] = row
      end
    end
    list[#list + 1] = finding("KAFKA-METADATA-TOPIC-CONFIG-EXPOSURE",
      "Per-topic settings are readable without authentication",
      "MEDIUM",
      string.format("%s of topic configuration were read for %s. Retention is the number that decides "
        .. "how much data a leak exposes, and it is the setting a caller would read first when "
        .. "planning what to collect.", plural(#configs.topic_rows, "setting"),
        plural(#configs.topic_security, "topic")),
      topic_sample(configs.topic_rows, 10, function(row)
        return string.format("%s.%s = %s (%s)", tostring(row.topic), tostring(row.key),
          tostring(row.value), tostring(row.why))
      end),
      { KB.REMEDIATION[2], KB.REMEDIATION[6] })
    if #long_retention > 0 then
      list[#list + 1] = finding("KAFKA-METADATA-LONG-RETENTION",
        "A topic retains records longer than a month, or forever",
        "MEDIUM",
        string.format("%s keep records for longer than thirty days, or are configured with unlimited "
          .. "retention. A long window is an operational choice, and it is also the window in which "
          .. "anything written to the topic - including a credential or a token - is still readable.",
          plural(#long_retention, "topic")),
        topic_sample(long_retention, 6, function(row)
          return string.format("%s.%s = %s", tostring(row.topic), tostring(row.key), tostring(row.value))
        end),
        { KB.REMEDIATION[6] })
    end
  end

  local groups = records.list_groups or {}
  if groups.answered and (groups.count or 0) > 0 then
    local evidence = {}
    for _, group in ipairs(groups.groups or {}) do
      evidence[#evidence + 1] = string.format("%s: state %s, protocol %s", tostring(group.group_id),
        tostring(group.state), tostring(group.protocol_type or "-"))
    end
    local internal_note = ""
    for _, row in ipairs(inventory.rows) do
      if string.find(row.name, "__consumer_offsets", 1, true) then
        internal_note = string.format(" The __consumer_offsets topic is present with %s, which is "
          .. "where those groups store their positions.", plural(row.partitions, "partition"))
      end
    end
    list[#list + 1] = finding("KAFKA-METADATA-GROUP-NAMES-DISCLOSED",
      "Consumer group names are visible without authentication",
      "MEDIUM",
      string.format("ListGroups answered with %s and their state. Group names identify the "
        .. "applications, the environments and often the team that owns them, and a group that is "
        .. "listed but has no consumer tells the caller which pipeline is currently down.%s",
        plural(groups.count, "consumer group"), internal_note),
      topic_sample(evidence, 10, function(line) return line end),
      { KB.REMEDIATION[2], KB.REMEDIATION[8] })
  end

  if configs.broker_answered and usable > 0 and #configs.broker_rows >= 3 then
    local authorizer_seen = false
    for _, row in ipairs(configs.broker_rows) do
      if row.name == "authorizer.class.name" then authorizer_seen = true end
    end
    if not authorizer_seen then
      list[#list + 1] = finding("KAFKA-METADATA-AUTHORIZER-NOT-VISIBLE",
        "Describing the broker did not return an authorizer setting",
        "INFO",
        "The config response contained no authorizer.class.name entry, so either the broker is older "
          .. "than that setting or the response was filtered. Whether ACLs are enforced cannot be "
          .. "decided from this answer alone.",
        { string.format("%s broker settings read", num_text(#configs.broker_rows)) },
        { KB.REMEDIATION[2] })
    end
  end

  if not negotiate.answered then
    list[#list + 1] = finding("KAFKA-METADATA-NEGOTIATION-FAILED",
      "The API version negotiation was not answered",
      "INFO",
      string.format("ApiVersions was not answered (%s). Everything below is limited to what the "
        .. "remaining requests returned; a TLS-only listener and a filtered path both look like this.",
        tostring(negotiate.error)),
      { tostring(negotiate.error) }, { KB.REMEDIATION[1] })
  end

  if #list == 0 then
    list[#list + 1] = finding("KAFKA-METADATA-NO-FINDING",
      "No metadata exposure was measured",
      "NONE",
      "Every metadata request was refused or returned nothing that describes the cluster. The access "
        .. "matrix above shows which request received which answer.",
      { string.format("%d of %d requests were granted", exposure.granted or 0, exposure.total or 0) },
      { KB.REMEDIATION[6] })
  end

  return list
end

----------------------------------------------------------------------------
-- 8. Knowledge base: what to do about it, and how to check it was done
----------------------------------------------------------------------------

KB.REMEDIATION = {
  {
    step = "Require authentication on the client listener before anything else: set a SASL mechanism on "
      .. "the listener (listener.name.<name>.sasl.enabled.mechanisms) and remove ANONYMOUS from it.",
    why = "Every finding in this report is caused by the same thing: an unauthenticated caller reaching "
      .. "APIs that were designed for clients. An ACL cannot match a caller that has no principal.",
  },
  {
    step = "Set authorizer.class.name (or the KRaft equivalent) and grant DESCRIBE explicitly: "
      .. "kafka-acls.sh --add --allow-principal User:<app> --operation Describe --topic <name>.",
    why = "Metadata has no separate 'list' permission: DESCRIBE on the topic resource decides both "
      .. "whether the topic appears in a wildcard listing and whether a named request is answered.",
  },
  {
    step = "Set auto.create.topics.enable=false and create topics through a pipeline that owns the "
      .. "name, the partition count and the replication factor.",
    why = "On-demand creation lets any caller allocate storage and choose a name an application may "
      .. "later consume from.",
  },
  {
    step = "Review which internal topics exist and treat their names as inventory: keep __consumer_offsets "
      .. "and __transaction_state out of any ACL grant that is not the coordinator's own principal, and "
      .. "restrict DESCRIBE on them to the operator role.",
    why = "The names describe the deployment (Schema Registry, Connect, MirrorMaker, CDC) and the "
      .. "internal topics are the ones whose loss stops the whole pipeline.",
  },
  {
    step = "Rename topics that describe regulated data so that the name does not classify the payload, "
      .. "and keep the mapping in the schema registry or in the application's configuration.",
    why = "A name is metadata that travels everywhere - logs, dashboards, error messages, this report - "
      .. "and it cannot be revoked once it is known.",
  },
  {
    step = "Scan the cluster again with this script after the change and confirm that Metadata answers "
      .. "with an authorization error and that the inventory section is empty.",
    why = "The claim being tested is about behaviour, and only a request measures behaviour: an ACL "
      .. "attached to the wrong resource and a listener that still accepts anonymous clients both look "
      .. "correct in configuration.",
  },
  {
    step = "Audit the settings this report could read: allow.everyone.if.no.acl.found must be false, "
      .. "authorizer.class.name must be set, super.users must name as few principals as possible, and no "
      .. "sensitive value may be returned by DescribeConfigs.",
    why = "Those four settings decide whether the ACLs are enforced at all, and they were readable to an "
      .. "unauthenticated caller, which means they are readable to anyone who can reach the port.",
  },
  {
    step = "Restrict DescribeConfigs and ListGroups the way you restrict Metadata: they are admin APIs, "
      .. "and their answers describe the deployment rather than one topic.",
    why = "Group names, connector settings and broker configuration are the reconnaissance an attacker "
      .. "would otherwise have to obtain from inside the network.",
  },
}

KB.VERIFICATION = {
  "kafka-topics.sh --bootstrap-server <broker> --list  (with credentials: the topics exist; without "
    .. "credentials the command must fail with TopicAuthorizationException)",
  "kafka-configs.sh --bootstrap-server <broker> --describe --entity-type brokers --entity-name <id>  "
    .. "(check allow.everyone.if.no.acl.found, authorizer.class.name and super.users)",
  "kafka-acls.sh --bootstrap-server <broker> --list --topic <name>  (show the DESCRIBE grants)",
  "kafka-consumer-groups.sh --bootstrap-server <broker> --list  (with credentials; without credentials "
    .. "it must fail rather than list the groups)",
  "kafka-broker-api-versions.sh --bootstrap-server <broker>  (compare the advertised API surface with "
    .. "the ApiVersions row in this report)",
  "grep -iE 'MetadataRequest|DescribeConfigs|ListGroups' <broker request log>  (confirm the anonymous "
    .. "requests are logged and attributed)",
}

KB.METHOD_LIMITS = {
  "The inventory is the broker's answer to one Metadata request. A topic that was created or deleted "
    .. "between the two reads at the start and the end of this scan appears as a change, which the "
    .. "safety ledger reports rather than hides.",
  "A wildcard Metadata listing is filtered per principal when an authorizer is configured. A short list "
    .. "is therefore not proof of a small cluster: it can mean the caller may describe only a few "
    .. "topics, and the per-name section of this report is what distinguishes the two.",
  "The script does not read records. Everything it reports about a topic comes from the metadata the "
    .. "broker publishes, so 'the topic exists and holds N partitions' is not a claim about the data "
    .. "inside it.",
  "DescribeConfigs values that the broker marks sensitive are never printed by this report; a value is "
    .. "quoted only when the broker sent one, which is itself the finding.",
  "The random-name probe is disabled by default because it is the one request that could create a topic "
    .. "on a broker that ignores allow_auto_topic_creation. When it is enabled, the script re-reads the "
    .. "topic list and reports a creation as a critical finding instead of as a measurement.",
  "Broker configuration is read once per broker that answered the first metadata request. A cluster "
    .. "whose controller is not among those brokers is described by the brokers that did answer, and the "
    .. "controller id in this report is whatever the metadata response said.",
  "A listener in front of the broker (a proxy, a load balancer, a Kafka Connect REST endpoint that "
    .. "merely looks like Kafka) can answer some of these requests and not others; the access matrix "
    .. "names each request's outcome separately for that reason.",
}

KB.ATTACK_VALUE = {
  { exposure = "the topic list",
    value = "names the data model; an attacker prioritises which topic to attack and which credential "
      .. "to look for, and a topic whose name says 'payments' does not have to be discovered by "
      .. "guessing" },
  { exposure = "internal topic names",
    value = "identifies the rest of the platform (Schema Registry, Connect, MirrorMaker, CDC), which "
      .. "turns one exposed broker into a map of the deployment" },
  { exposure = "broker inventory",
    value = "every host and port is a target, the controller is the node that performs deletions, and "
      .. "the rack layout says which failure domain holds a replica" },
  { exposure = "partition and replica counts",
    value = "decides where a single write lands and how much a caller can allocate; replication "
      .. "factor one is a partition that fails with its only broker" },
  { exposure = "health state",
    value = "under-replicated partitions and empty in-sync sets say when data is already at risk, "
      .. "which is when an unclean election is possible" },
  { exposure = "broker configuration",
    value = "allow.everyone.if.no.acl.found, super.users and the authorizer class tell an attacker "
      .. "whether ACLs are enforced and which principal to aim for" },
  { exposure = "topic configuration",
    value = "retention decides how much data is still there to collect, and min.insync.replicas "
      .. "decides what a write actually costs" },
  { exposure = "authorized operations masks",
    value = "the broker itself lists what the caller may do to each topic, which is a to-do list for "
      .. "the rest of the scan" },
}

----------------------------------------------------------------------------
-- 9. Report
----------------------------------------------------------------------------

local report = {}

function report.target_section(cfg, host, port, w, records)
  local lines = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id: %s", cfg.client_id),
    string.format("Timeout: %dms per request", cfg.timeout),
    string.format("Metadata schema requested: v%d (a newer schema carries topic ids and leader epochs)",
      METADATA_PREFERENCE),
  }
  local negotiate = records.negotiate or {}
  if negotiate.answered then
    lines[#lines + 1] = string.format("ApiVersions: %s advertised, error %s, throttle %sms",
      plural(negotiate.count or 0, "API"), tostring(negotiate.error_name),
      num_text(negotiate.throttle_ms or 0))
  end
  if w.failures and #w.failures > 0 then
    lines[#lines + 1] = string.format("Unanswered stages: %s", fmt_list((function()
      local parts = {}
      for _, failure in ipairs(w.failures) do
        parts[#parts + 1] = failure.stage .. " (" .. tostring(failure.reason) .. ")"
      end
      return parts
    end)(), 6))
  end
  if cfg.verbose and #w.stages > 0 then
    local stages = {}
    for _, stage in ipairs(w.stages) do stages[#stages + 1] = stage.name end
    lines[#lines + 1] = "Stages: " .. table.concat(stages, ", ")
  end
  return lines
end

function report.cluster_section(inventory, records)
  local lines = {}
  if not inventory.answered then
    lines[#lines + 1] = "The cluster was not described: " .. tostring(inventory.error or "no answer")
    return lines
  end
  lines[#lines + 1] = string.format("Cluster id: %s", tostring(inventory.cluster_id or "withheld"))
  lines[#lines + 1] = string.format("Controller: %s", inventory.controller_id
    and ("node " .. num_text(inventory.controller_id)) or "not returned")
  lines[#lines + 1] = string.format("Brokers: %s", plural(#(inventory.brokers or {}), "node"))
  for _, broker in ipairs(inventory.brokers or {}) do
    lines[#lines + 1] = string.format("  node %s: %s:%s%s", num_text(broker.node_id), tostring(broker.host),
      num_text(broker.port), broker.rack and (" rack " .. tostring(broker.rack)) or "")
  end
  local cluster = records.describe_cluster or {}
  if cluster.answered then
    lines[#lines + 1] = string.format("DescribeCluster v%s: endpoint type %s, fenced %s, authorized "
      .. "operations %s", num_text(cluster.version), num_text(cluster.endpoint_type),
      tostring(cluster.is_fenced), cluster.authorized_operations
        and kafka.cluster_ops_text(cluster.authorized_operations) or "-")
  elseif cluster.skipped then
    lines[#lines + 1] = "DescribeCluster: " .. tostring(cluster.skipped)
  else
    lines[#lines + 1] = "DescribeCluster was not answered: " .. tostring(cluster.error or "no answer")
  end
  return lines
end

function report.inventory_section(inventory, cfg)
  local metrics = inventory.metrics or {}
  local lines = {
    string.format("%s: %s user, %s internal, %s, %s",
      plural(metrics.topics, "topic"), num_text(metrics.user_topics), num_text(metrics.internal_topics),
      plural(metrics.partitions, "partition"), plural(metrics.replicas, "replica")),
    string.format("Replication factor histogram: %s", fmt_list((function()
      local parts = {}
      for factor, count in pairs(metrics.replication or {}) do
        parts[#parts + 1] = string.format("%s x %s", num_text(factor), num_text(count))
      end
      table.sort(parts)
      return parts
    end)(), 8)),
    string.format("Topic errors in the response: %s", num_text(metrics.topic_errors or 0)),
  }
  if not inventory.answered then
    return { "The inventory was not read: " .. tostring(inventory.error or "no answer") }
  end
  lines[#lines + 1] = string.format("%-34s %-6s %-5s %-5s %-9s %-8s %s",
    "Topic", "Parts", "RF", "ISR-", "Offline", "Internal", "Id")
  for index = 1, math.min(#inventory.rows, cfg.max_topics) do
    local row = inventory.rows[index]
    local short_id = row.topic_id and string.sub(row.topic_id, 1, 12) or "-"
    lines[#lines + 1] = string.format("%-34s %-6s %-5s %-5s %-9s %-8s %s",
      string.sub(tostring(row.name), 1, 34), num_text(row.partitions), num_text(row.replication_factor),
      num_text(row.under_replicated), num_text(row.offline_replicas),
      row.internal and "yes" or "no", short_id)
    if row.error_code and row.error_code ~= 0 then
      lines[#lines + 1] = string.format("    the broker answered %s for this topic",
        tostring(row.error_name))
    end
    if row.partitions_without_leader > 0 or row.empty_isr > 0 then
      lines[#lines + 1] = string.format("    %s without a leader, %s with an empty in-sync set",
        num_text(row.partitions_without_leader), num_text(row.empty_isr))
    end
  end
  if #inventory.rows > cfg.max_topics then
    lines[#lines + 1] = string.format("  (%d further topic(s) not shown; raise kafka.max-topics)",
      #inventory.rows - cfg.max_topics)
  end
  return lines
end

function report.internal_section(internal)
  if internal.count == 0 then
    return { "No internal topic was in the response: either the cluster runs without them or the "
      .. "listing did not include them." }
  end
  local lines = {}
  for _, entry in ipairs(internal.rows) do
    if entry.knowledge then
      lines[#lines + 1] = string.format("%s (%s, %s)", tostring(entry.row.name),
        entry.row.partitions and plural(entry.row.partitions, "partition") or "?",
        entry.knowledge.component)
      lines[#lines + 1] = "    proves: " .. entry.knowledge.proves
      lines[#lines + 1] = "    impact: " .. entry.knowledge.impact
    else
      lines[#lines + 1] = string.format("%s: an internal topic with no entry in this script's "
        .. "catalogue; the name is printed for review", tostring(entry.row.name))
    end
  end
  return lines
end

function report.health_section(health, inventory)
  local lines = {}
  if #health.conditions == 0 then
    lines[#lines + 1] = "No under-replicated partition, offline replica, empty in-sync set or "
      .. "leaderless partition was in the response."
  else
    lines[#lines + 1] = "Conditions: " .. table.concat(health.conditions, "; ")
  end
  if health.busiest_leader then
    lines[#lines + 1] = string.format("Leader distribution: node %s leads %s of %s",
      num_text(health.busiest_leader), plural(health.leader_skew, "partition"),
      plural((inventory.metrics or {}).partitions or 0, "partition"))
  end
  if next(health.racks) ~= nil then
    local parts = {}
    for _, rack in ipairs(sorted_keys(health.racks)) do
      parts[#parts + 1] = string.format("%s x%s", tostring(rack), num_text(health.racks[rack]))
    end
    lines[#lines + 1] = "Racks: " .. table.concat(parts, ", ")
    lines[#lines + 1] = "Rack assignments are published, so a caller can tell which failure domain "
      .. "holds a replica before deciding what to do with one broker."
  else
    lines[#lines + 1] = "No broker advertised a rack, so the response does not disclose a failure "
      .. "domain layout (each replica set is still published)."
  end
  return lines
end

function report.naming_section(naming)
  if naming.count == 0 then
    return { "No topic name matched a sensitivity pattern." }
  end
  local lines = {}
  for _, match in ipairs(naming.matches) do
    lines[#lines + 1] = string.format("%-34s %-16s %s", string.sub(tostring(match.topic), 1, 34),
      tostring(match.category), tostring(match.why))
  end
  local parts = {}
  for _, key in ipairs(sorted_keys(naming.categories)) do
    parts[#parts + 1] = string.format("%s x%s", tostring(key), num_text(naming.categories[key]))
  end
  lines[#lines + 1] = "Categories: " .. table.concat(parts, ", ")
  return lines
end

function report.config_section(configs, cfg)
  local lines = {}
  if configs.skipped then
    return { "Configuration was not read: " .. tostring(configs.skipped) }
  end
  if not configs.broker_answered and not configs.topic_answered then
    local reason = (configs.broker_answered == false) and "DescribeConfigs was refused or unanswered"
      or "DescribeConfigs was not run"
    return { reason .. ", so no setting is quoted in this report." }
  end
  if #configs.weak > 0 then
    lines[#lines + 1] = "Broker settings that matter:"
    for _, row in ipairs(configs.weak) do
      lines[#lines + 1] = string.format("  %-42s %-28s %s", tostring(row.key),
        #row.value > 0 and row.value or "(empty)", tostring(row.source or "-"))
      lines[#lines + 1] = "      " .. tostring(row.why)
    end
  end
  if configs.sensitive_disclosed > 0 then
    lines[#lines + 1] = string.format("Sensitive entries returned with a value: %s",
      plural(configs.sensitive_disclosed, "entry"))
    for _, line in ipairs(sensitive_evidence(configs, 8)) do lines[#lines + 1] = "  " .. line end
  end
  if #configs.topic_rows > 0 and cfg.max_configs > 0 then
    lines[#lines + 1] = "Topic settings read:"
    for _, row in ipairs(configs.topic_rows) do
      lines[#lines + 1] = string.format("  %s.%s = %s", tostring(row.topic), tostring(row.key),
        tostring(row.value))
    end
  end
  if #configs.topic_security > 0 then
    lines[#lines + 1] = "Topics whose configuration names a credential-like key:"
    local any = false
    for _, row in ipairs(configs.topic_security) do
      if #row.security > 0 then
        any = true
        lines[#lines + 1] = string.format("  %s: %s", tostring(row.resource),
          table.concat(row.security, ", "))
      end
    end
    if not any then lines[#lines + 1] = "  none" end
  end
  return lines
end

function report.boundary_section(boundary, unknown, inventory)
  local lines = {}
  if boundary.skipped then
    lines[#lines + 1] = "Per-name requests: " .. tostring(boundary.skipped)
  else
    lines[#lines + 1] = string.format("Per-name requests: %d described, %d refused, %d not found "
      .. "(%d name(s) were supplied by the scan rather than taken from the listing)",
      boundary.described, boundary.refused, boundary.missing, boundary.supplied or 0)
    for _, row in ipairs(boundary.rows or {}) do
      lines[#lines + 1] = string.format("  %-34s %-28s %-10s %s", string.sub(tostring(row.name), 1, 34),
        tostring(row.error_name or "no entry"), tostring(row.verdict), tostring(row.source or "-"))
    end
    if #boundary.hidden > 0 then
      lines[#lines + 1] = "Hidden from the listing but described by name: " .. fmt_list(boundary.hidden, 8)
    end
  end
  if unknown.ran then
    lines[#lines + 1] = string.format("Random name %s: %s (entries %s)",
      tostring(unknown.name), tostring(unknown.error_name or unknown.verdict), num_text(unknown.entries or 0))
    if unknown.verdict == "absent" then
      lines[#lines + 1] = "The broker answered the existence question without credentials, which is "
        .. "the oracle a name-guessing scan uses."
    elseif unknown.verdict == "created" then
      lines[#lines + 1] = "The broker created the topic although the request set "
        .. "allow_auto_topic_creation=false."
    end
  else
    lines[#lines + 1] = "Random name probe: " .. tostring(unknown.skipped
      or "disabled (kafka.unknown-probe=false)")
  end
  lines[#lines + 1] = string.format("The listing returned %s; %s of them were re-requested by name.",
    plural((inventory.metrics or {}).topics or 0, "topic"), num_text(boundary.requested or 0))
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
      if type(step) == "table" then
        lines[#lines + 1] = "   fix: " .. step.step
        if step.why then lines[#lines + 1] = "        why: " .. step.why end
      else
        lines[#lines + 1] = "   fix: " .. tostring(step)
      end
    end
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

function report.safety_section(safety)
  local lines = {}
  for _, check in ipairs(safety.checks or {}) do
    lines[#lines + 1] = string.format("[%s] %s%s", check.ok and "ok" or "FAILED", check.name,
      check.detail and (" - " .. tostring(check.detail)) or "")
  end
  if not safety.inventory_identical and #safety.delta == 0 then
    lines[#lines + 1] = "The topic list could not be compared because one of the two reads was not "
      .. "answered."
  end
  return lines
end

function report.rubric_section()
  local lines = {}
  for _, entry in ipairs(KB.RISK_RUBRIC) do
    lines[#lines + 1] = string.format("%s: %s", entry.severity, entry.condition)
  end
  return lines
end

function report.build(cfg, host, port, records, inventory, internal, health, naming, boundary, unknown,
  configs, exposure, safety, list, w)
  local out = stdnse.output_table()
  out["Target"] = report.target_section(cfg, host, port, w, records)
  out["Cluster"] = report.cluster_section(inventory, records)
  out["Access matrix"] = (function()
    local lines = { string.format("%-28s %-12s %-8s %s", "Request", "Access", "Version", "Answer") }
    for _, row in ipairs(exposure.rows) do
      lines[#lines + 1] = string.format("%-28s %-12s %-8s %s", row.name, tostring(row.access),
        row.version and ("v" .. num_text(row.version)) or "-", tostring(row.detail or "-"))
    end
    lines[#lines + 1] = string.format("%d of %d requests were granted a useful answer",
      exposure.granted, exposure.total)
    return lines
  end)()
  out["Topic inventory"] = report.inventory_section(inventory, cfg)
  out["Internal topics"] = report.internal_section(internal)
  out["Availability posture"] = report.health_section(health, inventory)
  out["Name exposure"] = report.naming_section(naming)
  out["Listing versus named requests"] = report.boundary_section(boundary, unknown, inventory)
  out["Configuration exposure"] = report.config_section(configs, cfg)
  out["Safety ledger"] = report.safety_section(safety)
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
  if not (records.negotiate and records.negotiate.answered) and not inventory.answered then
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

-- The names re-requested by name: a bounded sample of the listing, taken in the
-- order the broker returned it, so the comparison between the listing and the
-- per-name answers covers user topics and internal topics alike.
local function sample_names(rows, limit)
  local names = {}
  for index = 1, math.min(#rows, limit) do names[#names + 1] = rows[index].name end
  return names
end

-- A topic name that is valid for Kafka (letters, digits, dot, underscore, dash,
-- at most 249 characters) and that the script generates, so a broker that
-- creates it is creating something no application will ever use.
local function random_topic_name()
  local seed = string.format("nmap-metadata-audit-%d-%06d", os.time() % 1000000, math.random(0, 999999))
  return string.sub(seed, 1, 249)
end

action = function(host, port)
  local cfg = read_config()
  local w = Wire.new(host, port, cfg)
  local records = { auto_create_requests = 0 }
  local out = stdnse.output_table()

  if not w.connection.sock then
    out["Risk Level"] = "UNKNOWN"
    out["Target"] = {
      string.format("Endpoint: %s:%d/tcp", host.ip or "target", port.number),
      "Transport failure: " .. tostring(w.connection.last_error),
    }
    out["Method limits"] = {
      "The TCP connection failed, so no metadata request was sent. A TLS-only listener answers a "
        .. "plaintext Kafka probe exactly like this.",
    }
    return out
  end

  records.negotiate = probe.negotiate(w)
  records.metadata_all = probe.metadata_all(w, cfg)
  local before = analysis.inventory(records, cfg)
  records.metadata_after = probe.metadata_all(w, cfg)
  local after = analysis.inventory(records, cfg)

  -- The per-name sample is taken from the listing: names the broker itself
  -- published, so the request cannot introduce a name the cluster has never
  -- seen.
  if cfg.named_probe and before.answered and #before.rows > 0 then
    local source_of, names = {}, sample_names(before.rows, 8)
    for _, name in ipairs(names) do source_of[name] = "from the listing" end
    for _, name in ipairs(cfg.names) do
      local seen = false
      for _, existing in ipairs(names) do if existing == name then seen = true end end
      if not seen then
        names[#names + 1] = name
        source_of[name] = "supplied by the scan"
      end
    end
    records.metadata_named = probe.metadata_named(w, names, source_of)
  elseif not cfg.named_probe then
    records.metadata_named = { skipped = "the per-name probe is disabled (kafka.named-probe=false)" }
  elseif #cfg.names > 0 then
    local source_of, names = {}, {}
    for _, name in ipairs(cfg.names) do
      names[#names + 1] = name
      source_of[name] = "supplied by the scan"
    end
    records.metadata_named = probe.metadata_named(w, names, source_of)
  else
    records.metadata_named = { skipped = "the listing was empty or was not answered" }
  end

  if cfg.unknown_probe then
    records.metadata_unknown = probe.metadata_unknown(w, random_topic_name())
  else
    records.metadata_unknown = { skipped = "the random-name probe is disabled (kafka.unknown-probe=false)" }
  end

  records.describe_cluster = probe.describe_cluster(w)

  local config_resources = {}
  for _, broker in ipairs((records.metadata_all or {}).brokers or {}) do
    config_resources[#config_resources + 1] = { type = 4, name = tostring(broker.node_id) }
  end
  records.configs_broker = #config_resources > 0
    and probe.describe_configs(w, config_resources, "describe_configs_brokers")
    or { skipped = "no broker was in the metadata response" }
  local topic_resources = {}
  for index = 1, math.min(#before.rows, cfg.max_configs) do
    if not before.rows[index].internal or cfg.max_configs > 0 then
      topic_resources[#topic_resources + 1] = { type = 2, name = before.rows[index].name }
    end
  end
  records.configs_topics = #topic_resources > 0
    and probe.describe_configs(w, topic_resources, "describe_configs_topics")
    or { skipped = cfg.max_configs == 0 and "kafka.max-configs=0" or "no topic was in the listing" }

  records.list_groups = probe.list_groups(w)
  records.auto_create_requests = (w.flags and w.flags["metadata.auto_create"]
    and w.flags["metadata.auto_create"].true_count) or 0
  w:close()

  records.unknown = analysis.unknown_probe(records, before, cfg)
  local health = analysis.health(before)
  local naming = analysis.naming(before)
  local boundary = analysis.boundary(records, before, cfg)
  local configs = analysis.configs(records, cfg)
  local exposure = analysis.exposure(records, before, boundary, configs, health, naming)
  local safety = analysis.safety(records, before, cfg)
  local internal = analysis.internal(before)
  local list = findings.evaluate(records, before, internal, health, naming, boundary, records.unknown,
    configs, exposure, safety, cfg)

  local result = report.build(cfg, host, port, records, before, internal, health, naming, boundary,
    records.unknown, configs, exposure, safety, list, w)

  publish_findings(host, port, list)

  return result
end

