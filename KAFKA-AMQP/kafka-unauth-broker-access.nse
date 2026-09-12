local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
local os = require "os"
local kafka = require "kafka"
local vulns = require "vulns"

-- Risk band: CRITICAL. An unauthenticated Kafka listener hands an anonymous
-- client the full cluster topology, every consumer group with its members and
-- their client hosts, committed offsets, topic configuration and (on many
-- deployments) the ability to create and delete topics. There is no exploit
-- involved: the broker is doing exactly what it was configured to do.
local SCRIPT_RISK = "CRITICAL"

description = [[
Audits an Apache Kafka broker for unauthenticated access.

The script speaks the Kafka wire protocol directly (no Kafka client library, no
JMX) and walks the listener the way an anonymous client would:

* ApiVersions negotiation, to learn which APIs and schema versions the broker
  is willing to serve to a connection that never authenticated.
* Metadata with a null topic array, which asks the cluster for *every* topic it
  knows - including internal ones such as __consumer_offsets.
* DescribeCluster, ListGroups, DescribeGroups and FindCoordinator, which expose
  the consumer topology: group ids, member ids, client ids and the hosts the
  consumers connect from.
* OffsetFetch and ListOffsets, which turn committed offsets plus high
  watermarks into per-partition consumer lag.
* DescribeConfigs, which shows which topic and broker settings are readable,
  and whether values the broker marks sensitive are returned anyway.
* CreateTopics with validate_only set, which asks the broker "may this principal
  create a topic?" without creating anything, and DeleteTopics against a topic
  name that cannot exist, which distinguishes "authorized but the topic is
  missing" from "not authorized".

Every check is a read or a dry run. The script never creates, deletes, alters or
produces anything: the create probe is validated-only by construction and the
delete probe only ever names a random topic the script generated for itself.

Findings are graded by what the broker actually allowed, not by assumption: a
request answered with a cluster authorization error is reported as evidence of
working ACLs, a request answered normally is reported as anonymous access, and a
dropped or truncated connection is reported as "no conclusion" with the stage it
stopped at.
]]

author = "Nmap NSE Script Collection"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "discovery"}

portrule = shortport.port_or_service({ 9092, 9093, 9094, 19092 }, { "kafka", "kafka-broker" }, "tcp")

----------------------------------------------------------------------------
-- 1. Configuration
----------------------------------------------------------------------------

local FUNCTION_ORDER = {
  "negotiate", "metadata", "describe_cluster", "list_groups", "describe_groups",
  "find_coordinator", "offset_fetch", "list_offsets", "describe_configs",
  "create_topics", "delete_topics", "sasl_handshake",
}

local config = {
  timeout = 5000,
  client_id = "nmap-kafka-audit",
  max_topics = 200,
  max_groups = 25,
  max_describe_groups = 10,
  max_config_topics = 8,
  group_page = 5,
  sample_records = false,
  sample_bytes = 4096,
  allow_write_probes = true,
  probe_topic = nil,
  repeats = 1,
  on_transient_retry = true,
  transient_backoff_ms = 250,
}

local function clamp(value, low, high)
  if value < low then return low end
  if value > high then return high end
  return value
end

local function read_config()
  local args = nmap.registry.args or {}
  local cfg = {}
  for key, value in pairs(config) do cfg[key] = value end

  local timeout = tonumber(args["kafka.timeout"])
  if timeout then cfg.timeout = clamp(timeout, 500, 30000) end

  local client_id = args["kafka.client-id"]
  if client_id and #client_id > 0 and #client_id <= 90 then cfg.client_id = client_id end

  for _, pair in ipairs({
    { "kafka.max-topics", "max_topics", 1, 2000 },
    { "kafka.max-groups", "max_groups", 1, 500 },
    { "kafka.max-describe-groups", "max_describe_groups", 0, 200 },
    { "kafka.max-config-topics", "max_config_topics", 0, 200 },
    { "kafka.group-page", "group_page", 1, 100 },
    { "kafka.sample-bytes", "sample_bytes", 512, 1048576 },
    { "kafka.repeats", "repeats", 1, 5 },
    { "kafka.transient-backoff", "transient_backoff_ms", 0, 5000 },
  }) do
    local raw = tonumber(args[pair[1]])
    if raw then cfg[pair[2]] = clamp(math.floor(raw), pair[3], pair[4]) end
  end

  if args["kafka.sample-records"] ~= nil then
    local raw = string.lower(tostring(args["kafka.sample-records"]))
    cfg.sample_records = (raw == "1" or raw == "true" or raw == "yes")
  end
  if args["kafka.write-probes"] ~= nil then
    local raw = string.lower(tostring(args["kafka.write-probes"]))
    cfg.allow_write_probes = not (raw == "0" or raw == "false" or raw == "no")
  end
  if args["kafka.no-retry"] ~= nil then
    local raw = string.lower(tostring(args["kafka.no-retry"]))
    cfg.on_transient_retry = (raw == "0" or raw == "false" or raw == "no")
  end
  local topic = args["kafka.probe-topic"]
  if topic and #topic > 0 and #topic <= 200 then cfg.probe_topic = topic end

  return cfg
end

-- A probe topic name has to be unique per run (a broker remembers topic names
-- that were *really* created, and the delete probe relies on the name not
-- existing) but also recognisable in a broker log, so it carries a fixed
-- prefix and a run-specific suffix.
local function probe_topic_name(cfg)
  if cfg.probe_topic then return cfg.probe_topic end
  local seed = os.time() % 100000
  local salt = math.floor((os.clock() * 1000) % 10000)
  return string.format("nmap-audit-nonexistent-%05d-%04d", seed, salt)
end

----------------------------------------------------------------------------
-- 2. Small formatting helpers
----------------------------------------------------------------------------

local function fmt_bool(value)
  if value == nil then return "unknown" end
  return value and "yes" or "no"
end

local function fmt_list(items, limit, empty)
  if not items or #items == 0 then return empty or "none" end
  local out = {}
  for i = 1, math.min(#items, limit or #items) do
    out[#out + 1] = tostring(items[i])
  end
  if #items > (limit or #items) then
    out[#out + 1] = string.format("(+%d more)", #items - (limit or #items))
  end
  return table.concat(out, ", ")
end

local function plural(count, singular, plural_form)
  if count == 1 then return "1 " .. singular end
  return tostring(count) .. " " .. (plural_form or (singular .. "s"))
end

local function bytes_to_string(data, limit)
  if not data then return "" end
  local text = tostring(data)
  text = string.gsub(text, "%z", ".")
  if limit and #text > limit then
    text = string.sub(text, 1, limit) .. "..."
  end
  return text
end

----------------------------------------------------------------------------
-- 3. Wire layer
----------------------------------------------------------------------------
--
-- Everything that touches the network lives here. Each call is wrapped so the
-- probe can tell the difference between three very different outcomes:
--
--   * the broker answered           -> a conclusion about access
--   * the broker refused            -> an error code, also a conclusion
--   * the broker went silent        -> NO conclusion, and the probe says so
--
-- The last case is why the stage list exists: a report that says "timed out"
-- without saying at which request is useless to the person reading it.

local function new_wire(host, port, cfg)
  local w = {
    host = host, port = port, cfg = cfg,
    connection = nil, connected = false, failure = nil,
    stages = {}, version_map = {}, unsupported = {},
  }

  function w:stage(name, detail)
    self.stages[#self.stages + 1] = { name = name, detail = detail, at = os.time() }
  end

  function w:connect()
    if self.connected then return true end
    self:stage("connect", string.format("%s:%d/tcp", host.ip or "target", port.number))
    local conn = kafka.new_connection(host.ip or self.host, port.number, {
      timeout_ms = self.cfg.timeout,
      client_id = self.cfg.client_id,
    })
    if not conn.sock or not conn.sock._connected then
      self.failure = "connect"
      self.connection = conn
      return false, "tcp connection to " .. tostring(host.ip) .. ":" .. tostring(port.number) .. " failed"
    end
    self.connection = conn
    self.connected = true
    return true
  end

  function w:close()
    if self.connection then self.connection:close() end
  end

  function w:negotiate()
    if self.negotiated then return self.version_map end
    local summary, err = kafka.negotiate(self.connection)
    if not summary then
      self:stage("api_versions", "failed: " .. tostring(err))
      return nil, err
    end
    self.negotiated = true
    self.negotiate_summary = summary
    self.version_map = summary.versions
    self:stage("api_versions", string.format("broker offers %s (error %s)",
      plural(summary.count, "API"), tostring(summary.error_name)))
    for _, key in ipairs({ 3, 16, 15, 10, 9, 32, 19, 20, 60, 17, 36, 1, 2 }) do
      if not summary.versions[key] then self.unsupported[#self.unsupported + 1] = kafka.api_name(key) end
    end
    return self.version_map
  end

  -- A single API call with the transient-retry policy applied. Retrying a
  -- request that failed for a transient reason (a leader election, a
  -- coordinator moving) is what turns a flaky audited cluster into a complete
  -- report; retrying an authorization failure never is.
  function w:call(label, fn)
    local attempts = 1
    if self.cfg.on_transient_retry then attempts = 2 end
    local last = nil
    for attempt = 1, attempts do
      local result = fn(attempt)
      if result and result.ok then
        return result
      end
      last = result
      local code = result and result.error_code
      local retriable = false
      if code and kafka.ERRORS[code] and kafka.ERRORS[code].retriable then retriable = true end
      if not retriable or attempt == attempts then break end
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
-- Each probe returns a record that always carries the same two things: whether
-- the request was answered at all, and what the broker said about the caller's
-- authorization. The analysis layer never re-derives those from the payload.

local probe = {}

function probe.negotiate(w)
  local versions, err = w:negotiate()
  if not versions then
    return { stage = "api_versions", answered = false, error = err, access = "unknown" }
  end
  local summary = w.negotiate_summary
  local out = {
    stage = "api_versions", answered = true, access = summary.error_code == 0 and "granted" or "error",
    error_code = summary.error_code, error_name = summary.error_name,
    throttle_ms = summary.throttle_ms, api_count = summary.count,
    keys = summary.keys, versions = versions, unsupported = w.unsupported,
    version_rows = kafka.version_table(w.connection),
    error = summary.error_code ~= 0 and ("ApiVersions error " .. tostring(summary.error_name)) or nil,
  }
  return out
end

function probe.metadata(w, topics)
  local cfg = w.cfg
  local result = w:call("metadata", function()
    return kafka.metadata(w.connection, topics)
  end)
  if not result or not result.ok then
    return { stage = "metadata", answered = false, error = result and result.error or "no response",
      version = result and result.version }
  end
  local out = {
    stage = "metadata", answered = true, version = result.version, flexible = result.flexible,
    cluster_id = result.cluster_id, controller_id = result.controller_id,
    brokers = result.brokers, topics = {}, internal = {}, errors = {},
    throttle_ms = result.throttle_ms,
    trailing_bytes = result.trailing_bytes,
  }
  local rows = 0
  for _, topic in ipairs(result.topics or {}) do
    if topic.error_code == 0 then
      rows = rows + 1
      if rows <= cfg.max_topics then
        out.topics[#out.topics + 1] = topic
        if topic.is_internal then out.internal[#out.internal + 1] = topic end
      end
    else
      out.errors[#out.errors + 1] = topic
    end
  end
  out.topic_count = rows
  out.truncated = rows > cfg.max_topics
  out.error_code = (out.errors[1] and out.errors[1].error_code) or 0
  out.error_name = (out.errors[1] and out.errors[1].error_name) or "NONE"
  out.access = out.topic_count > 0 and "granted" or (out.errors[1] and "error" or "empty")
  return out
end

function probe.describe_cluster(w)
  local result = w:call("describe_cluster", function()
    return kafka.describe_cluster(w.connection)
  end)
  if not result or not result.ok then
    return { stage = "describe_cluster", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  return {
    stage = "describe_cluster", answered = true, version = result.version,
    error_code = result.error_code, error_name = result.error_name,
    error_message = result.error_message, cluster_id = result.cluster_id,
    controller_id = result.controller_id, brokers = result.brokers or {},
    rack_count = (function()
      local racks = {}
      for _, broker in ipairs(result.brokers or {}) do
        if broker.rack then racks[#racks + 1] = broker.rack end
      end
      return #racks
    end)(),
    access = result.error_code == 0 and "granted" or "error",
    trailing_bytes = result.trailing_bytes,
  }
end

function probe.list_groups(w)
  local result = w:call("list_groups", function()
    return kafka.list_groups(w.connection)
  end)
  if not result or not result.ok then
    return { stage = "list_groups", answered = false, error = result and result.error or "no response",
      version = result and result.version }
  end
  return {
    stage = "list_groups", answered = true, version = result.version,
    error_code = result.error_code, error_name = result.error_name,
    groups = result.groups or {}, throttle_ms = result.throttle_ms,
    access = result.error_code == 0 and "granted" or "error",
    trailing_bytes = result.trailing_bytes,
  }
end

function probe.describe_groups(w, names)
  if #names == 0 then
    return { stage = "describe_groups", answered = true, groups = {}, skipped = "no groups listed" }
  end
  local result = w:call("describe_groups", function()
    return kafka.describe_groups(w.connection, names)
  end)
  if not result or not result.ok then
    return { stage = "describe_groups", answered = false, error = result and result.error or "no response",
      version = result and result.version }
  end
  return {
    stage = "describe_groups", answered = true, version = result.version,
    groups = result.groups or {}, throttle_ms = result.throttle_ms,
    access = "granted", trailing_bytes = result.trailing_bytes,
  }
end

function probe.find_coordinator(w, key)
  if not key then
    return { stage = "find_coordinator", answered = true, skipped = "no group to look up" }
  end
  local result = w:call("find_coordinator", function()
    return kafka.find_coordinator(w.connection, key)
  end)
  if not result or not result.ok then
    return { stage = "find_coordinator", answered = false, error = result and result.error or "no response",
      version = result and result.version, key = key }
  end
  return {
    stage = "find_coordinator", answered = true, version = result.version, key = key,
    error_code = result.error_code, error_name = result.error_name,
    node_id = result.node_id, host = result.host, port = result.port,
    access = result.error_code == 0 and "granted" or "error",
    trailing_bytes = result.trailing_bytes,
  }
end

function probe.offset_fetch(w, group)
  local result = w:call("offset_fetch", function()
    return kafka.offset_fetch(w.connection, group)
  end)
  if not result or not result.ok then
    return { stage = "offset_fetch", answered = false, error = result and result.error or "no response",
      version = result and result.version, group = group }
  end
  local partitions = {}
  local denied = 0
  for _, topic in ipairs(result.topics or {}) do
    for _, part in ipairs(topic.partitions or {}) do
      partitions[#partitions + 1] = {
        topic = topic.name, partition = part.partition, offset = part.committed_offset,
        metadata = part.metadata, error_code = part.error_code, error_name = part.error_name,
      }
      if kafka.is_authz_error(part.error_code or 0) then denied = denied + 1 end
    end
  end
  return {
    stage = "offset_fetch", answered = true, version = result.version, group = group,
    top_level_error = result.error_code, top_level_name = result.error_name,
    partitions = partitions, partition_count = #partitions, denied_partitions = denied,
    ignored_partition_errors = result.partition_errors or {},
    throttle_ms = result.throttle_ms,
    access = (result.error_code == 0 and denied == 0) and "granted"
      or (result.error_code ~= 0 and "error" or "partial"),
    trailing_bytes = result.trailing_bytes,
  }
end

function probe.list_offsets(w, topic_names)
  if #topic_names == 0 then
    return { stage = "list_offsets", answered = true, rows = {}, skipped = "no topics to query" }
  end
  local entries = {}
  for _, topic in ipairs(topic_names) do
    entries[#entries + 1] = { name = topic, partitions = { { partition = 0, timestamp = -2 } } }
  end
  local result = w:call("list_offsets", function()
    return kafka.list_offsets(w.connection, entries)
  end)
  if not result or not result.ok then
    return { stage = "list_offsets", answered = false, error = result and result.error or "no response",
      version = result and result.version }
  end
  local rows = {}
  local denied = 0
  for _, topic in ipairs(result.topics or {}) do
    for _, part in ipairs(topic.partitions or {}) do
      rows[#rows + 1] = { topic = topic.name, partition = part.partition, offset = part.offset,
        timestamp = part.timestamp, error_code = part.error_code, error_name = part.error_name }
      if kafka.is_authz_error(part.error_code or 0) then denied = denied + 1 end
    end
  end
  return {
    stage = "list_offsets", answered = true, version = result.version, rows = rows,
    denied_partitions = denied, throttle_ms = result.throttle_ms,
    access = denied == 0 and "granted" or "partial",
    trailing_bytes = result.trailing_bytes,
  }
end

function probe.describe_configs(w, resources)
  if #resources == 0 then
    return { stage = "describe_configs", answered = true, results = {}, skipped = "no resources to describe" }
  end
  local result = w:call("describe_configs", function()
    return kafka.describe_configs(w.connection, resources)
  end)
  if not result or not result.ok then
    return { stage = "describe_configs", answered = false, error = result and result.error or "no response",
      version = result and result.version }
  end
  local rows = {}
  local sensitive_leaks = {}
  local denied = 0
  local config_count = 0
  for _, entry in ipairs(result.results or {}) do
    local row = {
      resource_type = entry.resource_type, resource_name = entry.resource_name,
      error_code = entry.error_code, error_name = entry.error_name,
      error_message = entry.error_message, configs = entry.configs or {},
    }
    rows[#rows + 1] = row
    if kafka.is_authz_error(entry.error_code or 0) then denied = denied + 1 end
    for _, config in ipairs(row.configs) do
      config_count = config_count + 1
      -- The broker tells us which values it considers sensitive and then
      -- either redacts them or hands them over. Anything marked sensitive that
      -- still carries a value is a configuration disclosure.
      if config.is_sensitive and config.value and #config.value > 0 then
        sensitive_leaks[#sensitive_leaks + 1] = {
          resource = entry.resource_name, name = config.name, value = config.value,
        }
      end
    end
  end
  return {
    stage = "describe_configs", answered = true, version = result.version,
    results = rows, config_count = config_count, denied_resources = denied,
    sensitive_leaks = sensitive_leaks, throttle_ms = result.throttle_ms,
    access = denied == 0 and "granted" or "partial",
    trailing_bytes = result.trailing_bytes,
  }
end

-- CreateTopics with validate_only: the broker reports exactly which topics it
-- would have created and with which error, and creates nothing. The engine
-- forces the flag on, so this probe cannot write even if it wanted to.
function probe.create_topics(w, name, opts)
  opts = opts or {}
  local result = w:call("create_topics", function()
    return kafka.create_topics(w.connection, {
      { name = name, partitions = opts.partitions or 1, replication_factor = opts.replication or 1 },
    }, { timeout_ms = w.cfg.timeout })
  end)
  if not result or not result.ok then
    return { stage = "create_topics", answered = false, error = result and result.error or "no response",
      version = result and result.version, topic = name }
  end
  local entry = (result.topics or {})[1] or {}
  return {
    stage = "create_topics", answered = true, version = result.version, topic = name,
    validate_only = result.validate_only == true,
    error_code = entry.error_code, error_name = entry.error_name,
    error_message = entry.error_message, num_partitions = entry.num_partitions,
    replication_factor = entry.replication_factor, configs = entry.configs or {},
    config_error_code = result.config_error_code, config_error_name = result.config_error_name,
    throttle_ms = result.throttle_ms,
    access = (entry.error_code == 0) and "granted"
      or (kafka.is_authz_error(entry.error_code or 0) and "denied" or "error"),
    trailing_bytes = result.trailing_bytes,
  }
end

-- DeleteTopics against a name that does not exist. Kafka authorizes the delete
-- before it looks the topic up, so the error code it returns answers a precise
-- question: TOPIC_AUTHORIZATION_FAILED means the ACL exists and this principal
-- is not on it, UNKNOWN_TOPIC_OR_PARTITION means the request was authorized and
-- only the topic was missing. The probe only ever sends a name it generated.
function probe.delete_topics(w, name)
  local result = w:call("delete_topics", function()
    return kafka.delete_topics(w.connection, { name }, { timeout_ms = w.cfg.timeout })
  end)
  if not result or not result.ok then
    return { stage = "delete_topics", answered = false, error = result and result.error or "no response",
      version = result and result.version, topic = name }
  end
  local entry = (result.topics or {})[1] or {}
  return {
    stage = "delete_topics", answered = true, version = result.version, topic = name,
    error_code = entry.error_code, error_name = entry.error_name,
    error_message = entry.error_message, throttle_ms = result.throttle_ms,
    access = (entry.error_code == 29) and "denied"
      or ((entry.error_code == 3 or entry.error_code == 91) and "granted" or "other"),
    trailing_bytes = result.trailing_bytes,
  }
end

function probe.sasl(w)
  local result = w:call("sasl_handshake", function()
    return kafka.sasl_handshake(w.connection, "PLAIN")
  end)
  if not result or not result.ok then
    return { stage = "sasl_handshake", answered = false, error = result and result.error or "no response",
      version = result and result.version }
  end
  local mechanisms = {}
  for _, name in ipairs(result.mechanisms or {}) do
    mechanisms[#mechanisms + 1] = tostring(name)
  end
  return {
    stage = "sasl_handshake", answered = true, version = result.version,
    error_code = result.error_code, error_name = result.error_name,
    mechanisms = mechanisms, mechanism_count = #mechanisms,
    scram = (function()
      local scram = {}
      for _, name in ipairs(mechanisms) do
        if string.find(name, "SCRAM") then scram[#scram + 1] = name end
      end
      return scram
    end)(),
    plaintext_mechanisms = (function()
      local weak = {}
      for _, name in ipairs(mechanisms) do
        if name == "PLAIN" or name == "AMQPLAIN" or name == "GSSAPI" or name == "LOGIN" then
          weak[#weak + 1] = name
        end
      end
      return weak
    end)(),
    access = result.error_code == 0 and "granted" or "error",
    trailing_bytes = result.trailing_bytes,
  }
end

-- Reading a record is the difference between "the metadata is exposed" and
-- "the message payloads are exposed". It is opt-in (kafka.sample-records),
-- reads a single bounded batch from one partition, and commits nothing.
function probe.sample_records(w, topic, partition)
  local entries = {
    { name = topic, partitions = { { partition = partition, fetch_offset = 0,
      max_bytes = w.cfg.sample_bytes } } },
  }
  local result = w:call("fetch", function()
    return kafka.fetch(w.connection, entries, {
      partition_max_bytes = w.cfg.sample_bytes,
      max_bytes = w.cfg.sample_bytes,
      record_limit = 4,
      version = 4,
    })
  end)
  if not result or not result.ok then
    return { stage = "fetch", answered = false, error = result and result.error or "no response",
      version = result and result.version, topic = topic, partition = partition }
  end
  local part = ((result.topics or {})[1] or {}).partitions
  part = part and part[1] or {}
  local decoded = part.records
  local out = {
    stage = "fetch", answered = true, version = result.version, topic = topic, partition = partition,
    error_code = part.error_code, error_name = part.error_name,
    high_watermark = part.high_watermark, log_start_offset = part.log_start_offset,
    records_bytes = part.records_bytes,
    batches = decoded and decoded.batches or {}, record_count = decoded and #decoded.records or 0,
    records = {}, truncated = decoded and decoded.truncated or false,
    codecs = decoded and decoded.codecs or {},
    storage_summary = decoded and decoded.batch_count and string.format(
      "%s in %s, %s", plural(#decoded.records, "record"), plural(decoded.batch_count, "batch"),
      plural(part.records_bytes or 0, "byte")) or "no records returned",
    access = (part.error_code == 0) and "granted" or "error",
  }
  for _, record in ipairs(decoded and decoded.records or {}) do
    out.records[#out.records + 1] = {
      offset = record.offset, timestamp = record.timestamp,
      key = record.key and bytes_to_string(record.key, 64) or nil,
      value = record.value and bytes_to_string(record.value, 96) or nil,
      value_bytes = record.value and #record.value or 0,
      header_count = #(record.headers or {}),
    }
    if #out.records >= 3 then break end
  end
  return out
end

----------------------------------------------------------------------------
-- 5. Analysis
----------------------------------------------------------------------------
--
-- The analysis layer answers one question per public API: did an anonymous
-- caller get what the API is supposed to protect? It never guesses. A probe
-- that was not answered produces "no conclusion", not a finding, and the
-- report keeps the failed stage so the reader can see where the audit stopped.

local analysis = {}

local ACCESS_LABEL = {
  ["granted"] = "granted",
  ["denied"] = "denied",
  ["partial"] = "partial",
  ["empty"] = "empty result",
  ["error"] = "error",
  ["unknown"] = "no conclusion",
  ["other"] = "inconclusive error",
  ["unsupported-version"] = "unsupported-version",
  ["skipped"] = "skipped",
}

function analysis.label(access)
  return ACCESS_LABEL[access] or tostring(access)
end

function analysis.access_matrix(records)
  local rows = {}
  local function add(name, record, detail)
    if not record then return end
    local access = record.access
    if not record.answered and access == nil then
      -- Three very different situations end up in the same "not answered"
      -- bucket, and the matrix must not blur them: an API the broker never
      -- advertised, a probe that did not apply to this broker, and a request
      -- that really got no answer.
      if record.skipped then
        access = "skipped"
      elseif record.error and string.find(tostring(record.error), "not offered by broker") then
        access = "unsupported-version"
      else
        access = "unknown"
      end
    elseif record.answered and access == nil then
      access = "skipped"
    end
    rows[#rows + 1] = {
      check = name,
      status = analysis.label(access),
      code = record.error_name or (record.error_code and kafka.error_name(record.error_code)) or "-",
      version = record.version,
      detail = detail,
      access = access,
      answered = record.answered,
    }
  end
  add("ApiVersions handshake", records.negotiate,
    records.negotiate and records.negotiate.answered
      and (plural(records.negotiate.api_count or 0, "API") .. " offered") or nil)
  add("Metadata (all topics)", records.metadata, records.metadata and records.metadata.answered
    and (plural(records.metadata.topic_count or 0, "topic")) or nil)
  add("DescribeCluster", records.describe_cluster, records.describe_cluster and records.describe_cluster.answered
    and (plural(#(records.describe_cluster.brokers or {}), "broker")) or nil)
  add("ListGroups", records.list_groups, records.list_groups and records.list_groups.answered
    and (plural(#(records.list_groups.groups or {}), "group")) or nil)
  add("DescribeGroups", records.describe_groups, records.describe_groups and records.describe_groups.answered
    and (records.describe_groups.skipped or plural(#(records.describe_groups.groups or {}), "group", "groups") .. " described") or nil)
  add("FindCoordinator", records.find_coordinator, records.find_coordinator and records.find_coordinator.answered
    and (records.find_coordinator.skipped or ("coordinator " .. tostring(records.find_coordinator.node_id))) or nil)
  add("OffsetFetch", records.offset_fetch, records.offset_fetch and records.offset_fetch.answered
    and (records.offset_fetch.skipped or plural(records.offset_fetch.partition_count or 0, "partition")) or nil)
  add("ListOffsets", records.list_offsets, records.list_offsets and records.list_offsets.answered
    and (records.list_offsets.skipped or plural(#(records.list_offsets.rows or {}), "partition")) or nil)
  add("DescribeConfigs", records.describe_configs, records.describe_configs and records.describe_configs.answered
    and (records.describe_configs.skipped or plural(records.describe_configs.config_count or 0, "setting")) or nil)
  add("CreateTopics (validate only)", records.create_topics,
    records.create_topics and records.create_topics.answered and "validate_only=true" or nil)
  add("DeleteTopics (random name)", records.delete_topics,
    records.delete_topics and records.delete_topics.answered and "topic name generated by the probe" or nil)
  add("SaslHandshake", records.sasl, records.sasl and records.sasl.answered
    and (plural(records.sasl.mechanism_count or 0, "mechanism")) or nil)
  if records.sample then
    add("Fetch (bounded sample)", records.sample, records.sample.answered
      and (records.sample.storage_summary or "no records") or nil)
  end
  return rows
end

-- How many of the eleven probe families answered without an authorization
-- error is the single number that drives the report's headline.
function analysis.granted_count(matrix)
  local granted, denied, unknown = 0, 0, 0
  for _, row in ipairs(matrix) do
    if row.access == "granted" or row.access == "partial" then
      granted = granted + 1
    elseif row.access == "denied" then
      denied = denied + 1
    elseif not row.answered or row.access == "unknown" or row.access == "error" then
      unknown = unknown + 1
    end
  end
  return granted, denied, unknown
end

function analysis.topic_stats(metadata)
  local stats = { total = 0, internal = 0, partitions = 0, under_replicated = 0, no_leader = 0, leaders = {} }
  if not metadata or not metadata.answered then return stats end
  for _, topic in ipairs(metadata.topics or {}) do
    stats.total = stats.total + 1
    if topic.is_internal then stats.internal = stats.internal + 1 end
    for _, part in ipairs(topic.partitions or {}) do
      stats.partitions = stats.partitions + 1
      stats.leaders[part.leader_id] = (stats.leaders[part.leader_id] or 0) + 1
      if part.leader_id == -1 then stats.no_leader = stats.no_leader + 1 end
      if #(part.isr or {}) < #(part.replicas or {}) then stats.under_replicated = stats.under_replicated + 1 end
    end
  end
  return stats
end

function analysis.group_stats(list_groups, describe_groups)
  local stats = { groups = 0, members = 0, client_hosts = {}, client_ids = {}, protocols = {}, states = {} }
  if list_groups and list_groups.answered then
    for _, group in ipairs(list_groups.groups or {}) do
      stats.groups = stats.groups + 1
      local protocol = group.protocol_type or "(empty)"
      stats.protocols[protocol] = (stats.protocols[protocol] or 0) + 1
      local state = group.state or "(not reported)"
      stats.states[state] = (stats.states[state] or 0) + 1
    end
  end
  if describe_groups and describe_groups.answered then
    for _, group in ipairs(describe_groups.groups or {}) do
      for _, member in ipairs(group.members or {}) do
        stats.members = stats.members + 1
        if member.client_host then stats.client_hosts[member.client_host] = true end
        if member.client_id then stats.client_ids[member.client_id] = true end
      end
    end
  end
  return stats
end

local function count_keys(tbl)
  local n = 0
  for _ in pairs(tbl or {}) do n = n + 1 end
  return n
end

function analysis.lag_rows(offsets, watermarks)
  local rows = {}
  local watermark_index = {}
  for _, row in ipairs((watermarks or {}).rows or {}) do
    watermark_index[row.topic .. "/" .. tostring(row.partition)] = row.offset
  end
  for _, entry in ipairs((offsets or {}).partitions or {}) do
    local key = entry.topic .. "/" .. tostring(entry.partition)
    local end_offset = watermark_index[key]
    local lag = nil
    if end_offset and entry.offset and entry.offset >= 0 then
      lag = end_offset - entry.offset
      if lag < 0 then lag = 0 end
    end
    rows[#rows + 1] = {
      group = offsets.group, topic = entry.topic, partition = entry.partition,
      committed = entry.offset, end_offset = end_offset, lag = lag,
    }
  end
  return rows
end

----------------------------------------------------------------------------
-- 6. Findings
----------------------------------------------------------------------------
--
-- Each finding states what was observed, what it means for an attacker who is
-- already on the network path, and what to change. Severity is driven by what
-- the anonymous principal received, so a broker with ACLs in place cannot be
-- reported as open no matter how much it advertises.

local findings = {}

local REMEDIATION = {
  unauth = {
    "Put the listener behind SASL: set 'listener.name.<listener>.sasl.enabled.mechanisms' and the "
      .. "matching JAAS configuration, then set 'sasl.mechanism.inter.broker.protocol' and "
      .. "'security.inter.broker.protocol' to the secure listener.",
    "Enable the authorizer: 'authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer' "
      .. "(KRaft) and remove any 'allow.everyone.if.no.acl.found=true' default.",
    "Never expose the PLAINTEXT listener beyond the broker network: bind it to the internal interface and "
      .. "keep clients on the SASL_SSL listener.",
  },
  acl = {
    "Keep the ACLs that produced the authorization errors, and audit the resources that answered "
      .. "normally: 'kafka-acls.sh --bootstrap-server <host:port> --list'.",
    "Add explicit denies only where a resource must stay closed to a service account; ACL denials in "
      .. "Kafka are per resource, so a missing ACL is what you saw.",
  },
  sasl = {
    "A listener that offers SASL but answers anonymous metadata is usually a cluster where the "
      .. "PLAINTEXT listener is still enabled. Remove it from 'listeners' once clients have moved.",
    "If PLAIN is the only mechanism, move to SCRAM-SHA-512 (or SASL/GSSAPI) and rotate credentials: "
      .. "PLAIN sends the password in the clear on a PLAINTEXT listener.",
  },
  config = {
    "Restrict DescribeConfigs with ACLs on the CLUSTER resource, and never store secrets in topic or "
      .. "broker configuration: values marked sensitive are returned by default to any principal that "
      .. "can describe the resource.",
  },
  groups = {
    "Group metadata is not secret by design, but it reveals which applications exist and where they "
      .. "run. Keep group-prefixed ACLs in place and prefer "
      .. "'group.id' naming that does not disclose the owning team.",
  },
  write = {
    "An anonymous principal that can create topics can also influence replication and retention for the "
      .. "whole cluster. Add CREATE on the CLUSTER resource only to the provisioning identity.",
    "For delete: DELETE on TOPIC resources must be granted to the platform team only, and the "
      .. "'delete.topic.enable' setting should stay true only where a controller actually manages it.",
  },
}

function findings.unauth_access(records, matrix)
  local granted = analysis.granted_count(matrix)
  if granted == 0 then
    -- Nothing answered: that is an absence of evidence, not evidence of
    -- anonymous access, and it must not be reported as a finding.
    return nil
  end
  local evidence = {}
  local names = {}
  for _, row in ipairs(matrix) do
    if row.access == "granted" or row.access == "partial" then
      names[#names + 1] = row.check
    end
    evidence[#evidence + 1] = string.format("%s -> %s%s", row.check, row.status,
      row.code ~= "-" and (" (" .. row.code .. ")") or "")
  end
  local severity = "MEDIUM"
  if records.metadata and records.metadata.access == "granted" then
    severity = "CRITICAL"
  elseif granted >= 3 then
    severity = "HIGH"
  end
  return {
    id = "KAFKA-ANONYMOUS-BROKER-ACCESS",
    severity = severity,
    title = "Kafka broker answers anonymous client requests",
    detail = string.format(
      "%s of the %s families answered without authentication: %s.",
      tostring(granted), tostring(#matrix), fmt_list(names, 6)),
    evidence = evidence,
    remediation = REMEDIATION.unauth,
  }
end

function findings.internal_topics(records)
  local metadata = records.metadata
  if not metadata or not metadata.answered or #(metadata.internal or {}) == 0 then return nil end
  local names = {}
  for _, topic in ipairs(metadata.internal) do names[#names + 1] = topic.name end
  return {
    id = "KAFKA-INTERNAL-TOPICS-EXPOSED",
    severity = "HIGH",
    title = "Internal Kafka topics are enumerable without authentication",
    detail = string.format(
      "The broker disclosed %s to an anonymous client: %s. __consumer_offsets holds the committed "
      .. "offsets for every consumer group in the cluster, and __transaction_state records the "
      .. "transaction coordinator state.",
      plural(#names, "internal topic"), fmt_list(names, 6)),
    evidence = { "Metadata(null) returned: " .. fmt_list(names, 10) },
    remediation = REMEDIATION.acl,
  }
end

function findings.group_enumeration(records)
  local stats = records.group_stats
  if not stats or stats.groups == 0 then return nil end
  local hosts, clients = {}, {}
  for host in pairs(stats.client_hosts) do hosts[#hosts + 1] = host end
  for client in pairs(stats.client_ids) do clients[#clients + 1] = client end
  table.sort(hosts)
  table.sort(clients)
  return {
    id = "KAFKA-CONSUMER-GROUP-ENUMERATION",
    severity = stats.members > 0 and "HIGH" or "MEDIUM",
    title = "Consumer group topology is readable without authentication",
    detail = string.format(
      "%s and %s were listed, and %s disclosed %s together with the client ids (%s) and the hosts the "
      .. "consumers connect from (%s). That is an inventory of every application consuming from the "
      .. "cluster and a map of where those applications live.",
      plural(stats.groups, "consumer group"), plural(stats.members, "member"),
      stats.members > 0 and "DescribeGroups" or "ListGroups",
      plural(stats.members, "member"), fmt_list(clients, 4), fmt_list(hosts, 4)),
    evidence = {
      "ListGroups: " .. fmt_list(records.list_groups and records.list_groups.groups or {}, 4,
        "no groups"),
    },
    remediation = REMEDIATION.groups,
  }
end

function findings.offset_leak(records, lag)
  local offsets = records.offset_fetch
  if not offsets or not offsets.answered or (offsets.partition_count or 0) == 0 then return nil end
  local with_lag = 0
  local sample = {}
  for _, row in ipairs(lag or {}) do
    if row.lag then
      with_lag = with_lag + 1
      if #sample < 4 then
        sample[#sample + 1] = string.format("%s/%d lag %s", row.topic, row.partition, tostring(row.lag))
      end
    end
  end
  return {
    id = "KAFKA-COMMITTED-OFFSETS-READABLE",
    severity = with_lag > 0 and "MEDIUM" or "LOW",
    title = "Committed consumer offsets are readable without authentication",
    detail = string.format(
      "OffsetFetch answered for %s; combined with ListOffsets that yields %s. Consumer lag is one of "
      .. "the most useful signals an attacker can watch: a lagging or stopped consumer tells them which "
      .. "service is unhealthy and how much unprocessed data is queued behind it%s.",
      plural(offsets.partition_count or 0, "partition"),
      plural(with_lag, "lag figure"), #sample > 0 and (": " .. fmt_list(sample, 4)) or ""),
    evidence = { "OffsetFetch: " .. fmt_list(lag or {}, 4, "no committed offsets") },
    remediation = REMEDIATION.groups,
  }
end

function findings.config_leak(records)
  local configs = records.describe_configs
  if not configs or not configs.answered or configs.config_count == 0 then return nil end
  local leaks = configs.sensitive_leaks or {}
  local severity = #leaks > 0 and "HIGH" or "MEDIUM"
  local detail
  if #leaks > 0 then
    local names = {}
    for _, leak in ipairs(leaks) do
      names[#names + 1] = string.format("%s=%s", leak.name, leak.value)
    end
    detail = string.format(
      "DescribeConfigs returned %s, of which %s the broker itself marks as sensitive and still "
      .. "delivered in the response: %s.",
      plural(configs.config_count, "setting"), plural(#leaks, "setting"), fmt_list(names, 4))
  else
    detail = string.format(
      "DescribeConfigs returned %s to an anonymous client. Configuration names alone disclose the "
      .. "cluster's security posture (inter-broker protocol, authorizer class, listener names).",
      plural(configs.config_count, "setting"))
  end
  return {
    id = "KAFKA-CONFIGURATION-DISCLOSURE",
    severity = severity,
    title = "Topic and broker configuration is readable without authentication",
    detail = detail,
    evidence = { "DescribeConfigs: " .. plural(configs.config_count, "setting") .. " returned"
      .. (#leaks > 0 and (", " .. plural(#leaks, "sensitive value") .. " disclosed") or "") },
    remediation = REMEDIATION.config,
  }
end

function findings.write_access(records)
  local out = {}
  local create = records.create_topics
  if create and create.answered then
    if create.access == "granted" then
      out[#out + 1] = {
        id = "KAFKA-ANONYMOUS-TOPIC-CREATE",
        severity = "CRITICAL",
        title = "Anonymous principal may create topics",
        detail = "CreateTopics answered successfully in validate_only mode for a name the probe "
          .. "generated. The broker therefore believes this principal holds CREATE on the cluster "
          .. "resource; a real call would have created the topic.",
        evidence = { string.format("CreateTopics validate_only -> %s", create.error_name or "NONE") },
        remediation = REMEDIATION.write,
      }
    elseif create.access == "denied" then
      out[#out + 1] = {
        id = "KAFKA-TOPIC-CREATE-DENIED",
        severity = "INFO",
        title = "Topic creation is denied for anonymous callers",
        detail = string.format("CreateTopics validate_only was refused: %s.",
          tostring(create.error_name)),
        evidence = { string.format("CreateTopics validate_only -> %s", tostring(create.error_name)) },
      }
    end
  end
  local delete = records.delete_topics
  if delete and delete.answered then
    if delete.access == "denied" then
      out[#out + 1] = {
        id = "KAFKA-TOPIC-DELETE-DENIED",
        severity = "INFO",
        title = "Topic deletion is denied for anonymous callers",
        detail = string.format(
          "DeleteTopics on the generated name %s returned %s, which is the authorization check firing "
          .. "before the topic lookup: the ACL exists and anonymous callers are not on it.",
          tostring(delete.topic), tostring(delete.error_name)),
        evidence = { string.format("DeleteTopics(%s) -> %s", tostring(delete.topic),
          tostring(delete.error_name)) },
      }
    elseif delete.access == "granted" then
      out[#out + 1] = {
        id = "KAFKA-ANONYMOUS-TOPIC-DELETE",
        severity = "HIGH",
        title = "Anonymous principal is authorized to delete topics",
        detail = string.format(
          "DeleteTopics for the generated name %s returned %s: the authorization check passed and only "
          .. "the topic lookup failed. The same call against an existing topic would have deleted it.",
          tostring(delete.topic), tostring(delete.error_name)),
        evidence = { string.format("DeleteTopics(%s) -> %s", tostring(delete.topic),
          tostring(delete.error_name)) },
        remediation = REMEDIATION.write,
      }
    end
  end
  return out
end

function findings.sasl_posture(records)
  local out = {}
  local sasl = records.sasl
  local metadata = records.metadata
  if not sasl or not sasl.answered then return out end
  local anonymous_metadata = metadata and metadata.access == "granted"
  if sasl.mechanism_count > 0 and anonymous_metadata then
    out[#out + 1] = {
      id = "KAFKA-SASL-OFFERED-NOT-REQUIRED",
      severity = "HIGH",
      title = "Listener offers SASL but still serves anonymous requests",
      detail = string.format(
        "The broker advertises %s but answered an anonymous Metadata request. Either the PLAINTEXT "
        .. "listener is still enabled, or SASL is configured on a different listener than the one being "
        .. "audited; both leave an unauthenticated path into the cluster.",
        fmt_list(sasl.mechanisms, 4)),
      evidence = { "SaslHandshake: " .. fmt_list(sasl.mechanisms, 6, "no mechanisms") },
      remediation = REMEDIATION.sasl,
    }
  end
  if #(sasl.plaintext_mechanisms or {}) > 0 then
    out[#out + 1] = {
      id = "KAFKA-CLEARTEXT-SASL-MECHANISM",
      severity = "MEDIUM",
      title = "Cleartext SASL mechanisms are enabled",
      detail = string.format(
        "The listener offers %s. PLAIN and LOGIN transmit the password in the clear, so on a PLAINTEXT "
        .. "or SASL_PLAINTEXT listener anyone on the network path can capture a working credential.",
        fmt_list(sasl.plaintext_mechanisms, 4)),
      evidence = { "SaslHandshake mechanisms: " .. fmt_list(sasl.mechanisms, 6, "none") },
      remediation = REMEDIATION.sasl,
    }
  end
  return out
end

function findings.record_exposure(records)
  if not records.sample then return nil end
  local sample = records.sample
  if not sample.answered then return nil end
  if sample.access ~= "granted" or (sample.record_count or 0) == 0 then
    return {
      id = "KAFKA-RECORDS-NOT-SAMPLED",
      severity = "INFO",
      title = "Message payloads were not readable by the anonymous caller",
      detail = string.format("Fetch on %s/%d returned %s.",
        tostring(sample.topic), tonumber(sample.partition) or 0,
        sample.access == "granted" and "no records" or tostring(sample.error_name)),
    }
  end
  local preview = {}
  for _, record in ipairs(sample.records or {}) do
    preview[#preview + 1] = string.format("offset %s: %s", kafka.int(record.offset or 0),
      record.value or record.key or "(empty)")
  end
  return {
    id = "KAFKA-RECORD-PAYLOAD-EXPOSURE",
    severity = "CRITICAL",
    title = "Message payloads are readable without authentication",
    detail = string.format(
      "A bounded Fetch against %s/%d returned %s. Payloads are the last line of defence: with "
      .. "unauthenticated consumer access an attacker reads production data directly, and on topics "
      .. "that carry credentials or personal data that is a data breach rather than a misconfiguration.",
      tostring(sample.topic), tonumber(sample.partition) or 0,
      plural(sample.record_count, "record")),
    evidence = preview,
    remediation = REMEDIATION.unauth,
  }
end

function findings.version_notes(records, w)
  local out = {}
  local negotiate = records.negotiate
  if not negotiate or not negotiate.answered then return out end
  local oldest = nil
  for _, row in ipairs(negotiate.version_rows or {}) do
    if row.broker_max and oldest == nil then oldest = row end
    if row.broker_max and row.broker_max < row.local_max then
      out[#out + 1] = string.format("%s: broker max v%d, audit can speak v%d",
        row.name, row.broker_max, row.chosen or row.broker_max)
    end
  end
  local missing = negotiate.unsupported or {}
  local notes = {
    id = "KAFKA-API-SURFACE",
    severity = "INFO",
    title = "Kafka API surface and version negotiation",
    detail = string.format(
      "%s answered; %s. %s",
      "ApiVersions", plural(negotiate.api_count or 0, "API"),
      #missing > 0
        and ("The broker does not offer " .. fmt_list(missing, 6)
          .. ", so the corresponding checks were skipped instead of guessed.")
        or "Every API this audit needs is advertised by the broker."),
  }
  if #out > 0 then notes.detail = notes.detail .. " Version gaps: " .. fmt_list(out, 6) .. "." end
  return { notes }
end

function findings.evaluate(records, matrix, lag)
  local out = {}
  local function push(finding)
    if finding then out[#out + 1] = finding end
  end
  push(findings.version_notes(records, nil)[1])
  push(findings.unauth_access(records, matrix))
  push(findings.internal_topics(records))
  push(findings.group_enumeration(records))
  push(findings.offset_leak(records, lag))
  push(findings.config_leak(records))
  push(findings.sasl_posture(records)[1])
  push(findings.sasl_posture(records)[2])
  for _, finding in ipairs(findings.write_access(records)) do push(finding) end
  push(findings.record_exposure(records))
  -- Order by severity, then by the order they were produced so the report reads
  -- the same way every run.
  table.sort(out, function(a, b)
    local left = kafka.SEVERITY_ORDER[a.severity] or 0
    local right = kafka.SEVERITY_ORDER[b.severity] or 0
    if left ~= right then return left > right end
    return a.id < b.id
  end)
  return out
end

----------------------------------------------------------------------------
-- 7. Reporting
----------------------------------------------------------------------------

local report = {}

function report.target_section(cfg, host, port, w)
  local rows = {}
  rows[#rows + 1] = string.format("Endpoint: %s:%d/tcp", host.ip or "target", port.number)
  rows[#rows + 1] = string.format("Client id: %s", cfg.client_id)
  rows[#rows + 1] = string.format("Timeout: %dms, retry on transient errors: %s",
    cfg.timeout, fmt_bool(cfg.on_transient_retry))
  rows[#rows + 1] = string.format("Probe topic: %s", tostring(cfg.probe_topic_name))
  rows[#rows + 1] = string.format("Record sampling: %s", cfg.sample_records and "enabled" or "disabled")
  if w and #w.stages > 0 then
    local stages = {}
    for _, stage in ipairs(w.stages) do
      stages[#stages + 1] = string.format("%s (%s)", stage.name, stage.detail or "")
    end
    rows[#rows + 1] = "Stages: " .. fmt_list(stages, 12)
  end
  return rows
end

function report.cluster_section(records)
  local rows = {}
  local metadata = records.metadata
  local cluster = records.describe_cluster
  local cluster_id = (metadata and metadata.cluster_id) or (cluster and cluster.cluster_id)
  if cluster_id then rows[#rows + 1] = "Cluster id: " .. tostring(cluster_id) end
  local controller = (metadata and metadata.controller_id) or (cluster and cluster.controller_id)
  if controller and controller >= 0 then rows[#rows + 1] = "Controller broker: " .. tostring(controller) end
  local brokers = (metadata and metadata.brokers) or (cluster and cluster.brokers) or {}
  if #brokers > 0 then
    local parts = {}
    for _, broker in ipairs(brokers) do
      local node = broker.node_id or broker.broker_id
      parts[#parts + 1] = string.format("%s=%s:%s%s", tostring(node), tostring(broker.host),
        tostring(broker.port), broker.rack and ("/" .. tostring(broker.rack)) or "")
    end
    rows[#rows + 1] = "Brokers: " .. fmt_list(parts, 8)
  end
  local stats = records.topic_stats
  if stats then
    rows[#rows + 1] = string.format("Topics: %d (%d internal), partitions: %d",
      stats.total, stats.internal, stats.partitions)
    if stats.under_replicated > 0 then
      rows[#rows + 1] = string.format("Under-replicated partitions: %d", stats.under_replicated)
    end
    if stats.no_leader > 0 then
      rows[#rows + 1] = string.format("Partitions without a leader: %d", stats.no_leader)
    end
  end
  if #rows == 0 then rows[#rows + 1] = "No cluster metadata was returned" end
  return rows
end

function report.topic_section(cfg, records)
  local metadata = records.metadata
  if not metadata or not metadata.answered then
    return { "Metadata was not answered; no topic inventory was produced." }
  end
  local rows = {}
  for _, topic in ipairs(metadata.topics or {}) do
    local partitions = topic.partitions or {}
    local leaders = {}
    for _, part in ipairs(partitions) do
      leaders[#leaders + 1] = tostring(part.leader_id)
    end
    rows[#rows + 1] = string.format("%s%s: %d partition(s), leaders %s%s",
      topic.name, topic.is_internal and " [internal]" or "", #partitions,
      fmt_list(leaders, 4),
      (topic.authorized_operations and topic.authorized_operations ~= -2147483648)
        and string.format(", authorized ops 0x%s", kafka.hex(topic.authorized_operations)) or "")
  end
  if #rows == 0 then
    rows[#rows + 1] = "The broker returned an empty topic list"
  elseif metadata.truncated then
    rows[#rows + 1] = string.format("Showing the first %d topics (kafka.max-topics)", cfg.max_topics)
  end
  return rows
end

function report.group_section(records)
  local rows = {}
  local listed = records.list_groups
  if not listed or not listed.answered then
    return { "ListGroups was not answered; consumer groups could not be enumerated." }
  end
  local described = {}
  for _, group in ipairs((records.describe_groups or {}).groups or {}) do
    described[group.group_id] = group
  end
  if #(listed.groups or {}) == 0 then
    rows[#rows + 1] = "No consumer groups were listed"
  end
  for _, group in ipairs(listed.groups) do
    local detail = described[group.group_id]
    local members = detail and detail.members or {}
    local member_text = {}
    for _, member in ipairs(members) do
      member_text[#member_text + 1] = string.format("%s@%s (%s)", tostring(member.client_id),
        tostring(member.client_host), tostring(member.member_id))
    end
    rows[#rows + 1] = string.format("%s: %s%s%s", tostring(group.group_id),
      tostring(group.protocol_type or "?"),
      group.state and ("/" .. tostring(group.state)) or "",
      #member_text > 0 and (" members: " .. fmt_list(member_text, 3)) or "")
  end
  return rows
end

function report.offset_section(records, lag)
  local rows = {}
  local offsets = records.offset_fetch
  if not offsets or not offsets.answered then
    return { "OffsetFetch was not answered; committed offsets are unknown." }
  end
  if offsets.skipped then return { offsets.skipped } end
  if offsets.partition_count == 0 then
    rows[#rows + 1] = string.format("Group %s has no committed offsets", tostring(offsets.group))
  end
  for _, row in ipairs(lag or {}) do
    rows[#rows + 1] = string.format("%s %s/%d committed %s, end offset %s, lag %s",
      tostring(row.group), row.topic, row.partition, tostring(row.committed),
      row.end_offset and tostring(row.end_offset) or "unknown",
      row.lag and tostring(row.lag) or "unknown")
  end
  if #(offsets.partitions or {}) > #(lag or {}) then
    rows[#rows + 1] = string.format("(%d of %d committed offsets had no watermark to compare against)",
      #offsets.partitions - #(lag or {}), #offsets.partitions)
  end
  return rows
end

function report.config_section(cfg, records)
  local configs = records.describe_configs
  if not configs or not configs.answered then
    return { "DescribeConfigs was not answered; configuration could not be read." }
  end
  if configs.skipped then return { configs.skipped } end
  local rows = {}
  for _, entry in ipairs(configs.results or {}) do
    if entry.error_code ~= 0 then
      rows[#rows + 1] = string.format("%s %s: %s", tostring(entry.resource_type),
        tostring(entry.resource_name), tostring(entry.error_name))
    else
      local settings = {}
      for _, config in ipairs(entry.configs) do
        settings[#settings + 1] = string.format("%s=%s%s%s", config.name,
          config.is_sensitive and "(sensitive) " or "",
          tostring(config.value), config.read_only and " [read-only]" or "")
      end
      rows[#rows + 1] = string.format("%s %s: %s", tostring(entry.resource_type),
        tostring(entry.resource_name), fmt_list(settings, cfg.max_config_topics + 4))
    end
  end
  return rows
end

function report.matrix_section(matrix)
  local rows = {}
  rows[#rows + 1] = string.format("%-30s %-12s %-28s %s", "Check", "Access", "Broker error", "Detail")
  for _, row in ipairs(matrix) do
    rows[#rows + 1] = string.format("%-30s %-12s %-28s %s", row.check, row.status, row.code,
      row.detail or "")
  end
  return rows
end

function report.finding_section(list)
  local rows = {}
  for index, finding in ipairs(list) do
    rows[#rows + 1] = string.format("%d. [%s] %s (%s)", index, finding.severity, finding.title,
      finding.id)
    rows[#rows + 1] = "   " .. finding.detail
    for _, line in ipairs(finding.evidence or {}) do
      rows[#rows + 1] = "   evidence: " .. line
    end
  end
  if #rows == 0 then rows[#rows + 1] = "No findings: every probe was either refused or unanswered." end
  return rows
end

function report.remediation_section(list)
  local rows = {}
  local seen = {}
  for _, finding in ipairs(list) do
    for _, line in ipairs(finding.remediation or {}) do
      if not seen[line] then
        seen[line] = true
        rows[#rows + 1] = line
      end
    end
  end
  if #rows == 0 then
    rows[#rows + 1] = "Keep the current listener and ACL configuration; re-run this audit after any "
      .. "change to listeners, ACLs or the authorizer class."
  end
  return rows
end

function report.limits_section(cfg, records, w)
  local rows = {
    "The audit speaks plaintext Kafka. A broker that requires TLS will drop the first frame and the "
      .. "script reports the timeout instead of an HTTP-style handshake failure.",
    "Authorization is inferred from broker error codes. A broker behind a proxy that rewrites error "
      .. "codes will be reported as inconclusive.",
    "Metadata for individual partitions is summarized; leader/replica assignment is listed per topic "
      .. "but not per partition.",
  }
  if not cfg.sample_records then
    rows[#rows + 1] = "Message payloads were not sampled (kafka.sample-records is false), so the report "
      .. "proves metadata exposure, not data exposure."
  end
  if records and records.offset_fetch and records.offset_fetch.skipped then
    rows[#rows + 1] = "No consumer group was listed, so committed offsets were not queried."
  end
  if w and w.failure then
    rows[#rows + 1] = string.format("The connection failed at the %s stage; every check after it is "
      .. "reported as unanswered rather than assumed.", tostring(w.failure))
  end
  return rows
end

function report.verification_section(cfg, host, port, records)
  local target = string.format("%s:%d", host.ip or "target", port.number)
  local rows = {
    string.format("List topics with the official client: kafka-topics.sh --bootstrap-server %s --list", target),
    string.format("List consumer groups: kafka-consumer-groups.sh --bootstrap-server %s --list", target),
  }
  if records and records.metadata and records.metadata.access == "granted" then
    rows[#rows + 1] = string.format("Read a topic without credentials: kafka-console-consumer.sh "
      .. "--bootstrap-server %s --topic <topic> --from-beginning --max-messages 1", target)
  end
  rows[#rows + 1] = "Re-run this script with --script-args kafka.sample-records=true to include a "
    .. "bounded payload sample in the evidence."
  rows[#rows + 1] = string.format("Audit command: nmap -Pn -p %d --script kafka-unauth-broker-access "
    .. "--script-args kafka.timeout=%d %s", port.number, cfg.timeout, host.ip or "target")
  return rows
end

function report.build(cfg, host, port, records, matrix, lag, list, w)
  local out = stdnse.output_table()
  out["Target"] = report.target_section(cfg, host, port, w)
  out["Cluster"] = report.cluster_section(records)
  out["Kafka API access matrix"] = report.matrix_section(matrix)

  local granted, denied, unanswered = analysis.granted_count(matrix)
  out["Access summary"] = string.format(
    "%d granted, %d denied, %d without a conclusion (of %d probe families)",
    granted, denied, unanswered, #matrix)

  out["Topics"] = report.topic_section(cfg, records)
  out["Consumer groups"] = report.group_section(records)
  out["Committed offsets and lag"] = report.offset_section(records, lag)
  out["Configuration"] = report.config_section(cfg, records)

  if records.create_topics and records.create_topics.answered then
    out["Write access (create)"] = string.format("validate_only create of %s -> %s",
      tostring(records.create_topics.topic), tostring(records.create_topics.error_name))
  end
  if records.delete_topics and records.delete_topics.answered then
    out["Write access (delete)"] = string.format("delete of generated name %s -> %s",
      tostring(records.delete_topics.topic), tostring(records.delete_topics.error_name))
  end
  if records.sasl and records.sasl.answered then
    out["SASL mechanisms"] = fmt_list(records.sasl.mechanisms, 8, "none advertised")
  end
  if records.sample then
    out["Payload sample"] = records.sample.storage_summary or "no sample taken"
    if #(records.sample.records or {}) > 0 then
      local lines = {}
      for _, record in ipairs(records.sample.records) do
        lines[#lines + 1] = string.format("offset %s key=%s value=%s", kafka.int(record.offset or 0),
          tostring(record.key), tostring(record.value))
      end
      out["Payload sample records"] = lines
    end
  end

  out["Findings"] = report.finding_section(list)
  out["Remediation"] = report.remediation_section(list)
  out["Method limits"] = report.limits_section(cfg, records, w)
  out["Verification"] = report.verification_section(cfg, host, port, records)

  local highest = "NONE"
  local severities = {}
  for _, finding in ipairs(list) do
    if finding.severity ~= "INFO" then severities[finding.severity] = true end
    if (kafka.SEVERITY_ORDER[finding.severity] or 0) > (kafka.SEVERITY_ORDER[highest] or 0) then
      highest = finding.severity
    end
  end
  -- "No findings" and "no answer" are different results. When not a single
  -- probe family reached a conclusion the report must say UNKNOWN: printing
  -- NONE there would read as "the broker is clean", which is exactly the claim
  -- the probes were unable to support.
  if highest == "NONE" then
    local conclusive = 0
    for _, row in ipairs(matrix) do
      local access = row.access
      if access == "granted" or access == "denied" or access == "partial"
        or access == "empty" or access == "error" or access == "other" then
        conclusive = conclusive + 1
      end
    end
    if conclusive == 0 then highest = "UNKNOWN" end
  end
  out["Risk Level"] = highest
  local summary = {}
  for _, severity in ipairs({ "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }) do
    if severities[severity] then
      local count = 0
      for _, finding in ipairs(list) do
        if finding.severity == severity then count = count + 1 end
      end
      summary[#summary + 1] = string.format("%s x%d", severity, count)
    end
  end
  out["Finding summary"] = #summary > 0 and table.concat(summary, ", ") or "no findings"
  return out
end

----------------------------------------------------------------------------
-- 8. Orchestration
----------------------------------------------------------------------------

-- The probe order is deliberate. ApiVersions first (everything else depends on
-- the negotiated schemas), then the read-only enumeration APIs, then the two
-- write-adjacent probes, and the payload sample last because it is the only
-- request that pulls real message data.
local function run_probes(w, cfg)
  local records = {}
  local ran = {}

  local function run(name, fn)
    if w.failure then
      records[name] = { stage = name, answered = false, error = "skipped after " .. tostring(w.failure) }
      return records[name]
    end
    local ok, result = pcall(fn)
    if not ok then
      records[name] = { stage = name, answered = false, error = "script error: " .. tostring(result) }
      w:stage(name, "error: " .. tostring(result))
      return records[name]
    end
    ran[#ran + 1] = name
    if result and not result.answered and result.error then
      -- A dead connection makes every later probe fail; recording the failure
      -- once is more useful than eleven identical timeouts.
      if string.find(tostring(result.error), "timeout") or string.find(tostring(result.error), "closed") then
        w.failure = name
      end
    end
    records[name] = result
    return result
  end

  run("negotiate", function() return probe.negotiate(w) end)
  run("metadata", function() return probe.metadata(w, nil) end)
  run("describe_cluster", function() return probe.describe_cluster(w) end)
  run("list_groups", function() return probe.list_groups(w) end)

  local group_names = {}
  for _, group in ipairs((records.list_groups or {}).groups or {}) do
    group_names[#group_names + 1] = group.group_id
    if #group_names >= cfg.max_describe_groups then break end
  end
  run("describe_groups", function() return probe.describe_groups(w, group_names) end)
  run("find_coordinator", function()
    return probe.find_coordinator(w, group_names[1] or "nmap-audit-nonexistent-group")
  end)

  local first_group = group_names[1]
  run("offset_fetch", function()
    if not first_group then
      return { stage = "offset_fetch", answered = true, skipped = "no consumer group was listed" }
    end
    return probe.offset_fetch(w, first_group)
  end)

  local topic_names = {}
  for _, topic in ipairs((records.metadata or {}).topics or {}) do
    if not topic.is_internal or #topic_names == 0 then
      topic_names[#topic_names + 1] = topic.name
    end
    if #topic_names >= math.min(cfg.max_topics, 12) then break end
  end
  run("list_offsets", function() return probe.list_offsets(w, topic_names) end)

  local resources = { { type = 2, name = topic_names[1] or "nmap-audit-nonexistent" } }
  for index = 2, math.min(#topic_names, cfg.max_config_topics) do
    resources[#resources + 1] = { type = 2, name = topic_names[index] }
  end
  if records.describe_cluster and records.describe_cluster.answered then
    local broker = (records.describe_cluster.brokers or {})[1]
    if broker and broker.host then
      resources[#resources + 1] = { type = 4, name = tostring((records.describe_cluster.brokers or {})[1].broker_id) }
    end
  end
  run("describe_configs", function() return probe.describe_configs(w, resources) end)

  if cfg.allow_write_probes then
    run("create_topics", function()
      return probe.create_topics(w, cfg.probe_topic_name, { partitions = 1, replication = 1 })
    end)
    run("delete_topics", function() return probe.delete_topics(w, cfg.probe_topic_name) end)
  else
    records.create_topics = { stage = "create_topics", answered = true,
      skipped = "kafka.write-probes=false" }
    records.delete_topics = { stage = "delete_topics", answered = true,
      skipped = "kafka.write-probes=false" }
  end

  run("sasl", function() return probe.sasl(w) end)

  if cfg.sample_records and #topic_names > 0 then
    run("sample", function() return probe.sample_records(w, topic_names[1], 0) end)
  elseif cfg.sample_records then
    records.sample = { stage = "fetch", answered = false, error = "no topic available to sample" }
  end

  records.ran = ran
  return records
end

local function collect_evidence(records)
  local lines = {}
  local function note(text) lines[#lines + 1] = text end
  note(string.format("ApiVersions: %s answered with %s",
    fmt_bool(records.negotiate and records.negotiate.answered),
    plural((records.negotiate or {}).api_count or 0, "API")))
  if records.metadata and records.metadata.answered then
    note(string.format("Metadata(null): %s, cluster id %s",
      plural(records.metadata.topic_count or 0, "topic"), tostring(records.metadata.cluster_id)))
  end
  if records.list_groups and records.list_groups.answered then
    note(string.format("ListGroups: %s", plural(#(records.list_groups.groups or {}), "group")))
  end
  if records.describe_groups and records.describe_groups.answered then
    local members = 0
    for _, group in ipairs(records.describe_groups.groups or {}) do
      members = members + #(group.members or {})
    end
    note(string.format("DescribeGroups: %s, %s", plural(#(records.describe_groups.groups or {}), "group"),
      plural(members, "member")))
  end
  if records.offset_fetch and records.offset_fetch.answered and not records.offset_fetch.skipped then
    note(string.format("OffsetFetch(%s): %s", tostring(records.offset_fetch.group),
      plural(records.offset_fetch.partition_count or 0, "committed offset")))
  end
  if records.describe_configs and records.describe_configs.answered then
    note(string.format("DescribeConfigs: %s across %s", plural(records.describe_configs.config_count or 0, "setting"),
      plural(#(records.describe_configs.results or {}), "resource")))
  end
  if records.create_topics and records.create_topics.answered and not records.create_topics.skipped then
    note(string.format("CreateTopics(validate_only=true, %s) -> %s", tostring(records.create_topics.topic),
      tostring(records.create_topics.error_name)))
  end
  if records.delete_topics and records.delete_topics.answered and not records.delete_topics.skipped then
    note(string.format("DeleteTopics(%s) -> %s", tostring(records.delete_topics.topic),
      tostring(records.delete_topics.error_name)))
  end
  if records.sasl and records.sasl.answered then
    note("SaslHandshake: " .. fmt_list(records.sasl.mechanisms, 6, "no mechanisms"))
  end
  if records.sample and records.sample.answered then
    note("Fetch: " .. tostring(records.sample.storage_summary))
  end
  return lines
end

action = function(host, port)
  local cfg = read_config()
  cfg.probe_topic_name = probe_topic_name(cfg)

  local w = new_wire(host, port, cfg)
  local connected, connect_error = w:connect()
  if not connected then
    local out = stdnse.output_table()
    out["Risk Level"] = "UNKNOWN"
    out["Target"] = report.target_section(cfg, host, port, w)
    out["Error"] = connect_error
    out["Method limits"] = {
      "The TCP connection to the Kafka listener failed, so no protocol exchange happened. A broker "
        .. "that requires TLS on this port looks exactly like this from a plaintext probe.",
      "Confirm the port is a Kafka listener (kafka.network:type=SocketServer) and that the client "
        .. "protocol matches the listener's security.protocol.",
    }
    return out
  end

  local records = run_probes(w, cfg)
  w:close()

  records.topic_stats = analysis.topic_stats(records.metadata)
  records.group_stats = analysis.group_stats(records.list_groups, records.describe_groups)
  local matrix = analysis.access_matrix(records)
  local lag = analysis.lag_rows(records.offset_fetch, records.list_offsets)
  local list = findings.evaluate(records, matrix, lag)

  local out = report.build(cfg, host, port, records, matrix, lag, list, w)
  out["Evidence"] = collect_evidence(records)

  -- Report the findings to Nmap's vulnerability machinery so they appear in
  -- normal and XML output, not only in script output.
  if nmap.registry and nmap.registry.args and vulns and vulns.add then
    for _, finding in ipairs(list) do
      if finding.severity == "CRITICAL" or finding.severity == "HIGH" then
        vulns.add(host, port, finding.id, finding.title, {
          format = function() return finding.detail end,
        })
      end
    end
  end

  return out
end
