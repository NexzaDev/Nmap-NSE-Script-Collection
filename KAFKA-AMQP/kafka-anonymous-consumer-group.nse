local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The wire engine owns framing, version negotiation and the response parsers.
local ok, kafka = pcall(require, "kafka")
-- Findings are reported through Nmap's own vulnerability machinery as well as
-- through the script table; the module is optional so the script still runs
-- under a minimal NSE installation.
local has_vulns, vulns = pcall(require, "vulns")

description = [[
Audits the consumer-group plane of a Kafka cluster for anonymous access.

A broker that answers group requests before it knows who is calling exposes the
part of the cluster where the data actually moves. This script walks that plane
one API at a time:

  1. ListGroups      - which groups exist, their protocol type and their state.
  2. DescribeGroups  - per member: the member id, the client id, the client
                       host, the protocol, and two opaque BYTES fields.
  3. ... those BYTES are the ConsumerProtocol subscription and assignment, and
     the script decodes them: the subscribed topic list, the user data, the
     generation id, the rack id and - most telling of all - the exact
     partitions each consumer owns.
  4. FindCoordinator - which broker coordinates each group, which maps the
                       group plane onto the broker fleet.
  5. OffsetFetch     - the committed offset of every group/topic/partition.
  6. ListOffsets     - the high watermark, so the report can show the lag: how
                       far behind the group is, in messages.

The last two steps are what turns a metadata leak into an operational one: a
reader who has the committed offsets and the log ends knows exactly how much
unconsumed data sits in the cluster, which topics are busy and which consumer
is falling behind.

Everything is read-only. The script never joins a group, never commits an
offset, never consumes a record: JoinGroup, OffsetCommit and Fetch are absent
from its request catalogue by construction.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-anonymous-consumer-group <target>
-- nmap -p 9092 --script kafka-anonymous-consumer-group --script-args kafka.max-groups=50,kafka.lag=true <target>
--
-- @args kafka.timeout       Per-request timeout in milliseconds
--                           (default 5000, range 500-60000).
-- @args kafka.client-id     Client id used in every request header
--                           (default "nmap-kafka-group-audit").
-- @args kafka.max-groups    Maximum number of groups described (default 20,
--                           range 1-200).
-- @args kafka.states        Comma separated group states for the ListGroups
--                           filter (only sent when the broker advertises
--                           ListGroups v4 or later), for example
--                           "Stable,Empty". Default: no filter.
-- @args kafka.lag           "true" (default) resolves high watermarks with
--                           ListOffsets so lag can be reported.
-- @args kafka.max-lag-rows  Maximum lag rows printed (default 20, 1-200).
-- @args kafka.no-retry      "true" disables the retry of transient errors.
-- @args kafka.verbose       "true" adds the per-stage transcript.
--
-- @output
-- 9092/tcp open  kafka
-- | kafka-anonymous-consumer-group:
-- |   Groups listed without authentication: 3
-- |   checkout-workers: consumer/Stable, 1 member, 2 committed partitions
-- |   member consumer-1-abc: client checkout-app at /10.0.0.7
-- |   subscribed to: orders; owns: orders[0,1]
-- |   Lag: orders/0 130 behind (committed 120 of 250)
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

local function state_filter(raw)
  if raw == nil or raw == "" then return nil end
  local states = {}
  for piece in string.gmatch(raw, "[^,%s]+") do
    states[#states + 1] = piece
  end
  return #states > 0 and states or nil
end

local function read_config()
  local cfg = {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000),
    client_id = arg_string("kafka.client-id", "nmap-kafka-group-audit", 120),
    max_groups = arg_number("kafka.max-groups", 20, 1, 200),
    states = state_filter(arg_string("kafka.states", nil, 200)),
    lag = arg_bool("kafka.lag", true),
    max_lag_rows = arg_number("kafka.max-lag-rows", 20, 1, 200),
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

local function worst(findings, fallback)
  local highest = fallback or "NONE"
  for _, finding in ipairs(findings or {}) do
    if (SEVERITY_ORDER[finding.severity] or 0) > (SEVERITY_ORDER[highest] or 0) then
      highest = finding.severity
    end
  end
  return highest
end

local function finding(id, title, severity, detail, evidence, remediation)
  return { id = id, title = title, severity = severity, detail = detail,
    evidence = evidence or {}, remediation = remediation or {} }
end

-- The engine renders numbers arithmetically; words are rendered here.
local GROUP_STATE_NOTES = {
  ["Stable"] = "the group has a settled assignment",
  ["PreparingRebalance"] = "a rebalance is being negotiated, no consumer owns a partition right now",
  ["CompletingRebalance"] = "the new assignment is being handed out",
  ["Empty"] = "the group exists but has no members: offsets are kept for consumers that will come back",
  ["Dead"] = "the group is being removed",
}

local function group_state_note(state)
  if state == nil then return "the broker did not report a state (ListGroups before v4)" end
  return GROUP_STATE_NOTES[state] or "an unknown state"
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
    local attempts = 1
    if self.cfg.retry then attempts = 2 end
    local last = nil
    for attempt = 1, attempts do
      local result = fn(attempt)
      if result and result.ok then return result end
      last = result
      local code = result and result.error_code
      local retriable = code and kafka.ERRORS[code] and kafka.ERRORS[code].retriable
      if not retriable or attempt == attempts then break end
      self:stage(label, "transient error, retrying: " .. tostring(result.error))
      stdnse.sleep(self.cfg.transient_backoff_ms / 1000)
    end
    return last
  end

  return w
end

----------------------------------------------------------------------------
-- 4. ConsumerProtocol decoding
----------------------------------------------------------------------------
--
-- DescribeGroups hands back two opaque BYTES fields per member. They are not
-- part of the broker protocol: they are the consumer's own wire format, defined
-- by the consumer protocol and versioned independently, and - unlike the broker
-- APIs - they never use the compact encoding. Decoding them is what turns
-- "a member exists" into "this consumer owns these partitions of these topics".

local consumer_protocol = {}

-- Subscription (ConsumerProtocol.java):
--   version INT16, topics ARRAY[STRING], user_data BYTES,
--   [v1+] owned_partitions ARRAY[Topic Partitions], [v2+] generation_id INT32,
--   [v3+] rack_id NULLABLE_STRING
function consumer_protocol.decode_subscription(bytes)
  if not bytes or #bytes == 0 then
    return { ok = false, error = "the member carries no subscription bytes" }
  end
  local r = kafka.reader(bytes)
  local version = r:i16()
  if version == nil then return { ok = false, error = "the subscription is shorter than its version field" } end
  local topics = r:array(function(rr)
    local name = rr:str()
    if name == nil then return nil, "truncated topic name" end
    return name
  end)
  if not topics then return { ok = false, error = "the subscription topic list is truncated" } end
  local user_data = r:bytes()
  local out = {
    ok = true, version = version, topics = topics,
    user_data_bytes = user_data and #user_data or 0,
    user_data = user_data and #user_data > 0 and string.sub(user_data, 1, 64) or nil,
    owned_partitions = {}, generation_id = nil, rack_id = nil,
    trailing_bytes = r:remaining(), fields_missing = {},
  }
  if version >= 1 then
    local owned = r:array(function(rr)
      local name = rr:str()
      local partitions = rr:array(function(r3) return r3:i32() end)
      if name == nil or not partitions then return nil, "truncated owned partition entry" end
      return { topic = name, partitions = partitions }
    end)
    if owned == nil then
      out.fields_missing[#out.fields_missing + 1] = "owned_partitions (truncated)"
    else
      out.owned_partitions = owned
    end
  else
    out.fields_missing[#out.fields_missing + 1] = "owned_partitions (subscription v0)"
  end
  if version >= 2 then
    out.generation_id = r:i32()
  else
    out.fields_missing[#out.fields_missing + 1] = "generation_id (subscription v0/v1)"
  end
  if version >= 3 then
    out.rack_id = r:str()
  else
    out.fields_missing[#out.fields_missing + 1] = "rack_id (subscription before v3)"
  end
  out.trailing_bytes = r:remaining()
  return out
end

-- Assignment (ConsumerProtocol.java):
--   version INT16, assigned_partitions ARRAY[Topic Partitions], [v1+] user_data BYTES
function consumer_protocol.decode_assignment(bytes)
  if not bytes or #bytes == 0 then
    return { ok = false, error = "the member carries no assignment bytes" }
  end
  local r = kafka.reader(bytes)
  local version = r:i16()
  if version == nil then return { ok = false, error = "the assignment is shorter than its version field" } end
  local topics = r:array(function(rr)
    local name = rr:str()
    local partitions = rr:array(function(r3) return r3:i32() end)
    if name == nil or not partitions then return nil, "truncated assignment entry" end
    return { name = name, partitions = partitions }
  end)
  if not topics then return { ok = false, error = "the assignment topic list is truncated" } end
  local out = {
    ok = true, version = version, topics = topics, partition_count = 0,
    user_data_bytes = 0, user_data = nil, trailing_bytes = 0, fields_missing = {},
  }
  for _, entry in ipairs(topics) do out.partition_count = out.partition_count + #entry.partitions end
  if version >= 1 then
    local user_data = r:bytes()
    out.user_data_bytes = user_data and #user_data or 0
    out.user_data = user_data and #user_data > 0 and string.sub(user_data, 1, 64) or nil
  else
    out.fields_missing[#out.fields_missing + 1] = "user_data (assignment v0)"
  end
  out.trailing_bytes = r:remaining()
  return out
end

-- A member is reported with the subscription and the assignment it announced,
-- or with the reason that the payload could not be read.
function consumer_protocol.describe(member)
  local out = {
    member_id = member.member_id, client_id = member.client_id, client_host = member.client_host,
    group_instance_id = member.group_instance_id,
    metadata_bytes = member.metadata_bytes, assignment_bytes = member.assignment_bytes,
    subscription = consumer_protocol.decode_subscription(member.member_metadata),
    assignment = consumer_protocol.decode_assignment(member.member_assignment),
  }
  return out
end


----------------------------------------------------------------------------
-- 5. Probes
----------------------------------------------------------------------------
--
-- Every probe records what the broker answered and whether the caller was
-- allowed to ask. The distinction between "denied" and "not answered" is kept
-- all the way into the report, because an ACL that refuses group enumeration
-- and a listener that drops frames are very different findings.

local probe = {}

function probe.negotiate(w)
  local versions, err = w:negotiate()
  if not versions then
    return { stage = "api_versions", answered = false, error = err, access = "unknown" }
  end
  local summary = w.negotiate_summary
  return {
    stage = "api_versions", answered = true,
    access = (summary.error_code == 0) and "granted" or "error",
    error_code = summary.error_code, error_name = summary.error_name,
    api_count = summary.count, versions = versions,
    list_groups_version = (versions[16] or {}).broker_max,
    describe_groups_version = (versions[15] or {}).broker_max,
    offset_fetch_version = (versions[9] or {}).broker_max,
    offset_commit_version = (versions[8] or {}).broker_max,
    join_group_version = (versions[11] or {}).broker_max,
    fetch_version = (versions[1] or {}).broker_max,
    version_rows = kafka.version_table(w.connection),
  }
end

function probe.list_groups(w)
  local opts = {}
  if w.cfg.states and (w.negotiate_summary or {}).count then
    local vg = (w.version_map or {})[16]
    if vg and vg.broker_max and vg.broker_max >= 4 then opts.states = w.cfg.states end
  end
  local result = w:call("list_groups", function()
    return kafka.list_groups(w.connection, opts)
  end)
  if not result or not result.ok then
    return { stage = "list_groups", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = {
    stage = "list_groups", answered = true, version = result.version,
    error_code = result.error_code, error_name = result.error_name,
    groups = result.groups or {}, filtered_by = opts.states, throttle_ms = result.throttle_ms,
  }
  out.access = (#out.groups > 0) and "granted"
    or ((result.error_code and result.error_code ~= 0) and "denied" or "empty")
  return out
end

-- One DescribeGroups call per batch: the API takes a list of names, so the
-- script does not have to pay one round trip per group.
function probe.describe_groups(w, names, batch_size)
  if not names or #names == 0 then
    return { stage = "describe_groups", answered = true, skipped = "no group was listed" }
  end
  local collected, versions = {}, {}
  local index = 1
  local access = nil
  while index <= #names do
    local batch = {}
    for offset = 0, (batch_size or 10) - 1 do
      if names[index + offset] then batch[#batch + 1] = names[index + offset] end
    end
    local result = w:call("describe_groups", function()
      return kafka.describe_groups(w.connection, batch)
    end)
    index = index + (batch_size or 10)
    if not result or not result.ok then
      collected[#collected + 1] = { batch_error = result and result.error or "no response" }
      access = access or "unknown"
    else
      versions[#versions + 1] = result.version
      local denied, granted = 0, 0
      for _, group in ipairs(result.groups or {}) do
        collected[#collected + 1] = group
        if group.error_code == 0 then granted = granted + 1 else denied = denied + 1 end
      end
      access = granted > 0 and "granted" or (denied > 0 and "denied" or access)
    end
  end
  return {
    stage = "describe_groups", answered = true, access = access or "unknown",
    version = versions[1], versions = versions, groups = collected,
    requested = #names, batches = math.ceil(#names / (batch_size or 10)),
  }
end

function probe.find_coordinator(w, group)
  local result = w:call("find_coordinator", function()
    return kafka.find_coordinator(w.connection, group)
  end)
  if not result or not result.ok then
    return { stage = "find_coordinator", group = group, answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  return {
    stage = "find_coordinator", group = group, answered = true, version = result.version,
    node_id = result.node_id, host = result.host, port = result.port,
    error_code = result.error_code, error_name = result.error_name,
    access = (result.error_code == 0) and "granted" or "error",
  }
end

-- OffsetFetch with a null topic list returns every partition the group has ever
-- committed. The request is free of side effects: it reads the offsets and does
-- not move them.
function probe.offset_fetch(w, group)
  local result = w:call("offset_fetch", function()
    return kafka.offset_fetch(w.connection, group, nil)
  end)
  if not result or not result.ok then
    return { stage = "offset_fetch", group = group, answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = {
    stage = "offset_fetch", group = group, answered = true, version = result.version,
    error_code = result.error_code, error_name = result.error_name,
    topics = result.topics or {}, throttle_ms = result.throttle_ms,
    partition_count = 0, committed_total = 0, errors = {},
  }
  for _, topic in ipairs(out.topics) do
    for _, partition in ipairs(topic.partitions or {}) do
      out.partition_count = out.partition_count + 1
      if partition.error_code and partition.error_code ~= 0 then
        out.errors[#out.errors + 1] = topic.name .. "/" .. num_text(partition.partition)
      elseif partition.committed_offset and partition.committed_offset >= 0 then
        out.committed_total = out.committed_total + 1
      end
    end
  end
  out.access = (out.partition_count > 0) and "granted"
    or ((result.error_code and result.error_code ~= 0) and "denied" or "empty")
  return out
end

-- The high watermark of a partition is where the log currently ends, so
-- high_watermark - committed_offset is the consumer's lag in messages.
function probe.list_offsets(w, entries)
  if not entries or #entries == 0 then
    return { stage = "list_offsets", answered = true, skipped = "no committed offset to resolve" }
  end
  local result = w:call("list_offsets", function()
    return kafka.list_offsets(w.connection, entries)
  end)
  if not result or not result.ok then
    return { stage = "list_offsets", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = {
    stage = "list_offsets", answered = true, version = result.version,
    topics = result.topics or {}, rows = {}, throttle_ms = result.throttle_ms,
  }
  for _, topic in ipairs(out.topics) do
    for _, partition in ipairs(topic.partitions or {}) do
      out.rows[#out.rows + 1] = {
        topic = topic.name, partition = partition.partition, error_code = partition.error_code,
        error_name = partition.error_name, timestamp = partition.timestamp,
        high_watermark = partition.offset, leader_epoch = partition.leader_epoch,
      }
    end
  end
  local granted = 0
  for _, row in ipairs(out.rows) do if row.error_code == 0 then granted = granted + 1 end end
  out.access = granted > 0 and "granted" or "error"
  return out
end


----------------------------------------------------------------------------
-- 6. Analysis
----------------------------------------------------------------------------
--
-- The analysis answers four questions, in this order: which groups exist, who
-- is in them and what do they claim to own, what have they committed, and how
-- far behind are they. Each answer is kept as a table so the report and the
-- findings can both cite the same numbers.

local analysis = {}

-- Every member of every described group, with its decoded ConsumerProtocol
-- payloads. A group the broker refused keeps its error and contributes nothing
-- else: an empty member list must not be mistaken for an idle group.
function analysis.members(records)
  local describe = records.describe_groups or {}
  local out = { rows = {}, by_group = {}, decoded = 0, undecodable = 0, denied_groups = {} }
  for _, group in ipairs(describe.groups or {}) do
    if group.batch_error then
      out.batch_errors = (out.batch_errors or 0) + 1
    elseif group.error_code and group.error_code ~= 0 then
      out.denied_groups[#out.denied_groups + 1] = { group_id = group.group_id, error_name = group.error_name }
    else
      local entries = {}
      for _, member in ipairs(group.members or {}) do
        local row = consumer_protocol.describe(member)
        row.group_id = group.group_id
        row.group_state = group.state
        row.protocol_type = group.protocol_type
        row.protocol_data = group.protocol_data
        if row.subscription.ok and row.assignment.ok then
          out.decoded = out.decoded + 1
        else
          out.undecodable = out.undecodable + 1
        end
        entries[#entries + 1] = row
        out.rows[#out.rows + 1] = row
      end
      out.by_group[group.group_id] = {
        state = group.state, protocol_type = group.protocol_type,
        protocol_data = group.protocol_data, members = entries,
        authorized_operations = group.authorized_operations,
      }
    end
  end
  return out
end

-- The reverse index: which groups subscribe to a topic, and which member owns
-- which partition. Two members owning the same partition is an anomaly worth
-- reporting, because a stable group must have exactly one owner per partition.
function analysis.ownership(members)
  local out = { by_topic = {}, owner_of = {}, double_owned = {}, topics = {}, assigned_partitions = 0 }
  for _, row in ipairs(members.rows or {}) do
    local subscription = row.subscription
    if subscription.ok then
      for _, topic in ipairs(subscription.topics) do
        out.by_topic[topic] = out.by_topic[topic] or { subscribers = {}, owners = {} }
        out.by_topic[topic].subscribers[#out.by_topic[topic].subscribers + 1] = {
          group_id = row.group_id, member_id = row.member_id, client_id = row.client_id,
        }
        out.topics[topic] = true
      end
    end
    local assignment = row.assignment
    if assignment.ok then
      for _, entry in ipairs(assignment.topics) do
        out.by_topic[entry.name] = out.by_topic[entry.name] or { subscribers = {}, owners = {} }
        out.topics[entry.name] = true
        for _, partition in ipairs(entry.partitions) do
          out.assigned_partitions = out.assigned_partitions + 1
          local key = entry.name .. "/" .. tostring(partition)
          local owner = out.owner_of[key]
          if owner then
            out.double_owned[#out.double_owned + 1] = {
              topic = entry.name, partition = partition,
              first = owner.member_id, second = row.member_id, group_id = row.group_id,
            }
          else
            out.owner_of[key] = {
              member_id = row.member_id, client_id = row.client_id, client_host = row.client_host,
              group_id = row.group_id,
            }
          end
          out.by_topic[entry.name].owners[#out.by_topic[entry.name].owners + 1] = {
            group_id = row.group_id, member_id = row.member_id, partition = partition,
          }
        end
      end
    end
  end
  return out
end

-- Lag is computed from two independent answers: what the group committed
-- (OffsetFetch) and where the log ends (ListOffsets). A row is only reported
-- when both sides answered with an offset, so an unreachable high watermark
-- never turns into a zero.
function analysis.lag(records)
  local offsets = records.offset_fetch or {}
  local watermarks = records.list_offsets or {}
  local high = {}
  for _, row in ipairs(watermarks.rows or {}) do
    if row.error_code == 0 and row.high_watermark then
      high[row.topic .. "/" .. num_text(row.partition)] = row.high_watermark
    end
  end
  local out = { rows = {}, by_group = {}, total_lag = 0, unresolved = 0, groups = {} }
  for _, entry in ipairs(offsets.results or {}) do
    local group = entry.group_id
    out.groups[group] = out.groups[group] or { lag = 0, partitions = 0, unresolved = 0 }
    for _, topic in ipairs(entry.topics or {}) do
      for _, partition in ipairs(topic.partitions or {}) do
        local key = topic.name .. "/" .. num_text(partition.partition)
        local end_offset = high[key]
        if partition.committed_offset == nil or partition.committed_offset < 0 then
          out.unresolved = out.unresolved + 1
          out.groups[group].unresolved = out.groups[group].unresolved + 1
        elseif end_offset == nil then
          out.unresolved = out.unresolved + 1
          out.groups[group].unresolved = out.groups[group].unresolved + 1
        else
          local behind = end_offset - partition.committed_offset
          if behind < 0 then behind = 0 end
          out.rows[#out.rows + 1] = {
            group = group, topic = topic.name, partition = partition.partition,
            committed_offset = partition.committed_offset, high_watermark = end_offset,
            lag = behind, leader_epoch = partition.leader_epoch,
          }
          out.total_lag = out.total_lag + behind
          out.groups[group].lag = out.groups[group].lag + behind
          out.groups[group].partitions = out.groups[group].partitions + 1
        end
      end
    end
  end
  table.sort(out.rows, function(a, b)
    if a.lag ~= b.lag then return a.lag > b.lag end
    if a.group ~= b.group then return a.group < b.group end
    if a.topic ~= b.topic then return a.topic < b.topic end
    return a.partition < b.partition
  end)
  return out
end

function analysis.group_inventory(records, members)
  local listed = (records.list_groups or {}).groups or {}
  local out = { rows = {}, states = {}, protocols = {}, with_members = 0, with_commits = 0 }
  local offsets_by_group = {}
  for _, entry in ipairs((records.offset_fetch or {}).results or {}) do
    offsets_by_group[entry.group_id] = entry
  end
  for _, group in ipairs(listed) do
    local described = members.by_group[group.group_id]
    local offsets = offsets_by_group[group.group_id]
    local row = {
      group_id = group.group_id, protocol_type = group.protocol_type,
      state = (described and described.state) or group.state,
      group_type = group.group_type,
      members = described and #described.members or nil,
      member_ids = {},
      committed_partitions = offsets and offsets.partition_count or nil,
      lag = (records.lag and records.lag.groups or {})[group.group_id] and
        (records.lag.groups or {})[group.group_id].lag or nil,
      described = described ~= nil,
    }
    for _, member in ipairs((described and described.members) or {}) do
      row.member_ids[#row.member_ids + 1] = member.member_id
    end
    if row.members and row.members > 0 then out.with_members = out.with_members + 1 end
    if row.committed_partitions and row.committed_partitions > 0 then out.with_commits = out.with_commits + 1 end
    local state = row.state or "not reported"
    out.states[state] = (out.states[state] or 0) + 1
    out.protocols[row.protocol_type or "none"] = (out.protocols[row.protocol_type or "none"] or 0) + 1
    out.rows[#out.rows + 1] = row
  end
  return out
end

function analysis.coordinators(records)
  local out = { rows = {}, nodes = {}, errors = {} }
  for _, record in ipairs(records.find_coordinator or {}) do
    if record.answered and record.error_code == 0 then
      out.rows[#out.rows + 1] = record
      local key = num_text(record.node_id)
      out.nodes[key] = out.nodes[key] or { node_id = record.node_id, host = record.host, port = record.port, groups = {} }
      out.nodes[key].groups[#out.nodes[key].groups + 1] = record.group
    else
      out.errors[#out.errors + 1] = string.format("%s -> %s", tostring(record.group),
        tostring(record.error_name or record.error or "no answer"))
    end
  end
  return out
end

-- The summary the findings cite: which layers of the group plane answered, and
-- what an unauthenticated reader therefore holds.
function analysis.exposure(records, members, ownership, lag)
  local out = { layers = {}, granted = 0, denied = 0, unanswered = 0 }
  local function layer(name, record, detail)
    if not record then return end
    local access = record.access
    if record.answered == false then access = "unanswered" end
    if access == "granted" or access == "empty" then out.granted = out.granted + 1 end
    if access == "denied" or access == "error" then out.denied = out.denied + 1 end
    if access == "unanswered" then out.unanswered = out.unanswered + 1 end
    out.layers[#out.layers + 1] = {
      name = name, access = access or "unknown", detail = detail,
      version = record.version, error_name = record.error_name,
    }
  end
  layer("ListGroups", records.list_groups,
    (records.list_groups or {}).answered and plural(#((records.list_groups or {}).groups or {}), "group") or nil)
  layer("DescribeGroups", records.describe_groups,
    records.describe_groups and records.describe_groups.answered
      and (records.describe_groups.skipped or plural(members.decoded, "ConsumerProtocol payload decoded")) or nil)
  layer("FindCoordinator", records.find_coordinator and records.find_coordinator[1],
    records.find_coordinator and records.find_coordinator[1] and records.find_coordinator[1].answered
      and ("coordinator node " .. num_text(records.find_coordinator[1].node_id)) or nil)
  layer("OffsetFetch", records.offset_fetch,
    records.offset_fetch and records.offset_fetch.answered and
      plural(records.offset_fetch.partition_count or 0, "committed partition") or nil)
  layer("ListOffsets", records.list_offsets,
    records.list_offsets and records.list_offsets.answered
      and (records.list_offsets.skipped or plural(#(records.list_offsets.rows or {}), "high watermark")) or nil)
  out.assigned_partitions = ownership.assigned_partitions
  out.subscribed_topics = 0
  for _ in pairs(ownership.topics or {}) do out.subscribed_topics = out.subscribed_topics + 1 end
  out.lag_rows = #(lag.rows or {})
  out.total_lag = lag.total_lag or 0
  return out
end


----------------------------------------------------------------------------
-- 7. Knowledge base
----------------------------------------------------------------------------
--
-- The tables the findings quote. Keeping them here means the wording of an
-- explanation and the decision to raise it cannot drift apart.

local KB = {}

KB.REMEDIATION = {
  {
    step = "Require authentication for the group plane: set 'sasl.enabled.mechanisms' on the listener and "
      .. "'security.inter.broker.protocol' to that listener, so ListGroups, DescribeGroups and OffsetFetch "
      .. "are answered only after a successful SASL exchange.",
    why = "Every finding in this report disappears at once: an unauthenticated client cannot read the group "
      .. "plane because it cannot open the connection state that the APIs need.",
  },
  {
    step = "Grant GROUP and TOPIC permissions explicitly with 'authorizer.class.name' "
      .. "(kafka.security.authorizer.AclAuthorizer or the KRaft equivalent) and remove wildcard ACLs from "
      .. "the group resource.",
    why = "Kafka authorizes per resource: an ACL on the group is what stops a client that authenticated as "
      .. "the wrong principal from reading the offsets of another team's group.",
  },
  {
    step = "Rename the client id and host away from defaults, and keep consumer clients on a network where "
      .. "the broker is not reachable by unauthenticated peers.",
    why = "The client id and client host are chosen by the consumer, so they leak operational naming and the "
      .. "internal addressing of the consumer fleet even when the group data itself is not sensitive.",
  },
  {
    step = "Turn on 'offsets.topic.num.partitions'-aware monitoring and alert on consumer lag through "
      .. "Kafka's own metrics (kafka.consumer:type=consumer-fetch-manager-metrics) instead of relying on the "
      .. "broker to publish it to everyone.",
    why = "The lag numbers this script read from the wire are the same numbers the operators watch; if an "
      .. "attacker can read them, the operator's monitoring system is not the only consumer of that signal.",
  },
  {
    step = "Keep 'group.initial.rebalance.delay.ms' and the rebalance protocol under review, and prefer the "
      .. "KIP-848 consumer group protocol (Kafka 3.7+) where a client listener need not expose per-member "
      .. "assignments to every caller.",
    why = "The classic protocol hands the full assignment to whoever asks; the newer protocol changes what a "
      .. "DescribeGroups call can return.",
  },
  {
    step = "Re-run this script after the change and keep the output as the baseline: a listener that answers "
      .. "only after authentication produces an access summary of 'denied' rather than 'granted'.",
    why = "The change has to be verified, not assumed: an ACL can be attached to the wrong resource and the "
      .. "broker will happily keep answering.",
  },
}

KB.METHOD_LIMITS = {
  "DescribeGroups returns the member metadata and assignment as opaque BYTES; the ConsumerProtocol inside "
    .. "them is versioned by the client library, so a payload written by an exotic or very old consumer is "
    .. "reported undecodable instead of being guessed at.",
  "OffsetFetch only reports offsets that were committed. A group that consumes without committing (auto "
    .. "'enable.auto.commit=false' plus manual commits, or a stateless reader) appears with no offsets even "
    .. "though it is running.",
  "Lag is the difference between the committed offset and the log end offset sampled at a slightly later "
    .. "instant; on a busy topic the number is a snapshot and not a constant. The script never blocks the "
    .. "producer side to make it exact.",
  "ListGroups only lists groups the broker knows about; a member of a group whose coordinator is another "
    .. "broker is still listed, but its description may be answered by that other broker only.",
  "Membership is dynamic: a consumer that leaves between the ListGroups call and the DescribeGroups call is "
    .. "reported as described by the second call, which is why the report carries the state it read and not "
    .. "the state it expected.",
}

KB.VERIFICATION = {
  "kafka-consumer-groups.sh --bootstrap-server <broker> --list  (with the same credentials the audit used; "
    .. "an anonymous run should now fail where it previously listed groups)",
  "kafka-consumer-groups.sh --bootstrap-server <broker> --describe --group <group>  (compare the member "
    .. "table with the one this script printed)",
  "kafka-configs.sh --bootstrap-server <broker> --describe --entity-type users  (confirm that the SASL "
    .. "mechanisms the listener advertises are the ones you intended)",
  "kafka-acls.sh --bootstrap-server <broker> --list --group <group>  (show the ACL that is supposed to stop "
    .. "this enumeration)",
  "grep -i 'Authenticated as\\|Principals' <broker server.log>  (confirm that the requests are now "
    .. "attributed to a principal instead of ANONYMOUS)",
  "nmap -p 9092 --script kafka-anonymous-consumer-group <target>  (the same probe, expected to report "
    .. "'denied' or an authorization error per API)",
}

-- What a group state means for the person reading the report, and what changes
-- between two consecutive polls.
KB.GROUP_STATES = {
  { state = "Stable", meaning = "the assignment is settled and every partition has exactly one owner",
    between_polls = "two polls agree" },
  { state = "PreparingRebalance", meaning = "members are joining or leaving and no partition is owned",
    between_polls = "the member list and the assignments change between polls" },
  { state = "CompletingRebalance", meaning = "the leader is handing out the new assignment",
    between_polls = "the assignment is present but may still change" },
  { state = "Empty", meaning = "the group has no members, and its committed offsets are being kept",
    between_polls = "the offsets persist while no consumer exists to advance them" },
  { state = "Dead", meaning = "the group is being removed and its metadata is on the way out",
    between_polls = "the group may disappear before the next poll" },
}

-- The bridge between an observation and a threat model: every finding in this
-- report maps to something an attacker can do with it, and the report says so
-- instead of leaving the reader to work it out.
KB.ATTACK_VALUE = {
  { exposure = "group and topic inventory",
    value = "tells the attacker which pipelines exist, so effort goes into a system whose failure matters "
      .. "rather than into a topic nobody reads" },
  { exposure = "member client ids and hosts",
    value = "names the service and the machine to impersonate or to target with a denial of service" },
  { exposure = "partition ownership per member",
    value = "identifies which consumer will notice a partition disappearing, and which one holds the "
      .. "offset that a forged commit would have to match" },
  { exposure = "committed offsets and lag",
    value = "measures how much unprocessed data is in flight: the larger the lag, the longer a tampered "
      .. "record sits in the pipeline before anyone compares it" },
  { exposure = "coordinator mapping",
    value = "points at the broker whose failure stops every consumer of those groups at once" },
}

KB.RISK_RUBRIC = {
  { severity = "CRITICAL", condition = "group enumeration, description and committed offsets are all "
    .. "answered without authentication" },
  { severity = "HIGH", condition = "the group plane answers, but either the descriptions or the offsets are "
    .. "refused" },
  { severity = "MEDIUM", condition = "only the group list is readable, with no member or offset data" },
  { severity = "LOW", condition = "the listener answers with authorization errors or an empty list" },
  { severity = "INFO", condition = "nothing was answered, or the answers contained no group data" },
}

----------------------------------------------------------------------------
-- 8. Findings
----------------------------------------------------------------------------

local findings = {}

function findings.evaluate(records, members, ownership, lag, inventory, exposure)
  local list = {}
  local describe = records.describe_groups or {}
  local list_groups = records.list_groups or {}

  -- 1. The headline: the group plane itself answered an anonymous caller.
  if list_groups.answered and list_groups.access == "granted" then
    local evidence = {}
    for _, layer in ipairs(exposure.layers) do
      evidence[#evidence + 1] = string.format("%s v%s -> %s%s", layer.name, tostring(layer.version),
        tostring(layer.access), layer.error_name and (" (" .. tostring(layer.error_name) .. ")") or "")
    end
    list[#list + 1] = finding("KAFKA-ANONYMOUS-CONSUMER-GROUP-ACCESS",
      "Consumer groups are enumerable without authentication",
      "CRITICAL",
      string.format("ListGroups answered %s to an unauthenticated client, and the group plane kept "
        .. "answering: %s described, %s of committed offsets readable, %s of consumer lag computed. "
        .. "An anonymous reader therefore knows which pipelines exist, which consumers serve them, how far "
        .. "behind they are and - through the decoded assignments - exactly which partitions each consumer "
        .. "owns. That is operational intelligence about the data flow, not just about the broker.",
        plural(#(list_groups.groups or {}), "group"), tostring(members.decoded),
        plural(records.offset_fetch and records.offset_fetch.partition_count or 0, "partition"),
        plural(#lag.rows, "row")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[2] })
  elseif list_groups.answered and list_groups.access == "empty" then
    list[#list + 1] = finding("KAFKA-GROUP-PLANE-EMPTY",
      "The group plane answered, but no group was listed",
      "INFO",
      "ListGroups answered with an empty list, which means the request was authorized and the cluster "
        .. "simply has no consumer groups on it, or every group was filtered out by the state filter. An "
        .. "empty answer is not a refusal, and the distinction matters for the next run.",
      { string.format("filter: %s", fmt_list(list_groups.filtered_by, 6, "none")) },
      { KB.REMEDIATION[1] })
  elseif list_groups.answered and (list_groups.access == "denied" or list_groups.error_code ~= 0) then
    list[#list + 1] = finding("KAFKA-GROUP-ENUMERATION-DENIED",
      "Group enumeration was refused without authentication",
      "LOW",
      string.format("ListGroups answered with %s instead of a group list: the cluster checks the principal "
        .. "on this path. That is the intended behaviour and it is reported so the baseline is explicit.",
        tostring(list_groups.error_name)),
      { string.format("ListGroups v%s -> %s", tostring(list_groups.version),
        tostring(list_groups.error_name)) }, { KB.REMEDIATION[2] })
  end

  -- 2. Member identity: client ids and hosts.
  local identified = 0
  local identity_rows = {}
  for _, row in ipairs(members.rows or {}) do
    if row.client_id or row.client_host then
      identified = identified + 1
      identity_rows[#identity_rows + 1] = string.format("%s/%s: client %s at %s", tostring(row.group_id),
        tostring(row.member_id), tostring(row.client_id or "?"), tostring(row.client_host or "?"))
    end
  end
  if identified > 0 then
    list[#list + 1] = finding("KAFKA-MEMBER-IDENTITY-DISCLOSURE",
      "Consumer member identities are disclosed",
      "HIGH",
      string.format("%s were published with the client id and the client host of each member. The client id "
        .. "is chosen by the application and the host is the address the consumer connects from, so together "
        .. "they name the service and the machine that runs it. Used with the assignment data below, this is "
        .. "the map an attacker needs to decide which consumer to impersonate or disrupt.",
        plural(identified, "member")),
      identity_rows, { KB.REMEDIATION[2], KB.REMEDIATION[3] })
  end

  -- 3. The decoded subscription and assignment: what is consumed and by whom.
  local subscribed = {}
  for topic in pairs(ownership.topics or {}) do subscribed[#subscribed + 1] = topic end
  table.sort(subscribed)
  if exposure.assigned_partitions > 0 or #subscribed > 0 then
    local evidence = {}
    for index = 1, math.min(#subscribed, 10) do
      local topic = subscribed[index]
      local entry = ownership.by_topic[topic] or { subscribers = {}, owners = {} }
      evidence[#evidence + 1] = string.format("%s: %s subscribed, %s assigned",
        topic, plural(#entry.subscribers, "member"), plural(#entry.owners, "partition"))
    end
    list[#list + 1] = finding("KAFKA-CONSUMER-ASSIGNMENT-DISCLOSURE",
      "Consumer subscriptions and partition ownership are disclosed",
      "HIGH",
      string.format("The ConsumerProtocol payloads inside DescribeGroups were decoded: %s across %s, with %s "
        .. "mapped to a specific member inside a specific group. Partition ownership is the difference "
        .. "between knowing that a topic is consumed and knowing which process will notice if it stops; it "
        .. "is also what a targeted attack on a consumer (or on its offsets) needs first.",
        plural(exposure.assigned_partitions or 0, "assigned partition"),
        plural(#subscribed, "topic"), plural(exposure.assigned_partitions or 0, "partition")),
      evidence, { KB.REMEDIATION[2], KB.REMEDIATION[5] })
  end

  if #ownership.double_owned > 0 then
    local rows = {}
    for index = 1, math.min(#ownership.double_owned, 6) do
      local entry = ownership.double_owned[index]
      rows[#rows + 1] = string.format("%s/%d claimed by %s and %s", entry.topic, entry.partition,
        tostring(entry.first), tostring(entry.second))
    end
    list[#list + 1] = finding("KAFKA-PARTITION-DOUBLE-OWNERSHIP",
      "Two members claim the same partition",
      "MEDIUM",
      string.format("%s were claimed by two members at the same time. In a stable group that cannot happen: "
        .. "either a rebalance was in flight while the scan ran, or the consumers are using a static "
        .. "membership configuration that disagrees with the group state.",
        plural(#ownership.double_owned, "partition")), rows, { KB.REMEDIATION[5] })
  end

  -- 4. Committed offsets and lag.
  local offset_record = records.offset_fetch or {}
  if offset_record.partition_count and offset_record.partition_count > 0 then
    local evidence = {
      string.format("committed partitions: %d", offset_record.partition_count),
      string.format("groups with commits: %d", inventory.with_commits or 0),
      string.format("lag rows computed: %d", #lag.rows),
    }
    local severity = (#lag.rows > 0) and "HIGH" or "MEDIUM"
    list[#list + 1] = finding("KAFKA-COMMITTED-OFFSET-DISCLOSURE",
      "Committed consumer offsets are readable without authentication",
      severity,
      string.format("OffsetFetch returned the committed offset of %s, and ListOffsets supplied the log end, "
        .. "so the report can state how much unconsumed data exists on the cluster: %d message(s) of lag "
        .. "across %d of the %s. Committed offsets are a record of the system's progress; the lag derived "
        .. "from them is a measure of how much unprocessed data an attacker could influence.",
        plural(offset_record.partition_count, "partition"), lag.total_lag, #lag.rows,
        plural(offset_record.partition_count, "partition")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[4] })
  end

  if #lag.rows > 0 and lag.total_lag > 0 then
    local top = lag.rows[1]
    list[#list + 1] = finding("KAFKA-CONSUMER-LAG-EXPOSURE",
      "Consumer lag is computed and reported",
      "MEDIUM",
      string.format("The worst lag observed was %d message(s) on %s/%s for group %s (committed %s of %s). "
        .. "Lag is operationally sensitive: it says which pipeline is falling behind, and a consumer that is "
        .. "already behind is the one whose failure will not be noticed immediately.",
        top.lag, top.topic, num_text(top.partition), top.group,
        tostring(top.committed_offset), tostring(top.high_watermark)),
      { string.format("total lag across the cluster: %d message(s)", lag.total_lag),
        string.format("lag rows: %d", #lag.rows) }, { KB.REMEDIATION[4] })
  end

  -- 5. Group state: a rebalance in flight is a window of inconsistent state.
  local rebalancing = {}
  for _, row in ipairs(inventory.rows or {}) do
    if row.state and (row.state == "PreparingRebalance" or row.state == "CompletingRebalance") then
      rebalancing[#rebalancing + 1] = string.format("%s (%s)", row.group_id, row.state)
    end
  end
  if #rebalancing > 0 then
    list[#list + 1] = finding("KAFKA-REBALANCE-OBSERVED",
      "Groups were mid-rebalance while the scan ran",
      "INFO",
      string.format("%s were rebalancing. During a rebalance no member owns a partition, the assignment "
        .. "churns, and a reader polling DescribeGroups sees a different picture from one poll to the next; "
        .. "the finding is informational because a rebalance is normal, but it also explains why two "
        .. "consecutive scans can disagree.",
        plural(#rebalancing, "group")), rebalancing, { KB.REMEDIATION[5] })
  end

  -- 6. The coordinator map.
  local coordinators = records.coordinators or {}
  if #(coordinators.rows or {}) > 0 then
    local nodes_seen = 0
    local evidence = {}
    for node_id, node in pairs(coordinators.nodes or {}) do
      nodes_seen = nodes_seen + 1
      evidence[#evidence + 1] = string.format("node %s (%s:%s) coordinates %s", tostring(node_id),
        tostring(node.host), tostring(node.port), plural(#node.groups, "group"))
    end
    list[#list + 1] = finding("KAFKA-COORDINATOR-MAP-EXPOSED",
      "The coordinator of every group is disclosed",
      "LOW",
      string.format("FindCoordinator named the broker that coordinates %s across %s. The coordinator owns "
        .. "the group's state and is the single point that a group-level denial of service would aim at; "
        .. "mapping groups to brokers is the reconnaissance step before touching either.",
        plural(#coordinators.rows, "group"), plural(nodes_seen, "broker")),
      evidence, { KB.REMEDIATION[2] })
  end

  if not list_groups.answered then
    list[#list + 1] = finding("KAFKA-GROUP-PLANE-UNREACHABLE",
      "The group plane could not be measured",
      "INFO",
      string.format("ListGroups was not answered (%s). The group plane may be ACL-protected, may be dropped "
        .. "by a listener that requires authentication, or may simply have timed out; the transport section "
        .. "above says which, and this report makes no claim beyond that.",
        tostring(list_groups.error)), { tostring(list_groups.error) }, { KB.REMEDIATION[1] })
  end

  return list
end


----------------------------------------------------------------------------
-- 9. Report
----------------------------------------------------------------------------

local report = {}

function report.target_section(cfg, host, port, w, records)
  local lines = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id: %s", cfg.client_id),
    string.format("Timeout: %dms, retry on transient errors: %s", cfg.timeout, fmt_bool(cfg.retry)),
    string.format("Group budget: %s (max-groups), lag resolution: %s",
      plural(cfg.max_groups, "group"), fmt_bool(cfg.lag)),
  }
  if cfg.states then lines[#lines + 1] = "State filter: " .. fmt_list(cfg.states, 6) end
  local versions = (records.negotiate or {}).versions or {}
  local version_list = {}
  for _, key in ipairs({ 16, 15, 10, 9, 2, 8, 11 }) do
    local entry = versions[key]
    if entry and entry.broker_max then
      version_list[#version_list + 1] = string.format("%s v%d", kafka.api_name(key), entry.broker_max)
    end
  end
  if #version_list > 0 then lines[#lines + 1] = "Group APIs offered: " .. fmt_list(version_list, 8) end
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

-- The access matrix: one row per API of the group plane, with the verdict, the
-- negotiated version and what the answer contained.
function report.exposure_section(exposure, records)
  local lines = {}
  local header = string.format("%-18s %-14s %-8s %s", "API", "Access", "Version", "What came back")
  lines[#lines + 1] = header
  for _, layer in ipairs(exposure.layers or {}) do
    lines[#lines + 1] = string.format("%-18s %-14s %-8s %s", layer.name, tostring(layer.access),
      layer.version and ("v" .. tostring(layer.version)) or "-", tostring(layer.detail or "-"))
  end
  lines[#lines + 1] = string.format("Summary: %d granted or empty, %d denied, %d unanswered",
    exposure.granted or 0, exposure.denied or 0, exposure.unanswered or 0)
  if exposure.lag_rows and exposure.lag_rows > 0 then
    lines[#lines + 1] = string.format("Derived from the answers: %s assigned to a member, %s lagging",
      plural(exposure.assigned_partitions, "partition"), plural(exposure.lag_rows, "partition"))
  end
  return lines
end

function report.inventory_section(inventory, records)
  if not (records.list_groups or {}).answered then
    return { "ListGroups was not answered, so no group inventory exists." }
  end
  if #(inventory.rows or {}) == 0 then
    return { "The broker listed no consumer group." }
  end
  local lines = {}
  for _, row in ipairs(inventory.rows) do
    local members = row.members and num_text(row.members) or "?"
    local commits = row.committed_partitions and num_text(row.committed_partitions) or "?"
    local lag = row.lag and num_text(row.lag) or "?"
    lines[#lines + 1] = string.format("%s: %s/%s, %s, %s committed, lag %s",
      row.group_id, tostring(row.protocol_type or "none"), tostring(row.state or "state not reported"),
      plural(row.members or 0, "member"), commits, lag)
    if not row.described then
      lines[#lines + 1] = "    not described: the group was beyond kafka.max-groups or DescribeGroups "
        .. "refused it"
    elseif row.members == 0 then
      lines[#lines + 1] = "    " .. group_state_note(row.state)
    end
  end
  local state_pairs = {}
  for state, count in pairs(inventory.states or {}) do
    state_pairs[#state_pairs + 1] = string.format("%s x%d", tostring(state), count)
  end
  table.sort(state_pairs)
  lines[#lines + 1] = "States: " .. fmt_list(state_pairs, 8)
  return lines
end

function report.member_section(members, cfg)
  local lines = {}
  if #(members.rows or {}) == 0 then
    if members.denied_groups and #members.denied_groups > 0 then
      lines[#lines + 1] = "DescribeGroups was refused for: "
        .. fmt_list((function()
          local names = {}
          for _, entry in ipairs(members.denied_groups) do
            names[#names + 1] = entry.group_id .. " (" .. tostring(entry.error_name) .. ")"
          end
          return names
        end)(), 8)
    else
      lines[#lines + 1] = "No member was described."
    end
    return lines
  end
  for _, row in ipairs(members.rows) do
    lines[#lines + 1] = string.format("%s / %s: client %s at %s%s", tostring(row.group_id),
      tostring(row.member_id), tostring(row.client_id or "?"), tostring(row.client_host or "?"),
      row.group_instance_id and (" (static member " .. tostring(row.group_instance_id) .. ")") or "")
    local subscription = row.subscription
    if subscription.ok then
      lines[#lines + 1] = string.format("    subscription v%s: topics %s; user data %s%s",
        num_text(subscription.version), fmt_list(subscription.topics, 8, "none"),
        plural(subscription.user_data_bytes, "byte"),
        subscription.generation_id and ("; generation " .. num_text(subscription.generation_id)) or "")
      if #subscription.owned_partitions > 0 then
        local owned = {}
        for _, entry in ipairs(subscription.owned_partitions) do
          owned[#owned + 1] = string.format("%s[%s]", entry.topic,
            fmt_list(entry.partitions, 8, "-"))
        end
        lines[#lines + 1] = "    thinks it owns: " .. fmt_list(owned, 6)
      end
      if subscription.rack_id then
        lines[#lines + 1] = "    rack: " .. tostring(subscription.rack_id)
      end
    else
      lines[#lines + 1] = "    subscription not decoded: " .. tostring(subscription.error)
    end
    local assignment = row.assignment
    if assignment.ok then
      local owned = {}
      for _, entry in ipairs(assignment.topics) do
        owned[#owned + 1] = string.format("%s[%s]", entry.name, fmt_list(entry.partitions, 10, "-"))
      end
      lines[#lines + 1] = string.format("    assignment v%s: %s in %s; user data %s",
        num_text(assignment.version), plural(assignment.partition_count, "partition"),
        plural(#assignment.topics, "topic"), plural(assignment.user_data_bytes, "byte"))
      if #owned > 0 then lines[#lines + 1] = "    owns: " .. fmt_list(owned, 6) end
    else
      lines[#lines + 1] = "    assignment not decoded: " .. tostring(assignment.error)
    end
  end
  lines[#lines + 1] = string.format("Decoded %s, undecodable %s",
    plural(members.decoded or 0, "payload"), tostring(members.undecodable or 0))
  return lines
end

function report.ownership_section(ownership)
  local lines = {}
  if not ownership.topics or not next(ownership.topics) then
    return { "No subscription or assignment named a topic." }
  end
  local topics = {}
  for topic in pairs(ownership.topics) do topics[#topics + 1] = topic end
  table.sort(topics)
  for _, topic in ipairs(topics) do
    local entry = ownership.by_topic[topic] or { subscribers = {}, owners = {} }
    lines[#lines + 1] = string.format("%s: %s subscribed, %s assigned to a member", topic,
      plural(#entry.subscribers, "member"), plural(#entry.owners, "partition"))
    local by_member = {}
    for _, owner in ipairs(entry.owners) do
      local key = owner.member_id
      by_member[key] = by_member[key] or {}
      by_member[key][#by_member[key] + 1] = owner.partition
    end
    local member_keys = {}
    for key in pairs(by_member) do member_keys[#member_keys + 1] = key end
    table.sort(member_keys)
    for _, member in ipairs(member_keys) do
      table.sort(by_member[member])
      lines[#lines + 1] = string.format("    %s owns [%s]", tostring(member),
        fmt_list(by_member[member], 16))
    end
  end
  if #(ownership.double_owned or {}) > 0 then
    lines[#lines + 1] = string.format("Anomaly: %s claimed by two members at once",
      plural(#ownership.double_owned, "partition"))
  end
  return lines
end

function report.lag_section(lag, cfg, watermark_record)
  local lines = {}
  if watermark_record and watermark_record.skipped then
    lines[#lines + 1] = "Lag resolution was skipped: " .. tostring(watermark_record.skipped)
    if #(lag.rows or {}) == 0 and (lag.unresolved or 0) > 0 then
      lines[#lines + 1] = string.format("%s kept their committed offset but no log end was fetched.",
        plural(lag.unresolved, "partition"))
    end
    return lines
  end
  if not lag.rows or #lag.rows == 0 then
    if lag.unresolved and lag.unresolved > 0 then
      lines[#lines + 1] = string.format(
        "%s could not be resolved into a lag number: either the group never committed an offset or the "
        .. "high watermark was not answered for that partition.", plural(lag.unresolved, "partition"))
    else
      lines[#lines + 1] = "No committed offset produced a lag row."
    end
    return lines
  end
  lines[#lines + 1] = string.format("%-20s %-16s %6s %12s %12s %8s", "Group", "Topic/part", "Latest",
    "Committed", "Log end", "Behind")
  for index = 1, math.min(#lag.rows, cfg.max_lag_rows) do
    local row = lag.rows[index]
    lines[#lines + 1] = string.format("%-20s %-16s %6s %12s %12s %8d", tostring(row.group),
      row.topic .. "/" .. num_text(row.partition), "yes", num_text(row.committed_offset),
      num_text(row.high_watermark), row.lag)
  end
  if #lag.rows > cfg.max_lag_rows then
    lines[#lines + 1] = string.format("(%d further rows not shown; raise kafka.max-lag-rows)",
      #lag.rows - cfg.max_lag_rows)
  end
  lines[#lines + 1] = string.format("Total lag: %d message(s) across %s",
    lag.total_lag or 0, plural(#lag.rows, "partition"))
  if lag.unresolved and lag.unresolved > 0 then
    lines[#lines + 1] = string.format("Unresolved partitions (no commit or no watermark): %d", lag.unresolved)
  end
  return lines
end

function report.coordinator_section(coordinators)
  local lines = {}
  if not coordinators or #(coordinators.rows or {}) == 0 then
    return { "FindCoordinator produced no coordinator mapping." }
  end
  local node_ids = {}
  for node_id in pairs(coordinators.nodes or {}) do node_ids[#node_ids + 1] = node_id end
  table.sort(node_ids)
  for _, node_id in ipairs(node_ids) do
    local node = coordinators.nodes[node_id]
    lines[#lines + 1] = string.format("node %s (%s:%s): %s", tostring(node_id), tostring(node.host),
      tostring(node.port), fmt_list(node.groups, 10))
  end
  for _, error in ipairs(coordinators.errors or {}) do
    lines[#lines + 1] = "not resolved: " .. error
  end
  return lines
end

function report.finding_section(list)
  if #list == 0 then
    return { "No findings: the group plane published nothing to an unauthenticated caller." }
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

function report.state_section(inventory)
  local lines = {}
  for _, entry in ipairs(KB.GROUP_STATES) do
    local seen = (inventory.states or {})[entry.state]
    lines[#lines + 1] = string.format("%s%s: %s; between two polls, %s", entry.state,
      seen and string.format(" (%d)", seen) or "", entry.meaning, entry.between_polls)
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

function report.rubric_section()
  local lines = {}
  for _, entry in ipairs(KB.RISK_RUBRIC) do
    lines[#lines + 1] = string.format("%s: %s", entry.severity, entry.condition)
  end
  return lines
end

function report.build(cfg, host, port, records, members, ownership, lag, inventory, exposure, coordinators, list, w)
  local out = stdnse.output_table()
  out["Target"] = report.target_section(cfg, host, port, w, records)
  out["Access matrix"] = report.exposure_section(exposure, records)
  out["Group inventory"] = report.inventory_section(inventory, records)
  out["Members and identity"] = report.member_section(members, cfg)
  out["Subscriptions and ownership"] = report.ownership_section(ownership)
  out["Committed offsets and lag"] = report.lag_section(lag, cfg, records.list_offsets)
  out["Coordinators"] = report.coordinator_section(coordinators)
  out["Findings"] = report.finding_section(list)
  out["Remediation"] = report.remediation_section(list)
  out["Group state reference"] = report.state_section(inventory)
  out["Why the exposure matters"] = report.value_section(list)
  out["Risk rubric"] = report.rubric_section()
  out["Method limits"] = KB.METHOD_LIMITS
  out["Verification"] = KB.VERIFICATION
  -- A listener that never answered ApiVersions was not audited at all: the
  -- group plane is unmeasured, which is not the same as clean.
  if not (records.negotiate and records.negotiate.answered) then
    out["Risk Level"] = "UNKNOWN"
  else
    out["Risk Level"] = worst(list, "NONE")
  end
  local summary = {}
  for _, severity in ipairs({ "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" }) do
    local count = 0
    for _, item in ipairs(list) do
      if item.severity == severity then count = count + 1 end
    end
    if count > 0 then summary[#summary + 1] = string.format("%s x%d", severity, count) end
  end
  out["Finding summary"] = #summary > 0 and table.concat(summary, ", ") or "no findings"
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

-- The lag resolution needs the topics that the groups committed, so the two
-- requests are chained: OffsetFetch first, then one ListOffsets call for every
-- topic that appeared in a committed offset.
local function collect_offset_fetch(w, group_names, cfg)
  local combined = { results = {}, rows = {}, partition_count = 0, answered = true, access = nil, errors = {} }
  for _, group in ipairs(group_names) do
    local record = probe.offset_fetch(w, group)
    if record.answered then
      combined.results[#combined.results + 1] = {
        group_id = group, topics = record.topics, error_code = record.error_code,
        error_name = record.error_name, partition_count = record.partition_count,
      }
      combined.partition_count = combined.partition_count + (record.partition_count or 0)
      for _, error in ipairs(record.errors or {}) do combined.errors[#combined.errors + 1] = error end
      combined.version = combined.version or record.version
      if record.access == "granted" then combined.access = "granted"
      elseif not combined.access and record.access == "denied" then combined.access = "denied" end
    else
      combined.answered = false
      combined.errors[#combined.errors + 1] = group .. ": " .. tostring(record.error)
    end
  end
  combined.access = combined.access or (combined.answered and "empty" or "unknown")
  return combined
end

local function collect_list_offsets(w, offset_record, cfg)
  if not cfg.lag then
    return { stage = "list_offsets", answered = true, skipped = "kafka.lag=false", rows = {} }
  end
  local wanted = {}
  for _, entry in ipairs(offset_record.results or {}) do
    for _, topic in ipairs(entry.topics or {}) do
      local bucket = wanted[topic.name]
      if not bucket then
        bucket = { name = topic.name, partitions = {}, seen = {} }
        wanted[topic.name] = bucket
      end
      for _, partition in ipairs(topic.partitions or {}) do
        if not bucket.seen[partition.partition] then
          bucket.seen[partition.partition] = true
          bucket.partitions[#bucket.partitions + 1] = { partition = partition.partition, timestamp = -1 }
        end
      end
    end
  end
  local entries = {}
  for _, bucket in pairs(wanted) do
    table.sort(bucket.partitions, function(a, b) return a.partition < b.partition end)
    entries[#entries + 1] = { name = bucket.name, partitions = bucket.partitions }
  end
  table.sort(entries, function(a, b) return a.name < b.name end)
  return probe.list_offsets(w, entries)
end

action = function(host, port)
  local cfg = read_config()
  local w = new_wire(host, port, cfg)
  local out = stdnse.output_table()
  local connected, connect_error = w:connect()
  if not connected then
    out["Risk Level"] = "UNKNOWN"
    out["Target"] = { string.format("Endpoint: %s:%d/tcp", host.ip or "target", port.number),
      "Transport failure: " .. tostring(connect_error) }
    out["Method limits"] = {
      "The TCP connection failed, so the group plane was never reached. A TLS-only listener answers a "
        .. "plaintext Kafka probe exactly like this.",
    }
    return out
  end

  local records = {}
  records.negotiate = probe.negotiate(w)
  records.list_groups = probe.list_groups(w)

  local group_names = {}
  for _, group in ipairs((records.list_groups.groups or {})) do
    if #group_names >= cfg.max_groups then break end
    group_names[#group_names + 1] = group.group_id
  end

  records.describe_groups = probe.describe_groups(w, group_names, 10)
  records.find_coordinator = {}
  for _, group in ipairs(group_names) do
    records.find_coordinator[#records.find_coordinator + 1] = probe.find_coordinator(w, group)
  end
  records.offset_fetch = collect_offset_fetch(w, group_names, cfg)
  records.list_offsets = collect_list_offsets(w, records.offset_fetch, cfg)
  w:close()

  local members = analysis.members(records)
  local ownership = analysis.ownership(members)
  local lag = analysis.lag(records)
  records.lag = lag
  local inventory = analysis.group_inventory(records, members)
  local exposure = analysis.exposure(records, members, ownership, lag)
  local coordinators = analysis.coordinators(records)
  records.coordinators = coordinators
  local list = findings.evaluate(records, members, ownership, lag, inventory, exposure)

  local result = report.build(cfg, host, port, records, members, ownership, lag, inventory, exposure,
    coordinators, list, w)

  -- Register the confirmed exposures with Nmap's vulnerability machinery so
  -- they appear in normal and XML output, not only in the script table.
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
