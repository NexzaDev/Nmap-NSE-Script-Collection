local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- Framing, version negotiation and every response parser come from the shared
-- engine; this script owns the probes, the analysis and the report.
local ok, kafka = pcall(require, "kafka")

description = [[
Measures how much cluster state a Kafka listener hands to an unauthenticated
caller, with the controller and the metadata epoch at the centre of it.

An unauthenticated Metadata request does not only list topic names. On a
current broker it answers with:

  * the controller id, and - through the KRaft-aware DescribeCluster API - the
    endpoint type and the controller addresses,
  * the cluster id, every broker address and rack,
  * for every partition: the leader, the full replica assignment, the in-sync
    replica set, the leader epoch and any offline replica,
  * the per-topic and per-cluster authorized-operations masks.

That is a complete map of the data layer. The script collects it, decides what
it exposes (under-replication, leader concentration, a controller that moved
mid-scan) and reports each conclusion with the observation behind it, sampling
Metadata repeatedly so an election during the scan is visible instead of
averaged away. Nothing here writes, consumes or commits.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-controller-epoch-leak --script-args kafka.samples=5 <target>
--
-- @args kafka.timeout        Per-request timeout in milliseconds
--                            (default 5000, range 500-60000).
-- @args kafka.client-id      Client id used in every request header
--                            (default "nmap-kafka-controller-audit").
-- @args kafka.max-topics     Maximum topics described in the report
--                            (default 30, range 1-500).
-- @args kafka.samples        Metadata samples taken to observe controller or
--                            leader movement (default 3, range 1-10).
-- @args kafka.sample-gap-ms  Delay between samples (default 400, 0-10000).
-- @args kafka.verbose        "true" adds the per-stage transcript.
--
-- @output
-- 9092/tcp open  kafka
-- | kafka-controller-epoch-leak:
-- |   Controller: 2 (1 endpoint advertised, KRaft aware)
-- |   Cluster id: nse-open-cluster
-- |   Brokers: 3, topics: 42 (5 internal), partitions: 180
-- |   Exposure: broker inventory, replica assignment, ISR, leader epochs
-- |_  Risk Level: MEDIUM
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
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({9092, 9093, 9094, 19092, 29092}, "kafka", {"tcp"})

local SCRIPT_RISK = "LOW"
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

local function read_config()
  local cfg = {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000),
    client_id = arg_string("kafka.client-id", "nmap-kafka-controller-audit", 120),
    max_topics = arg_number("kafka.max-topics", 30, 1, 500),
    samples = arg_number("kafka.samples", 3, 1, 10),
    sample_gap_ms = arg_number("kafka.sample-gap-ms", 400, 0, 10000),
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
-- 4. Probes
----------------------------------------------------------------------------

local probe = {}

function probe.api_versions(w)
  local versions, err = w:negotiate()
  if not versions then
    return { stage = "api_versions", answered = false, error = err }
  end
  return {
    stage = "api_versions", answered = true, version_rows = kafka.version_table(w.connection),
    versions = versions, api_count = w.negotiate_summary.count,
    metadata_version = (versions[3] or {}).broker_max,
    cluster_version = (versions[60] or {}).broker_max,
  }
end

function probe.metadata(w, label)
  local result = w:call("metadata", function()
    return kafka.metadata(w.connection, nil)
  end)
  if not result or not result.ok then
    return { stage = "metadata", label = label, answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = {
    stage = "metadata", label = label, answered = true, version = result.version,
    cluster_id = result.cluster_id, controller_id = result.controller_id,
    brokers = result.brokers or {}, topics = {}, topic_count = 0, internal = 0,
    errors = {}, throttle_ms = result.throttle_ms,
  }
  for _, topic in ipairs(result.topics or {}) do
    if topic.error_code == 0 then
      out.topic_count = out.topic_count + 1
      if topic.is_internal then out.internal = out.internal + 1 end
      if #out.topics < (w.cfg.max_topics * 4) then out.topics[#out.topics + 1] = topic end
    else
      out.errors[#out.errors + 1] = topic
    end
  end
  out.access = out.topic_count > 0 and "granted" or "empty"
  return out
end

function probe.describe_cluster(w)
  local result = w:call("describe_cluster", function()
    return kafka.describe_cluster(w.connection, { include_authorized_operations = true })
  end)
  if not result or not result.ok then
    return { stage = "describe_cluster", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  return {
    stage = "describe_cluster", answered = true, version = result.version,
    error_code = result.error_code, error_name = result.error_name,
    endpoint_type = result.endpoint_type, cluster_id = result.cluster_id,
    controller_id = result.controller_id, brokers = result.brokers or {},
    cluster_authorized_operations = result.cluster_authorized_operations,
    access = (result.error_code == 0) and "granted" or "error",
  }
end

-- Metadata is sampled repeatedly so that a controller election or a leader
-- change during the scan becomes an observation instead of noise. Each sample
-- records what changed, not just what was there.
function probe.samples(w, count, gap_ms)
  local samples = {}
  for index = 1, count do
    local sample = probe.metadata(w, "sample-" .. tostring(index))
    samples[#samples + 1] = sample
    if index < count and gap_ms > 0 then stdnse.sleep(gap_ms / 1000) end
  end
  return samples
end


----------------------------------------------------------------------------
-- 5. Analysis
----------------------------------------------------------------------------
local analysis = {}

-- Which Metadata version carries which field; the report says honestly what
-- this broker could and could not have told us.
local METADATA_FEATURES = {
  { version = 1, field = "controller id", note = "the identity of the elected controller" },
  { version = 2, field = "cluster id", note = "the cluster's permanent identifier" },
  { version = 5, field = "offline replicas", note = "partitions whose replicas are down" },
  { version = 7, field = "leader epochs", note = "the epoch of every partition leadership" },
  { version = 8, field = "authorized operations", note = "the ACL mask for topics and the cluster" },
  { version = 9, field = "compact schemas", note = "the flexible encoding with tagged fields" },
}

function analysis.features(metadata_version)
  local available, missing = {}, {}
  for _, feature in ipairs(METADATA_FEATURES) do
    if metadata_version and metadata_version >= feature.version then
      available[#available + 1] = feature
    else
      missing[#missing + 1] = feature
    end
  end
  return available, missing
end

function analysis.topology(records, cfg)
  local metadata = records.samples and records.samples[1] or records.metadata
  local cluster = records.describe_cluster or {}
  local out = {
    brokers = (metadata and metadata.brokers) or cluster.brokers or {},
    cluster_id = (metadata and metadata.cluster_id) or cluster.cluster_id,
    controller_id = (metadata and metadata.controller_id) or cluster.controller_id,
    topic_count = (metadata and metadata.topic_count) or 0,
    internal_topics = (metadata and metadata.internal) or 0,
    partitions = 0, leaders = 0, replicas = 0, isr_entries = 0,
    under_replicated = {}, offline_replicas = {}, leader_epochs = {},
    leader_distribution = {}, racks = {}, replica_counts = {},
  }
  local topics = (metadata and metadata.topics) or {}
  for _, topic in ipairs(topics) do
    local under = 0
    for _, partition in ipairs(topic.partitions or {}) do
      out.partitions = out.partitions + 1
      local replicas = #(partition.replicas or {})
      local isr = #(partition.isr or {})
      out.replicas = out.replicas + replicas
      out.isr_entries = out.isr_entries + isr
      out.replica_counts[replicas] = (out.replica_counts[replicas] or 0) + 1
      if partition.leader_id and partition.leader_id >= 0 then
        out.leaders = out.leaders + 1
        out.leader_distribution[partition.leader_id] = (out.leader_distribution[partition.leader_id] or 0) + 1
      end
      if partition.leader_epoch and partition.leader_epoch > 0 then
        out.leader_epochs[#out.leader_epochs + 1] = {
          topic = topic.name, partition = partition.index, epoch = partition.leader_epoch,
        }
      end
      if isr < replicas then
        under = under + 1
        out.under_replicated[#out.under_replicated + 1] = {
          topic = topic.name, partition = partition.index,
          replicas = replicas, isr = isr, leader = partition.leader_id,
        }
      end
      for _, replica in ipairs(partition.offline_replicas or {}) do
        out.offline_replicas[#out.offline_replicas + 1] = {
          topic = topic.name, partition = partition.index, broker = replica,
        }
      end
    end
    if under > 0 then out.replica_counts[-1] = (out.replica_counts[-1] or 0) + 1 end
  end
  for _, broker in ipairs(out.brokers) do
    if broker.rack and broker.rack ~= "" then out.racks[broker.rack] = (out.racks[broker.rack] or 0) + 1 end
  end
  out.controller_is_broker = false
  for _, broker in ipairs(out.brokers) do
    if broker.broker_id == out.controller_id then out.controller_is_broker = true end
  end
  out.top_leader = { broker = nil, count = 0 }
  for broker, count in pairs(out.leader_distribution) do
    if count > out.top_leader.count then out.top_leader = { broker = broker, count = count } end
  end
  out.max_topics_shown = cfg.max_topics
  return out
end

-- Everything an unauthenticated caller learned, phrased as exposure.
function analysis.exposure(records, topology, cluster)
  local exposed = {}
  local function add(kind, detail)
    exposed[#exposed + 1] = { kind = kind, detail = detail }
  end
  if #topology.brokers > 0 then
    add("broker inventory", string.format("%s with addresses, ports and racks",
      plural(#topology.brokers, "broker")))
  end
  if topology.cluster_id and topology.controller_id then
    add("cluster and controller identity", string.format("cluster %s, controller %s (%s)",
      tostring(topology.cluster_id), tostring(topology.controller_id),
      topology.controller_is_broker and "present in the broker list" or "not advertised as a broker"))
  end
  if cluster and cluster.answered and cluster.version and cluster.version >= 1 then
    add("controller endpoints", string.format("endpoint type %s advertised through DescribeCluster v%s",
      tostring(cluster.endpoint_type), tostring(cluster.version)))
  end
  if topology.partitions > 0 then
    add("partition topology", string.format("%s, %s, %s",
      plural(topology.partitions, "partition"), plural(topology.replicas, "replica assignment"),
      plural(topology.isr_entries, "in-sync replica")))
  end
  if #topology.leader_epochs > 0 then
    add("leader epochs", string.format("%s readable, so leadership changes can be timed from outside",
      plural(#topology.leader_epochs, "partition")))
  end
  if #topology.offline_replicas > 0 then
    add("offline replicas", plural(#topology.offline_replicas, "replica") .. " reported offline")
  end
  return exposed
end
-- Comparing samples turns a snapshot into a timeline: a controller election, a
-- leader change or an unstable cluster is visible in the differences.
function analysis.stability(samples, cfg)
  local out = {
    requested = cfg.samples, answered = 0, controller_changes = {},
    cluster_id_changes = {}, topic_count_changes = {}, errors = {},
  }
  local previous = nil
  for _, sample in ipairs(samples or {}) do
    if not sample.answered then
      out.errors[#out.errors + 1] = tostring(sample.label) .. ": " .. tostring(sample.error)
    else
      out.answered = out.answered + 1
      if previous then
        if previous.controller_id ~= sample.controller_id then
          out.controller_changes[#out.controller_changes + 1] = string.format("%s -> %s",
            tostring(previous.controller_id), tostring(sample.controller_id))
        end
        if previous.cluster_id ~= sample.cluster_id then
          out.cluster_id_changes[#out.cluster_id_changes + 1] = string.format("%s -> %s",
            tostring(previous.cluster_id), tostring(sample.cluster_id))
        end
        if previous.topic_count ~= sample.topic_count then
          out.topic_count_changes[#out.topic_count_changes + 1] = string.format("%d -> %d",
            previous.topic_count, sample.topic_count)
        end
      end
      previous = sample
    end
  end
  out.stable = out.answered >= 2 and #out.controller_changes == 0
  return out
end

function analysis.leader_skew(topology)
  if topology.leaders < 4 then return nil end
  local top = topology.top_leader
  if not top.broker or top.count == 0 then return nil end
  local share = math.floor(top.count * 100 / topology.leaders + 0.5)
  return { broker = top.broker, count = top.count, share = share,
    brokers = #topology.brokers, leaders = topology.leaders }
end

function analysis.skew_verdict(skew)
  if not skew then return nil end
  if skew.brokers < 2 then
    return string.format("every partition is led by the only broker (%d leaders)", skew.leaders)
  end
  if skew.share >= 80 then
    return string.format("broker %s leads %d of %d partitions (%d%%), so a single broker carries the read path",
      tostring(skew.broker), skew.count, skew.leaders, skew.share)
  end
  return string.format("broker %s leads %d of %d partitions (%d%%), above an even split",
    tostring(skew.broker), skew.count, skew.leaders, skew.share)
end

----------------------------------------------------------------------------
-- 6. Findings
----------------------------------------------------------------------------
local findings = {}

local REMEDIATE_AUTH = "Require authentication on this listener ('sasl.enabled.mechanisms' plus "
  .. "'security.inter.broker.protocol') and restrict the cluster-level Describe permission with "
  .. "'authorizer.class.name' and the matching ACLs."
local REMEDIATE_NETWORK = "Keep the client listener on a private network and publish only the addresses "
  .. "clients need ('advertised.listeners'); the metadata response is a map of the broker fleet, so its "
  .. "reachability is a network design decision, not a broker setting."

function findings.evaluate(records, topology, exposed, stability, skew, cfg)
  local list = {}
  local metadata = records.samples and records.samples[1] or records.metadata

  if metadata and metadata.answered and metadata.access == "granted"
    and (metadata.topic_count or 0) > 0 then
    local evidence = {}
    for _, item in ipairs(exposed) do evidence[#evidence + 1] = item.kind .. ": " .. item.detail end
    list[#list + 1] = finding("KAFKA-CONTROLLER-IDENTITY-LEAK",
      "Controller and cluster identity disclosed without authentication",
      "LOW",
      string.format("An anonymous Metadata request answered with controller id %s, cluster id %s and %s. "
        .. "Naming the controller is the reconnaissance step of every attack on the metadata layer: the "
        .. "controller decides leadership, so it is the node whose compromise matters most.",
        tostring(topology.controller_id), tostring(topology.cluster_id),
        plural(#topology.brokers, "broker address")),
      evidence, { REMEDIATE_AUTH, REMEDIATE_NETWORK })

    list[#list + 1] = finding("KAFKA-TOPOLOGY-DISCLOSURE",
      "Full partition and replica map readable without authentication",
      "LOW",
      string.format("The same request returned %s across %s: leaders, replica assignments and in-sync sets. "
        .. "For someone planning theft of data or disruption of service, the replica assignment is the "
        .. "difference between guessing and knowing which broker holds which partition.",
        plural(topology.partitions, "partition"), plural(topology.topic_count, "topic")),
      { string.format("replica assignment: %s", plural(topology.replicas, "entry by broker")),
        string.format("in-sync: %s", plural(topology.isr_entries, "entry")) },
      { REMEDIATE_AUTH })
  end

  if #topology.under_replicated > 0 then
    local rows = {}
    for index = 1, math.min(#topology.under_replicated, 8) do
      local entry = topology.under_replicated[index]
      rows[#rows + 1] = string.format("%s/%s: %d of %d replicas in sync (leader %s)", entry.topic,
        tostring(entry.partition), entry.isr, entry.replicas, tostring(entry.leader))
    end
    list[#list + 1] = finding("KAFKA-UNDER-REPLICATED-PARTITIONS",
      "Under-replicated partitions are visible to an unauthenticated caller",
      "MEDIUM",
      string.format("%s are below their replication factor (%s across %s). This is reported here because the "
        .. "information itself is the exposure: an attacker reading Metadata learns exactly which partitions "
        .. "have no redundancy left, and availability problems that the operator would have to find in "
        .. "internal metrics are published on the wire.",
        plural(#topology.under_replicated, "partition"), plural(#topology.under_replicated, "partition"),
        plural(#records.samples or 1, "sample")),
      rows, { REMEDIATE_AUTH,
        "Re-replicate the affected partitions ('kafka-reassign-partitions.sh') and alert on "
        .. "UnderReplicatedPartitions in the broker metrics." })
  end

  if #topology.offline_replicas > 0 then
    local rows = {}
    for index = 1, math.min(#topology.offline_replicas, 6) do
      local entry = topology.offline_replicas[index]
      rows[#rows + 1] = string.format("%s/%s replica on broker %s is offline", entry.topic,
        tostring(entry.partition), tostring(entry.broker))
    end
    list[#list + 1] = finding("KAFKA-OFFLINE-REPLICAS-EXPOSED",
      "Offline replicas are enumerated in the metadata response",
      "LOW",
      string.format("%s were reported offline. A broker that has lost a replica publishes that fact to every "
        .. "anonymous caller, which is an availability inventory for anyone who wants to make the loss worse.",
        plural(#topology.offline_replicas, "replica")), rows, { REMEDIATE_AUTH })
  end

  local verdict = analysis.skew_verdict(skew)
  if verdict and skew and skew.share >= 60 then
    list[#list + 1] = finding("KAFKA-LEADER-CONCENTRATION",
      "Partition leadership is concentrated on one broker",
      "LOW", verdict .. ". Leadership balance is visible from outside, and it decides which broker a "
        .. "disruption would hurt most.",
      { string.format("leaders: %s", plural(skew.leaders, "partition")) },
      { "Prefer rack-aware replica assignment and let the controller balance leadership "
        .. "('auto.leader.rebalance.enable'), then verify with 'kafka-topics.sh --describe'." })
  end

  if #stability.controller_changes > 0 then
    list[#list + 1] = finding("KAFKA-CONTROLLER-ELECTION-OBSERVED",
      "The controller changed during the scan",
      "LOW",
      string.format("Across %s the controller moved (%s). Controller elections are the window in which "
        .. "metadata is inconsistent; a client that polls Metadata can observe the exact moment it happens, "
        .. "and so can an attacker.",
        plural(stability.answered, "sample"), fmt_list(stability.controller_changes, 4)),
      { string.format("samples answered: %d of %d", stability.answered, stability.requested) },
      { "Investigate controller stability: disk latency, GC pauses and network partitions on the "
        .. "controller change the election rate; alert on the ControllerElectionRateOnZk metric." })
  elseif stability.answered >= 2 and #stability.topic_count_changes > 0 then
    list[#list + 1] = finding("KAFKA-METADATA-CHURN-OBSERVED",
      "The topic inventory changed while the scan ran",
      "INFO",
      string.format("The topic count moved during sampling (%s). Metadata churn is normal on a busy cluster, "
        .. "and it is also why a snapshot of the cluster should carry its timestamp.",
        fmt_list(stability.topic_count_changes, 4)), {}, {})
  end

  if not (metadata and metadata.answered) then
    list[#list + 1] = finding("KAFKA-METADATA-NOT-AVAILABLE",
      "Metadata was not answered, so no exposure could be measured",
      "INFO",
      "The broker did not answer a Metadata request during the scan. That is what an ACL, a listener "
        .. "configuration or a network policy looks like from here, and it is also what a broken scan looks "
        .. "like; the transport section above says which one applies.",
      { (metadata or {}).error or "no Metadata answer" }, {})
  end

  return list
end

----------------------------------------------------------------------------
-- 7. Report
----------------------------------------------------------------------------
local report = {}

function report.build(cfg, host, port, records, topology, exposed, stability, skew, list, w)
  local out = stdnse.output_table()
  local target = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id: %s", cfg.client_id),
    string.format("Timeout: %dms, samples: %d every %dms", cfg.timeout, cfg.samples, cfg.sample_gap_ms),
  }
  local api_versions = records.api_versions or {}
  if api_versions.metadata_version then
    target[#target + 1] = string.format("Metadata negotiated at v%s", tostring(api_versions.metadata_version))
  end
  if w.failure then target[#target + 1] = "Transport failure: " .. tostring(w.failure) end
  out["Target"] = target

  local summary = {
    "Cluster id: " .. tostring(topology.cluster_id or "unknown"),
    string.format("Controller: %s (%s)", tostring(topology.controller_id or "unknown"),
      topology.controller_is_broker and "also a broker" or "not in the broker list"),
    string.format("Brokers: %s, racks: %s", tostring(#topology.brokers),
      fmt_list((function()
        local racks = {}
        for rack in pairs(topology.racks) do racks[#racks + 1] = rack end
        return racks
      end)(), 6, "none advertised")),
    string.format("Topics: %s (%s internal)", tostring(topology.topic_count), tostring(topology.internal_topics)),
    string.format("Partitions: %s, replica entries: %s, in-sync entries: %s", tostring(topology.partitions),
      tostring(topology.replicas), tostring(topology.isr_entries)),
  }
  local available, missing = analysis.features(api_versions.metadata_version)
  local function field_names(features)
    local fields = {}
    for _, feature in ipairs(features) do fields[#fields + 1] = feature.field end
    return fields
  end
  if #available > 0 then
    summary[#summary + 1] = "Metadata fields available: " .. fmt_list(field_names(available), 8)
  end
  if #missing > 0 then
    summary[#summary + 1] = "Fields this broker version omits: " .. fmt_list(field_names(missing), 8)
  end
  out["Cluster"] = summary

  local exposure = {}
  for _, item in ipairs(exposed) do
    exposure[#exposure + 1] = string.format("%s: %s", item.kind, item.detail)
  end
  out["Exposure"] = #exposure > 0 and exposure or { "No exposure was measured." }

  local cluster = records.describe_cluster or {}
  local cluster_lines = {}
  if cluster.answered then
    cluster_lines[#cluster_lines + 1] = string.format("DescribeCluster v%s: %s", tostring(cluster.version),
      tostring(cluster.error_name or "NONE"))
    cluster_lines[#cluster_lines + 1] = "Endpoint type: "
      .. tostring(cluster.endpoint_type or "not part of this version")
    cluster_lines[#cluster_lines + 1] = "Cluster authorized operations: "
      .. kafka.cluster_ops_text(cluster.cluster_authorized_operations)
    if cluster.error_code and cluster.error_code ~= 0 then
      cluster_lines[#cluster_lines + 1] = "The admin API was refused without a credential ("
        .. tostring(cluster.error_name) .. "): the metadata quorum is not enumerable from here."
    end
  else
    cluster_lines[#cluster_lines + 1] = "DescribeCluster was not answered: "
      .. tostring(cluster.error or "no answer")
  end
  out["Cluster API"] = cluster_lines

  local nodes = {}
  for _, broker in ipairs(topology.brokers) do
    local led = topology.leader_distribution[broker.broker_id] or 0
    nodes[#nodes + 1] = string.format("%s: %s:%s rack=%s leaders=%d%s", tostring(broker.broker_id),
      tostring(broker.host), tostring(broker.port), tostring(broker.rack or "none"), led,
      broker.broker_id == topology.controller_id and " [controller]" or "")
  end
  out["Brokers"] = #nodes > 0 and nodes or { "No broker inventory was returned." }

  local metadata = records.samples and records.samples[1] or records.metadata
  local topic_rows = {}
  for index, topic in ipairs((metadata and metadata.topics) or {}) do
    if index > cfg.max_topics then break end
    local parts = {}
    for _, partition in ipairs(topic.partitions or {}) do
      local state = (#(partition.isr or {}) < #(partition.replicas or {})) and "under-replicated" or "in sync"
      parts[#parts + 1] = string.format("%d:leader=%s,isr=%d/%d,%s%s", partition.index,
        tostring(partition.leader_id), #(partition.isr or {}), #(partition.replicas or {}), state,
        partition.leader_epoch and (",epoch=" .. tostring(partition.leader_epoch)) or "")
    end
    topic_rows[#topic_rows + 1] = string.format("%s%s: %s", topic.name, topic.is_internal and " [internal]" or "",
      fmt_list(parts, 6))
  end
  if (metadata and metadata.topic_count or 0) > cfg.max_topics then
    topic_rows[#topic_rows + 1] = string.format("(%d further topics not shown; raise kafka.max-topics)",
      metadata.topic_count - cfg.max_topics)
  end
  out["Topic map"] = #topic_rows > 0 and topic_rows or { "No topic map was produced." }

  local health = {
    string.format("Under-replicated partitions: %d", #topology.under_replicated),
    string.format("Offline replicas: %d", #topology.offline_replicas),
    string.format("Leader epochs read: %d", #topology.leader_epochs),
  }
  local verdict = analysis.skew_verdict(skew)
  if verdict then health[#health + 1] = "Leadership: " .. verdict end
  for replicas, count in pairs(topology.replica_counts) do
    if replicas > 0 then health[#health + 1] = string.format("Replication factor %d: %s", replicas, plural(count, "partition")) end
  end
  out["Replica health"] = health

  local samples = {}
  for index, sample in ipairs(records.samples or {}) do
    samples[#samples + 1] = sample.answered
      and string.format("sample %d: controller %s, %s, cluster id %s", index,
        tostring(sample.controller_id), plural(sample.topic_count, "topic"), tostring(sample.cluster_id))
      or string.format("sample %d: no answer (%s)", index, tostring(sample.error))
  end
  samples[#samples + 1] = string.format("Controller changes: %s; topic count changes: %s",
    fmt_list(stability.controller_changes, 4, "none"), fmt_list(stability.topic_count_changes, 4, "none"))
  out["Stability samples"] = samples

  out["Findings"] = report.finding_section(list)
  out["Remediation"] = {
    REMEDIATE_AUTH, REMEDIATE_NETWORK,
    "Alert on the exposures this script reports: UnderReplicatedPartitions, OfflineReplicas and "
      .. "ControllerElectionRate are broker metrics, and a leak that is visible on the wire is worth an "
      .. "alert even before it is worth a firewall change.",
  }
  out["Method limits"] = {
    "Metadata is versioned: a broker older than v7 cannot report leader epochs and one older than v5 cannot "
      .. "report offline replicas, so an absent field is a version limit, not a clean bill of health.",
    "Sampling observes the scan window only; a stable sample says nothing about the rest of the day.",
  }
  if not (records.samples and records.samples[1] and records.samples[1].answered) then
    out["Risk Level"] = "UNKNOWN"
  else
    out["Risk Level"] = worst(list, "NONE")
  end
  return out
end

function report.finding_section(list)
  if #list == 0 then
    return { "No findings: the cluster published no more than the protocol requires." }
  end
  local lines = {}
  for index, item in ipairs(list) do
    lines[#lines + 1] = string.format("%d. [%s] %s (%s)", index, item.severity, item.title, item.id)
    lines[#lines + 1] = "   " .. item.detail
    for _, evidence in ipairs(item.evidence) do lines[#lines + 1] = "   evidence: " .. evidence end
    for _, step in ipairs(item.remediation) do lines[#lines + 1] = "   fix: " .. step end
  end
  return lines
end

----------------------------------------------------------------------------
-- 8. Orchestration
----------------------------------------------------------------------------
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
      "The TCP connection failed, so no protocol exchange happened. A TLS-only listener answers a plaintext "
        .. "Kafka probe exactly like this.",
    }
    return out
  end

  local records = {}
  records.api_versions = probe.api_versions(w)
  records.metadata = probe.metadata(w, "single")
  records.describe_cluster = probe.describe_cluster(w)
  records.samples = probe.samples(w, cfg.samples, cfg.sample_gap_ms)
  w:close()

  local topology = analysis.topology(records, cfg)
  local exposed = analysis.exposure(records, topology, records.describe_cluster)
  local stability = analysis.stability(records.samples, cfg)
  local skew = analysis.leader_skew(topology)
  local list = findings.evaluate(records, topology, exposed, stability, skew, cfg)

  local result = report.build(cfg, host, port, records, topology, exposed, stability, skew, list, w)
  if cfg.verbose then
    local transcript = {}
    for _, stage in ipairs(w.stages) do
      transcript[#transcript + 1] = string.format("%s: %s", stage.name, tostring(stage.detail or ""))
    end
    result["Probe transcript"] = transcript
  end
  return result
end
