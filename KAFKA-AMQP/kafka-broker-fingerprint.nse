local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The Kafka wire engine (nselib/kafka.lua) owns framing, version negotiation
-- and every response parser. This script never touches a socket directly.
local ok, kafka = pcall(require, "kafka")

description = [[
Fingerprints a Kafka broker from its own wire protocol, without credentials.

A Kafka listener answers ApiVersions before it knows who is calling, so the set
of APIs and version ranges it advertises is a fingerprint in itself:

  * the oldest and the newest schema family the broker understands (classic
    versus the compact "flexible" encoding introduced in 2.4),
  * whether the admin APIs of the KRaft generation are present
    (DescribeCluster, endpoint types, the fenced-broker flag),
  * whether a metadata quorum or a ZooKeeper ensemble is behind it,
  * the cluster id, controller id, broker inventory (host, port, rack),
  * the consumer-group, transaction and Schema Registry topics that exist,
    which name the platform built on top of the broker,
  * the SASL mechanisms the listener announces and whether authentication is
    actually enforced for metadata requests,
  * the throttle time the broker reports, which betrays active quotas.

Everything is inferred from protocol answers, and every claim in the report
carries the observation that produced it. The result is a lower bound: a broker
can be newer than the oldest release consistent with what it advertises, never
older, and the report says so instead of guessing a version number.

No request in this script can change broker state. Configuration values are
reported by name only: the fingerprint does not need the secrets that the
access-audit script quotes as evidence.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-broker-fingerprint <target>
-- nmap -p 9092 --script kafka-broker-fingerprint --script-args kafka.timeout=3000,kafka.sasl-mechanism=SCRAM-SHA-256 <target>
--
-- @args kafka.timeout           Per-request timeout in milliseconds
--                               (default 5000, range 500-60000).
-- @args kafka.client-id         Client id sent in every request header
--                               (default "nmap-kafka-fingerprint").
-- @args kafka.max-topics        Maximum number of topics listed in the report
--                               (default 40, range 1-500).
-- @args kafka.sasl-mechanism    Mechanism named in the SaslHandshake probe
--                               (default "SCRAM-SHA-256").
-- @args kafka.config-probe      "false" disables the read-only DescribeConfigs
--                               probe (default enabled).
-- @args kafka.no-retry          "true" disables the retry of transient errors.
-- @args kafka.verbose           "true" adds the per-stage transcript.
--
-- @output
-- 9092/tcp open  kafka
-- | kafka-broker-fingerprint:
-- |   Broker: 1 at broker-1.internal (rack rack-a)
-- |   Cluster id: nse-open-cluster, controller broker: 1
-- |   Controller placement: combined (the controller is also a broker)
-- |   Schema generation: 2.4 or later (flexible/compact schemas)
-- |   Fingerprint markers:...
-- |_  Risk Level: LOW
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

local DEFAULT_CLIENT_ID = "nmap-kafka-fingerprint"

local function arg_string(name, default, max_length)
  local raw = nmap.registry.args and nmap.registry.args[name]
  if raw == nil then return default end
  raw = tostring(raw)
  if max_length and #raw > max_length then raw = string.sub(raw, 1, max_length) end
  return raw
end

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
    client_id = arg_string("kafka.client-id", DEFAULT_CLIENT_ID, 120),
    max_topics = arg_number("kafka.max-topics", 40, 1, 500),
    mechanism = string.upper(arg_string("kafka.sasl-mechanism", "SCRAM-SHA-256", 40)),
    config_probe = arg_bool("kafka.config-probe", true),
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
  if value == nil then return "unknown" end
  return value and "yes" or "no"
end

local function plural(count, singular, plural_form)
  count = tonumber(count) or 0
  if count == 1 then return "1 " .. singular end
  return string.format("%d %s", count, plural_form or (singular .. "s"))
end

local function fmt_list(values, limit, empty_text)
  if not values or #values == 0 then return empty_text or "none" end
  local shown = {}
  for index = 1, math.min(#values, limit) do shown[#shown + 1] = tostring(values[index]) end
  local text = table.concat(shown, ", ")
  if #values > limit then text = text .. string.format(" (+%d more)", #values - limit) end
  return text
end

local function pct(part, whole)
  part, whole = tonumber(part) or 0, tonumber(whole) or 0
  if whole <= 0 then return "n/a" end
  return string.format("%d%%", math.floor(part * 100 / whole + 0.5))
end

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

local function finding(id, title, severity, detail, evidence, remediation, verification)
  return {
    id = id, title = title, severity = severity, detail = detail,
    evidence = evidence or {}, remediation = remediation or {}, verification = verification or {},
  }
end

local function sorted_keys(map)
  local keys = {}
  for key in pairs(map or {}) do keys[#keys + 1] = key end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  return keys
end

----------------------------------------------------------------------------
-- 3. Wire layer
----------------------------------------------------------------------------
--
-- A thin wrapper around the engine's connection: it negotiates once, keeps the
-- stage log that the report prints, and turns an enginerecord into the shape the
-- probes below expect (answered / access / error) without interpreting the
-- payload. Interpretation is the analysis layer's job.

local function new_wire(host, port, cfg)
  local w = {
    host = host, port = port, cfg = cfg,
    connection = nil, connected = false, failure = nil,
    stages = {}, version_map = {}, unsupported = {},
    negotiate_summary = nil,
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
    -- The engine builds a connection that is already open; a missing socket
    -- plus last_error is the only failure it reports.
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
    if self.version_map and next(self.version_map) then return self.version_map end
    local summary, err = kafka.negotiate(self.connection)
    if not summary then
      self:stage("api_versions", "failed: " .. tostring(err))
      self.failure = self.failure or err
      return nil, err
    end
    self.negotiate_summary = summary
    self.version_map = summary.versions or {}
    self.unsupported = summary.unsupported or {}
    self:stage("api_versions", string.format("broker offers %s (error %s)",
      plural(summary.count or 0, "API"), tostring(summary.error_name)))
    return self.version_map, nil
  end

  -- One request, one response, with the retry policy applied only to errors the
  -- protocol itself marks as transient.
  function w:call(label, fn)
    local attempts = 1
    if self.cfg.retry then attempts = 2 end
    local last = nil
    for attempt = 1, attempts do
      local result = fn(attempt)
      if result and result.ok then return result end
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
-- Each probe returns the same envelope: answered, the API version that was
-- used, the access verdict and the raw fields the analysis needs. Nothing is
-- classified here, so a probe can be re-read by a later section without having
-- to repeat the request.

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
    throttle_ms = summary.throttle_ms, api_count = summary.count,
    keys = summary.keys, versions = versions,
    version_rows = kafka.version_table(w.connection),
    soft_version = summary.soft_version,
  }
end

function probe.metadata(w, topics)
  local result = w:call("metadata", function()
    return kafka.metadata(w.connection, topics)
  end)
  if not result or not result.ok then
    return { stage = "metadata", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local cfg = w.cfg
  local out = {
    stage = "metadata", answered = true, version = result.version, flexible = result.flexible,
    cluster_id = result.cluster_id, controller_id = result.controller_id,
    brokers = result.brokers or {}, topics = {}, internal = {},
    throttle_ms = result.throttle_ms, errors = {}, trailing_bytes = result.trailing_bytes,
  }
  local rows = 0
  for _, topic in ipairs(result.topics or {}) do
    if topic.error_code == 0 then
      rows = rows + 1
      if #out.topics < cfg.max_topics then
        out.topics[#out.topics + 1] = topic
      end
      if topic.is_internal then out.internal[#out.internal + 1] = topic end
    else
      out.errors[#out.errors + 1] = topic
    end
  end
  out.topic_count = rows
  out.truncated = rows > #out.topics
  local leader_epochs, offline = 0, 0
  for _, topic in ipairs(out.topics) do
    for _, partition in ipairs(topic.partitions or {}) do
      if partition.leader_epoch and partition.leader_epoch > 0 then leader_epochs = leader_epochs + 1 end
      offline = offline + #(partition.offline_replicas or {})
    end
  end
  out.partitions_with_leader_epoch = leader_epochs
  out.offline_replicas = offline
  out.access = out.topic_count > 0 and "granted" or (out.errors[1] and "error" or "empty")
  out.error_code = out.errors[1] and out.errors[1].error_code or 0
  out.error_name = out.errors[1] and out.errors[1].error_name or "NONE"
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
    error_message = result.error_message, endpoint_type = result.endpoint_type,
    cluster_id = result.cluster_id, controller_id = result.controller_id,
    brokers = result.brokers or {}, cluster_authorized_operations = result.cluster_authorized_operations,
    throttle_ms = result.throttle_ms, trailing_bytes = result.trailing_bytes,
    access = (result.error_code == 0) and "granted" or "error",
  }
end

-- SaslHandshake is answered before authentication, which makes it the only
-- honest way to ask a listener "do you speak SASL, and which mechanisms do you
-- offer?" without a credential. The second call names a mechanism that no
-- broker implements, to separate "SASL is not configured" from "this mechanism
-- is not the right one".
function probe.sasl(w)
  local mechanism = w.cfg.mechanism
  local result = w:call("sasl_handshake", function()
    return kafka.sasl_handshake(w.connection, mechanism)
  end)
  local out = { stage = "sasl_handshake", mechanism = mechanism }
  if not result or not result.ok then
    out.answered = false
    out.error = result and result.error or "no response"
    out.version = result and result.version
    return out
  end
  out.answered = true
  out.version = result.version
  out.error_code = result.error_code
  out.error_name = result.error_name
  out.mechanisms = result.mechanisms or {}
  out.access = (result.error_code == 0) and "granted" or "error"
  local impossible = w:call("sasl_handshake", function()
    return kafka.sasl_handshake(w.connection, "NMAP-NOT-A-MECHANISM")
  end)
  if impossible and impossible.ok then
    out.unknown_mechanism_error = impossible.error_code
    out.unknown_mechanism_name = impossible.error_name
  end
  return out
end

-- Configuration is read for its shape, not for its values: the report prints
-- names, whether a value is sensitive and whether it is read-only. A LOW-risk
-- fingerprint has no business quoting a keystore password into a log.
function probe.configs(w, resources)
  local result = w:call("describe_configs", function()
    return kafka.describe_configs(w.connection, resources, { include_synonyms = false })
  end)
  if not result or not result.ok then
    return { stage = "describe_configs", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = {
    stage = "describe_configs", answered = true, version = result.version,
    throttle_ms = result.throttle_ms, results = {}, config_count = 0, sensitive = {},
    names = {}, trailing_bytes = result.trailing_bytes,
  }
  for _, entry in ipairs(result.results or {}) do
    local row = {
      error_code = entry.error_code, error_name = entry.error_name,
      resource_type = entry.resource_type, resource_name = entry.resource_name,
      configs = {},
    }
    for _, config in ipairs(entry.configs or {}) do
      out.config_count = out.config_count + 1
      out.names[#out.names + 1] = config.name
      if config.is_sensitive then out.sensitive[#out.sensitive + 1] = config.name end
      row.configs[#row.configs + 1] = {
        name = config.name, read_only = config.read_only,
        is_sensitive = config.is_sensitive, source = config.source,
        value_present = config.value ~= nil,
      }
    end
    out.results[#out.results + 1] = row
  end
  local granted, denied = 0, 0
  for _, entry in ipairs(out.results) do
    if entry.error_code == 0 then granted = granted + 1 else denied = denied + 1 end
  end
  out.granted_resources, out.denied_resources = granted, denied
  out.access = granted > 0 and "granted" or (denied > 0 and "denied" or "unknown")
  return out
end


----------------------------------------------------------------------------
-- 5. Knowledge base and analysis
----------------------------------------------------------------------------
--
-- The inference tables (schema generations, the API-version markers that date
-- them, the internal-topic names that identify the platform, the cluster
-- operation bitmask) and the pure analysis functions that apply them live in
-- nselib/kafka.lua section 18, next to the message definitions they are derived
-- from. Keeping them there means the next Kafka audit script cannot disagree
-- with this one about what "2.4 or later" means.

----------------------------------------------------------------------------
-- 7. Findings
----------------------------------------------------------------------------

local findings = {}

local REMEDIATION = {
  "Serve the broker inventory only to authenticated clients: set the listener's 'sasl.enabled.mechanisms' and 'security.inter.broker.protocol' so that ApiVersions, Metadata and DescribeCluster are answered after authentication.",
  "Keep the admin listener on a private network: 'listener.security.protocol.map', 'advertised.listeners' and the cluster's 'authorizer.class.name' decide what a reachable port can reveal.",
  "If the fingerprint itself is the problem, restrict the listener with a firewall or a network policy instead of relying on the broker to hide its own API catalogue; ApiVersions is answered before any credential is checked.",
}

function findings.evaluate(records, generation, platform, topology, posture, quotas, config_summary)
  local list = {}

  if records.negotiate and records.negotiate.answered then
    local detail = string.format(
      "The listener answered ApiVersions before any credential was supplied and advertised %s across %s. "
        .. "The protocol catalogue is a build fingerprint: %s.",
      plural(records.negotiate.api_count or 0, "API"), plural(#(topology.brokers or {}), "broker"),
      generation.generation_label or "unknown generation")
    local evidence = {}
    for _, line in ipairs(generation.evidence or {}) do evidence[#evidence + 1] = line end
    if records.metadata and records.metadata.answered then
      evidence[#evidence + 1] = string.format("Metadata v%s answered with %s",
        tostring(records.metadata.version), plural(records.metadata.topic_count or 0, "topic"))
    end
    list[#list + 1] = finding("KAFKA-UNAUTHENTICATED-FINGERPRINT",
      "Broker fingerprint collected without authentication",
      records.metadata and records.metadata.access == "granted" and "LOW" or "INFO",
      detail, evidence, { REMEDIATION[1], REMEDIATION[3] })
  end

  if #platform.markers > 0 then
    local components = {}
    for _, marker in ipairs(platform.markers) do
      components[#components + 1] = string.format("%s (%s)", marker.component, marker.topic)
    end
    list[#list + 1] = finding("KAFKA-PLATFORM-INVENTORY-EXPOSED",
      "Internal topics name the platform built on this cluster",
      "INFO",
      string.format("The topic inventory lists %s; their names identify %s. An unauthenticated reader learns "
        .. "which components of the data platform exist and where their state lives, which is prefacing work "
        .. "for anyone planning an attack on the pipeline rather than the broker.",
        plural(topology.internal_topics, "internal topic"), fmt_list(components, 6)),
      components, { REMEDIATION[2] })
  end

  if posture.sasl_offered and not posture.sasl_required then
    list[#list + 1] = finding("KAFKA-SASL-OFFERED-NOT-ENFORCED",
      "The listener announces SASL but answers anonymous requests",
      "MEDIUM",
      string.format("SaslHandshake advertised %s, yet Metadata was answered without a credential. Clients choose "
        .. "whether to authenticate, so an attacker simply does not; every guarantee that depends on the "
        .. "principal's identity (ACLs, quotas, audit attribution) is absent on this path.",
        fmt_list(posture.mechanisms, 6)),
      posture.notes, { REMEDIATION[1], REMEDIATION[2] })
  end

  if records.describe_cluster and records.describe_cluster.answered
    and (records.describe_cluster.version or 0) >= 1 then
    list[#list + 1] = finding("KAFKA-KRAFT-CONTROLLER-ENDPOINTS",
      "Controller endpoints are advertised on the client listener",
      "INFO",
      string.format("DescribeCluster v%s answers with endpoint type %s and controller %s. On a KRaft cluster the "
        .. "client-facing listener therefore publishes the addresses of the controller quorum, which is where a "
        .. "compromise of the metadata layer would be aimed.",
        tostring(records.describe_cluster.version), tostring(records.describe_cluster.endpoint_type),
        tostring(topology.controller_id)),
      { string.format("endpoint type: %s", tostring(records.describe_cluster.endpoint_type)) },
      { REMEDIATION[2] })
  end

  if not (records.describe_cluster and records.describe_cluster.answered) then
    list[#list + 1] = finding("KAFKA-CONTROLLER-MODE-UNKNOWN",
      "The controller mode could not be confirmed from the wire",
      "INFO",
      "DescribeCluster was not answered, so the broker does not expose the KRaft-aware admin API on this "
        .. "listener. That is the normal answer of a ZooKeeper-based deployment and of any release older than "
        .. "the admin API, and it is also what an ACL that refuses the call looks like. The report does not "
        .. "choose between those three explanations from one observation.",
      { (records.describe_cluster or {}).error or "no DescribeCluster answer" },
      { "If the deployment is migrating to KRaft, plan the migration with the broker inventory this script "
        .. "already produced: controller placement decides the migration order." })
  end

  if config_summary.resources_granted and config_summary.resources_granted > 0 then
    list[#list + 1] = finding("KAFKA-CONFIGURATION-SHAPE-EXPOSED",
      "Broker configuration is readable without authentication",
      "LOW",
      string.format("DescribeConfigs answered %s for %s with %s, of which %s were marked sensitive. The values "
        .. "are withheld in this report on purpose, but the shape alone tells an attacker how the cluster is "
        .. "configured and which knobs a later call could try to turn.",
        plural(config_summary.names, "setting"), plural(config_summary.resources_granted, "resource"),
        plural(config_summary.names, "setting"), tostring(config_summary.sensitive)),
      config_summary.lines, { REMEDIATION[1] })
  end

  if #quotas > 0 then
    list[#list + 1] = finding("KAFKA-QUOTA-ENFORCEMENT-OBSERVED",
      "The broker enforced a request quota during the scan",
      "INFO",
      "Throttle times were reported on responses to a scanner that sent a handful of requests. Quotas are "
        .. "enforced per principal; seeing them on an anonymous connection means the default quota applies to "
        .. "unauthenticated clients.",
      quotas, { "Set a per-user quota with 'kafka-configs --alter --add-config' and keep an explicit default "
        .. "user quota ('--entity-type users --entity-name default') so unauthenticated bursts cannot crowd out "
        .. "real clients." })
  end

  return list
end

----------------------------------------------------------------------------
-- 8. Report
----------------------------------------------------------------------------

local report = {}

function report.target_section(cfg, host, port, w)
  local lines = {
    string.format("Endpoint: %s:%d/%s", host.ip or "target", port.number, port.protocol or "tcp"),
    string.format("Client id: %s", cfg.client_id),
    string.format("Timeout: %dms, retry on transient errors: %s", cfg.timeout, fmt_bool(cfg.retry)),
    string.format("SaslHandshake probe mechanism: %s", cfg.mechanism),
  }
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

function report.build(cfg, host, port, records, generation, platform, topology, posture, quotas, config_summary, list, w)
  local out = stdnse.output_table()
  out["Target"] = report.target_section(cfg, host, port, w)

  local fingerprint = {}
  fingerprint[#fingerprint + 1] = "Generation: " .. (generation.generation_label or "unknown")
  if generation.reason then fingerprint[#fingerprint + 1] = "Why: " .. generation.reason end
  for _, marker in ipairs(generation.markers or {}) do
    fingerprint[#fingerprint + 1] = string.format("Marker: %s v%s (%s)", marker.api_name,
      tostring(marker.version), marker.evidence)
  end
  fingerprint[#fingerprint + 1] = "Cluster id: " .. tostring(topology.cluster_id or "unknown")
  fingerprint[#fingerprint + 1] = string.format("Controller: %s, placement: %s", tostring(topology.controller_id),
    topology.controller_is_broker and "combined (the controller is also a broker)"
      or "separate (the controller is not in the broker list)")
  fingerprint[#fingerprint + 1] = string.format("Node inventory: %s, %s with a rack",
    plural(#topology.brokers, "broker"), tostring(topology.brokers_with_rack))
  fingerprint[#fingerprint + 1] = string.format("Topics: %s (%s internal), %s, %s with a leader epoch",
    tostring(records.metadata and records.metadata.topic_count or 0), tostring(topology.internal_topics),
    plural(topology.partitions, "partition"), tostring(topology.leader_epochs))
  if topology.offline_replicas > 0 then
    fingerprint[#fingerprint + 1] = string.format("Under-replicated: %s offline",
      plural(topology.offline_replicas, "replica"))
  end
  out["Fingerprint"] = fingerprint

  local nodes = {}
  for _, broker in ipairs(topology.brokers) do
    nodes[#nodes + 1] = string.format("%s: %s:%s (rack %s)%s", tostring(broker.broker_id),
      tostring(broker.host), tostring(broker.port), tostring(broker.rack or "none"),
      broker.broker_id == topology.controller_id and " [controller]" or "")
  end
  out["Nodes"] = #nodes > 0 and nodes or { "No broker inventory was returned." }

  if records.describe_cluster and records.describe_cluster.answered then
    out["Cluster API"] = {
      "DescribeCluster v" .. tostring(records.describe_cluster.version)
        .. ", cluster authorized operations: " .. kafka.cluster_ops_text(records.describe_cluster.cluster_authorized_operations),
      "Endpoint type: " .. tostring(records.describe_cluster.endpoint_type or "not part of this version"),
    }
  else
    out["Cluster API"] = { "DescribeCluster was not answered: "
      .. tostring((records.describe_cluster or {}).error or "no answer") }
  end

  if #platform.markers > 0 then
    local components = {}
    for _, marker in ipairs(platform.markers) do
      components[#components + 1] = string.format("%s -> %s (%s)", marker.topic, marker.component, marker.note)
    end
    out["Platform markers"] = components
  end

  local sasl_lines = {
    "SASL offered: " .. fmt_bool(posture.sasl_offered),
    "SASL enforced for metadata: " .. fmt_bool(posture.sasl_required),
    "Mechanisms: " .. fmt_list(posture.mechanisms, 8, "none advertised"),
  }
  for _, note in ipairs(posture.notes) do sasl_lines[#sasl_lines + 1] = note end
  out["Listener posture"] = sasl_lines

  out["Configuration (names only)"] = (#config_summary.lines > 0) and config_summary.lines
    or { config_summary.skipped or "DescribeConfigs returned no resource." }
  if #quotas > 0 then out["Quotas"] = quotas end
  out["Findings"] = report.finding_section(list)
  out["Remediation"] = REMEDIATION
  out["Method limits"] = report.limits_section(records)
  -- A listener that answered nothing at all has no risk level: reporting NONE
  -- would state that it is clean, which is exactly what was not established.
  -- The fingerprint is the deliverable. When even ApiVersions was not answered,
  -- nothing about this listener was established, so the risk level is UNKNOWN
  -- rather than the "NONE" of a clean report.
  if not (records.negotiate and records.negotiate.answered) then
    out["Risk Level"] = "UNKNOWN"
  else
    out["Risk Level"] = worst(list, "NONE")
  end
  return out
end

function report.finding_section(list)
  if #list == 0 then
    return { "No findings: the listener answered too little to fingerprint it, or it is configured exactly as it should be." }
  end
  local lines = {}
  for index, item in ipairs(list) do
    lines[#lines + 1] = string.format("%d. [%s] %s (%s)", index, item.severity, item.title, item.id)
    lines[#lines + 1] = "   " .. item.detail
    for _, evidence in ipairs(item.evidence) do lines[#lines + 1] = "   evidence: " .. evidence end
  end
  return lines
end

function report.limits_section(records)
  local lines = {
    "The generation reported here is a lower bound derived from the advertised API versions: a broker can be newer than the markers it advertises, never older.",
    "ApiVersions is answered before authentication on every Kafka listener; a fingerprint collected this way cannot be prevented by ACLs alone, only by removing the listener from reach.",
    "Internal topics are reported from the metadata response; a broker that refuses Metadata to anonymous callers will produce no platform markers, which is not evidence that none exist.",
  }
  if records.metadata and records.metadata.truncated then
    lines[#lines + 1] = "The topic list was truncated at kafka.max-topics; the platform markers are based on the topics that fit."
  end
  return lines
end

----------------------------------------------------------------------------
-- 9. Orchestration
----------------------------------------------------------------------------

action = function(host, port)
  local cfg = read_config()
  local w = new_wire(host, port, cfg)
  local connected, connect_error = w:connect()
  local out = stdnse.output_table()

  if not connected then
    out["Risk Level"] = "UNKNOWN"
    out["Target"] = report.target_section(cfg, host, port, w)
    out["Error"] = connect_error
    out["Method limits"] = {
      "The TCP connection failed, so no protocol exchange took place. A TLS-only listener answers a plaintext "
        .. "Kafka probe exactly like this.",
      "Confirm the listener's security.protocol and re-run against the matching port.",
    }
    return out
  end

  local records = {}
  records.negotiate = probe.negotiate(w)
  records.metadata = probe.metadata(w, nil)
  records.describe_cluster = probe.describe_cluster(w)
  records.sasl = probe.sasl(w)
  if cfg.config_probe then
    local resources = { { type = 4, name = tostring((records.metadata.brokers or {})[1]
      and (records.metadata.brokers or {})[1].broker_id or 1) } }
    for _, topic in ipairs(records.metadata.topics or {}) do
      if #resources >= 3 then break end
      resources[#resources + 1] = { type = 2, name = topic.name }
    end
    records.configs = probe.configs(w, resources)
  end
  w:close()

  local generation = kafka.fingerprint_generation(records)
  local platform = kafka.fingerprint_platform(records)
  local topology = kafka.fingerprint_topology(records)
  local posture = kafka.fingerprint_listener_posture(records)
  local quotas = kafka.fingerprint_quotas(records)
  local config_summary = kafka.fingerprint_config_summary(records)
  local list = findings.evaluate(records, generation, platform, topology, posture, quotas, config_summary)

  local result = report.build(cfg, host, port, records, generation, platform, topology, posture, quotas,
    config_summary, list, w)
  if cfg.verbose then
    local transcript = {}
    for _, stage in ipairs(w.stages) do
      transcript[#transcript + 1] = string.format("%s: %s", stage.name, tostring(stage.detail or ""))
    end
    result["Probe transcript"] = transcript
  end
  return result
end
