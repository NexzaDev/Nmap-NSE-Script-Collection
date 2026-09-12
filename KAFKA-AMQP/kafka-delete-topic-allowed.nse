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
Determines whether a Kafka cluster lets an unauthenticated caller delete
topics, and whether it lets that caller discard records from topics that
already exist - without deleting a topic or a single record.

DeleteTopics has no dry-run mode, so the script never names a topic that
exists. It measures the permission on two paths that cannot do damage:

  * DeleteTopics is sent for names that were generated for this run and then
    verified absent with Metadata (with allow_auto_topic_creation forced to
    false). Kafka authorizes the DELETE operation on the topic resource before
    it looks the name up, so UNKNOWN_TOPIC_OR_PARTITION is not a refusal: it is
    proof that the ACL let the request through, while TOPIC_AUTHORIZATION_FAILED
    is proof that it did not.
  * A second DeleteTopics request uses the version 6 topic-id form with an id
    that cannot match anything, which exercises the path a controller takes when
    it deletes a topic it has just heard about.
  * DeleteRecords is the API that reveals the DELETE operation on an existing
    topic, and it is safe here because every request asks for offset 0: records
    below offset 0 do not exist, so the call is a no-op that the broker still
    authorizes. A broker that answers NONE would have let the caller discard the
    whole log had it asked for a higher offset.

The cluster's topic list is read before and after the probes and compared, so
the report can state - and the operator can verify - that nothing was removed.
]]

---
-- @usage
-- nmap -p 9092 --script kafka-delete-topic-allowed <target>
-- nmap -p 9092 --script kafka-delete-topic-allowed --script-args kafka.records-topics=2,kafka.verbose=true <target>
--
-- @args kafka.timeout         Per-request timeout in milliseconds
--                            (default 5000, range 500-60000).
-- @args kafka.client-id       Client id used in every request header
--                            (default "nmap-kafka-delete-audit").
-- @args kafka.names           Number of generated topic names to offer to
--                            DeleteTopics (default 3, range 1-20).
-- @args kafka.topic-id-probe  "true" (default) adds the version 6 topic-id form.
-- @args kafka.records-probe   "true" (default) measures DeleteRecords on the
--                            topics that exist.
-- @args kafka.records-topics  Maximum number of existing topics to include in
--                            the DeleteRecords probe (default 5, range 0-50).
-- @args kafka.max-topics      Maximum topics carried into the report
--                            (default 100, range 1-2000).
-- @args kafka.verbose         "true" adds the per-stage transcript.
--
-- @output
-- 9092/tcp open  kafka
-- | kafka-delete-topic-allowed:
-- |   DeleteTopics v6 advertised; DeleteRecords v2 advertised
-- |   nmap-delete-audit-...-4821: absent before the probe and absent after it
-- |   name path: UNKNOWN_TOPIC_OR_PARTITION -> the ACL let the request through
-- |   DeleteRecords at offset 0 on orders/0: NONE (low watermark 0)
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

local function read_config()
  local cfg = {
    timeout = arg_number("kafka.timeout", 5000, 500, 60000),
    client_id = arg_string("kafka.client-id", "nmap-kafka-delete-audit", 120),
    names = arg_number("kafka.names", 3, 1, 20),
    topic_id_probe = arg_bool("kafka.topic-id-probe", true),
    records_probe = arg_bool("kafka.records-probe", true),
    records_topics = arg_number("kafka.records-topics", 5, 0, 50),
    max_topics = arg_number("kafka.max-topics", 100, 1, 2000),
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

-- The names this run offers to DeleteTopics. They are generated, never chosen:
-- a name an operator could have created is a name this script must not use.
local function generated_names(prefix, count)
  local names = {}
  local seed = os.time() % 1000000
  for index = 1, count do
    names[#names + 1] = string.format("%s-%d-%d-%d", prefix, seed, math.random(100000, 999999), index)
  end
  return names
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
-- 4. What a delete answer means
----------------------------------------------------------------------------
--
-- Kafka authorizes the DELETE operation on the topic resource before it looks
-- the name up, so the interesting answers are not only the ones that say
-- "deleted": an existence error from an unauthenticated caller is proof that
-- the authorization check passed.

local OUTCOMES = {
  [0] = { verdict = "accepted", severity = "HIGH",
    meaning = "the broker accepted the deletion; for a name that exists this is the last answer before the log is removed" },
  [3] = { verdict = "authorized-name-absent", severity = "HIGH",
    meaning = "the name was looked up, which happens only after authorization: the caller was allowed to delete it" },
  [17] = { verdict = "authorized-name-invalid", severity = "MEDIUM",
    meaning = "the name was rejected, and the authorization check ran before the name was parsed" },
  [29] = { verdict = "denied", severity = "NONE",
    meaning = "the topic ACL refused the caller: deletion is enforced on the topic resource" },
  [31] = { verdict = "denied", severity = "NONE",
    meaning = "the cluster ACL refused the caller: deletion is enforced on the cluster resource" },
  [35] = { verdict = "unsupported-version", severity = "INFO",
    meaning = "the broker does not implement the requested DeleteTopics version" },
  [41] = { verdict = "not-controller", severity = "INFO",
    meaning = "a broker that does not control deletion answered; the controller may answer differently" },
  [42] = { verdict = "invalid-request", severity = "LOW",
    meaning = "the request itself was refused, which is a policy answer rather than an ACL one" },
  [100] = { verdict = "authorized-id-absent", severity = "HIGH",
    meaning = "the topic id was looked up, which happens after authorization: the caller may use the id form" },
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

local function is_permitted_verdict(verdict)
  if verdict == nil then return false end
  return verdict == "accepted" or string.sub(verdict, 1, 11) == "authorized-"
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
  local delete_topics = versions[20]
  local delete_records = versions[21]
  out.delete_topics_version = delete_topics and delete_topics.broker_max or nil
  out.delete_records_version = delete_records and delete_records.broker_max or nil
  out.delete_topics_offered = delete_topics ~= nil
  out.delete_records_offered = delete_records ~= nil
  out.topic_id_form = out.delete_topics_version ~= nil and out.delete_topics_version >= 6
  out.metadata_version = (versions[3] or {}).broker_max
  return out
end

-- The topic list, twice: once to choose what to probe and once to prove that
-- nothing changed. Existence is always asked with allow_auto_topic_creation
-- forced to false.
function probe.topic_list(w, label)
  local result = w:call(label or "metadata_list", function()
    return kafka.metadata(w.connection, nil, { auto_create = false })
  end)
  if not result or not result.ok then
    return { stage = label or "metadata_list", answered = false, topics = {}, names = {},
      error = result and result.error or "no response", version = result and result.version }
  end
  local out = { stage = label or "metadata_list", answered = true, version = result.version,
    topics = result.topics or {}, names = {}, order = {}, errors = {},
    brokers = result.brokers or {}, controller_id = result.controller_id, cluster_id = result.cluster_id }
  for _, topic in ipairs(out.topics) do
    out.names[topic.name] = true
    out.order[#out.order + 1] = topic.name
    if topic.error_code and topic.error_code ~= 0 then
      out.errors[#out.errors + 1] = string.format("%s (%s)", tostring(topic.name), tostring(topic.error_name))
    end
  end
  out.count = #out.order
  table.sort(out.order)
  out.access = (out.count > 0) and "granted" or "empty"
  return out
end

function probe.name_absent(w, name)
  local result = w:call("metadata_name_check", function()
    return kafka.metadata(w.connection, { name }, {
      auto_create = false, cluster_authorized_operations = false,
      topic_authorized_operations = false,
    })
  end)
  if not result or not result.ok then
    return { answered = false, name = name, error = result and result.error or "no response", exists = nil }
  end
  local entry = (result.topics or {})[1]
  return {
    answered = true, name = name, version = result.version,
    error_code = entry and entry.error_code, error_name = entry and entry.error_name,
    exists = entry ~= nil and entry.error_code == 0,
  }
end

-- The name path: one request carrying the generated names, none of which exists.
function probe.delete_by_name(w, names)
  local result = w:call("delete_by_name", function()
    return kafka.delete_topics(w.connection, names, { timeout_ms = math.min(w.cfg.timeout, 10000) })
  end)
  if not result or not result.ok then
    return { stage = "delete_by_name", answered = false, names = names,
      error = result and result.error or "no response", version = result and result.version, rows = {} }
  end
  local out = { stage = "delete_by_name", answered = true, version = result.version,
    names = names, rows = {}, throttle_ms = result.throttle_ms }
  for _, topic in ipairs(result.topics or {}) do
    local outcome = outcome_for(topic.error_code, topic.error_name)
    out.rows[#out.rows + 1] = {
      name = topic.name, error_code = topic.error_code, error_name = topic.error_name,
      error_message = topic.error_message, verdict = outcome.verdict, severity = outcome.severity,
      meaning = outcome.meaning,
    }
  end
  return out
end

-- The topic-id path, which is what a controller uses when it deletes a topic it
-- learned about: the id is all zeros here, so it cannot match any topic.
-- A topic id the cluster cannot know: sixteen random bytes, which the protocol
-- treats as a lookup by id rather than by name (an all-zero id means "use the
-- name"). Every byte is drawn separately per run, so the id cannot collide with
-- one the controller handed out.
local function random_topic_id()
  local bytes = {}
  for _ = 1, 16 do bytes[#bytes + 1] = string.char(math.random(0, 255)) end
  return table.concat(bytes)
end

function probe.delete_by_id(w, name, topic_id)
  local result = w:call("delete_by_id", function()
    return kafka.delete_topics(w.connection, { name },
      { timeout_ms = math.min(w.cfg.timeout, 10000), topic_id = topic_id })
  end)
  if not result or not result.ok then
    return { stage = "delete_by_id", answered = false,
      error = result and result.error or "no response", version = result and result.version }
  end
  local topic = (result.topics or {})[1] or {}
  local outcome = outcome_for(topic.error_code, topic.error_name)
  return {
    stage = "delete_by_id", answered = true, version = result.version,
    requested_id = hex_bytes(topic_id), error_code = topic.error_code, error_name = topic.error_name,
    error_message = topic.error_message, verdict = outcome.verdict, severity = outcome.severity,
    meaning = outcome.meaning, throttle_ms = result.throttle_ms,
  }
end

-- DeleteRecords at offset 0 deletes nothing (records below offset 0 do not
-- exist) while still passing through the authorization check the API runs.
function probe.delete_records(w, entries)
  if not entries or #entries == 0 then
    return { stage = "delete_records", answered = true, skipped = "no topic was selected", rows = {} }
  end
  local result = w:call("delete_records", function()
    return kafka.delete_records(w.connection, entries, { timeout_ms = math.min(w.cfg.timeout, 10000) })
  end)
  if not result or not result.ok then
    return { stage = "delete_records", answered = false,
      error = result and result.error or "no response", version = result and result.version, rows = {} }
  end
  local out = { stage = "delete_records", answered = true, version = result.version,
    rows = {}, throttle_ms = result.throttle_ms, requested_offset = 0,
    partitions_granted = result.partitions_granted, partitions_denied = result.partitions_denied,
    partitions_errored = result.partitions_errored, access = result.access }
  for _, topic in ipairs(result.topics or {}) do
    for _, partition in ipairs(topic.partitions or {}) do
      local outcome = outcome_for(partition.error_code, partition.error_name)
      out.rows[#out.rows + 1] = {
        topic = topic.name, partition = partition.partition, offset = 0,
        error_code = partition.error_code, error_name = partition.error_name,
        low_watermark = partition.low_watermark, verdict = outcome.verdict,
        severity = outcome.severity, meaning = outcome.meaning,
      }
    end
  end
  return out
end

----------------------------------------------------------------------------
-- 6. Analysis
----------------------------------------------------------------------------

local analysis = {}

function analysis.name_path(records)
  local delete = records.delete_by_name or {}
  local out = { rows = delete.rows or {}, attempted = #(delete.names or {}),
    permitted = 0, denied = 0, other = 0, verdicts = {}, answered = delete.answered }
  for _, row in ipairs(out.rows) do
    out.verdicts[row.verdict] = (out.verdicts[row.verdict] or 0) + 1
    if is_permitted_verdict(row.verdict) then out.permitted = out.permitted + 1
    elseif row.verdict == "denied" then out.denied = out.denied + 1
    else out.other = out.other + 1 end
  end
  return out
end

function analysis.id_path(records, cfg)
  local record = records.delete_by_id
  if not cfg.topic_id_probe then
    return { skipped = "kafka.topic-id-probe=false" }
  end
  if not record then
    return { skipped = "the broker does not advertise the topic-id form" }
  end
  return record
end

function analysis.records_path(records, cfg)
  local delete = records.delete_records or {}
  local out = { rows = delete.rows or {}, answered = delete.answered, skipped = delete.skipped,
    error = delete.error,
    version = delete.version, permitted = 0, denied = 0, errored = 0, verdicts = {},
    requested_offset = 0, topics = {}, low_watermarks = {} }
  for _, row in ipairs(out.rows) do
    out.verdicts[row.verdict] = (out.verdicts[row.verdict] or 0) + 1
    if row.verdict == "accepted" then out.permitted = out.permitted + 1
    elseif row.verdict == "denied" then out.denied = out.denied + 1
    else out.errored = out.errored + 1 end
    out.topics[row.topic] = (out.topics[row.topic] or 0) + 1
    if row.low_watermark ~= nil then
      out.low_watermarks[#out.low_watermarks + 1] = string.format("%s/%s -> %s", tostring(row.topic),
        num_text(row.partition), num_text(row.low_watermark))
    end
  end
  return out
end

-- The safety ledger is the part of the report that says what the script did not
-- do. Every claim in it is derived from a response, not from the intent of the
-- code that sent the request.
function analysis.safety(records, before, after, cfg)
  local out = { checks = {}, failed = 0, names_checked = 0, offset_zero = true,
    inventory_identical = nil, topic_delta = nil, topic_count_before = before.count or 0,
    topic_count_after = after.count or 0 }
  local function check(name, ok, detail)
    out.checks[#out.checks + 1] = { name = name, ok = ok, detail = detail }
    if not ok then out.failed = out.failed + 1 end
  end
  for _, name_check in ipairs(records.name_checks or {}) do
    out.names_checked = out.names_checked + 1
    if name_check.exists then
      check(string.format("'%s' was absent before the probe", tostring(name_check.name)), false,
        "the name already exists on the cluster, so the probe could have deleted a real topic")
    end
  end
  for _, row in ipairs((records.delete_records or {}).rows or {}) do
    if row.offset ~= 0 then
      out.offset_zero = false
      check("every DeleteRecords offset was 0", false,
        string.format("%s/%s asked for offset %s", tostring(row.topic), num_text(row.partition),
          tostring(row.offset)))
    end
  end
  check("every DeleteRecords offset was 0", out.offset_zero,
    "offset 0 is below the log start offset of every partition, so no record can match it")
  if records.delete_by_name and records.delete_by_name.answered then
    local existing = 0
    for _, row in ipairs(records.delete_by_name.rows or {}) do
      if records.before and (records.before.names or {})[row.name] then existing = existing + 1 end
    end
    check("no DeleteTopics request named a topic that exists", existing == 0,
      string.format("%d of %d names existed at the time of the request", existing,
        #(records.delete_by_name.rows or {})))
  end
  if before.answered and after.answered then
    local delta = {}
    for name in pairs(after.names or {}) do
      if not (before.names or {})[name] then delta[#delta + 1] = "+" .. name end
    end
    for name in pairs(before.names or {}) do
      if not (after.names or {})[name] then delta[#delta + 1] = "-" .. name end
    end
    table.sort(delta)
    out.topic_delta = delta
    out.inventory_identical = #delta == 0
    check("the topic list is identical before and after", #delta == 0,
      #delta == 0 and string.format("%d topics on both reads", before.count or 0)
        or fmt_list(delta, 8))
  else
    check("the topic list could be read twice", false,
      "one of the two reads was not answered, so the script cannot prove the cluster is unchanged")
  end
  out.clean = out.failed == 0
  return out
end

function analysis.exposure(records, name_path, id_path, records_path, safety)
  local rows = {}
  local function add(name, record, access, detail)
    rows[#rows + 1] = { name = name, access = access or (record and record.access) or "unknown",
      version = record and record.version, detail = detail,
      error_name = record and record.error_name, record = record }
  end
  local negotiate = records.negotiate or {}
  add("ApiVersions", negotiate, negotiate.answered and (negotiate.access or "granted") or "unanswered",
    negotiate.answered and (plural(negotiate.api_count or 0, "API") .. " offered") or tostring(negotiate.error))
  add("Metadata (topic list, before)", records.before,
    records.before and (records.before.access or "unknown") or "unanswered",
    records.before and plural(records.before.count or 0, "topic") or nil)
  add("Metadata (generated names)", records.name_checks and records.name_checks[1],
    records.name_checks and #records.name_checks > 0 and "answered" or "skipped",
    records.name_checks and plural(records.name_checks and #records.name_checks or 0, "name") or "none")
  add("DeleteTopics (name)", records.delete_by_name,
    records.delete_by_name and (records.delete_by_name.answered and
      (name_path.permitted > 0 and "granted" or (name_path.denied > 0 and "denied" or "answered"))
      or "unanswered") or "not attempted",
    string.format("%d attempted: %d permitted, %d denied", name_path.attempted or 0, name_path.permitted,
      name_path.denied))
  if not id_path.skipped then
    add("DeleteTopics (topic id)", records.delete_by_id,
      records.delete_by_id and (records.delete_by_id.answered and
        (is_permitted_verdict(records.delete_by_id.verdict) and "granted"
          or (records.delete_by_id.verdict == "denied" and "denied" or "answered")) or "unanswered")
        or "not attempted",
      records.delete_by_id and tostring(records.delete_by_id.error_name) or nil)
  end
  if not records_path.skipped then
    add("DeleteRecords (offset 0)", records.delete_records,
      records.delete_records and (records.delete_records.answered and
        (records_path.permitted > 0 and "granted"
          or (records_path.denied > 0 and "denied" or "answered")) or "unanswered") or "not attempted",
      string.format("%d partition(s): %d permitted, %d denied, %d other",
        #(records_path.rows or {}), records_path.permitted, records_path.denied, records_path.errored))
  end
  add("Metadata (topic list, after)", records.after,
    records.after and (records.after.access or "unknown") or "unanswered",
    records.after and plural(records.after.count or 0, "topic") or nil)
  local granted, denied, unanswered = 0, 0, 0
  for _, row in ipairs(rows) do
    if row.access == "granted" or row.access == "answered" then granted = granted + 1
    elseif row.access == "denied" then denied = denied + 1
    elseif row.access == "unanswered" then unanswered = unanswered + 1 end
  end
  return { rows = rows, granted = granted, denied = denied, unanswered = unanswered,
    clean = safety.clean }
end


----------------------------------------------------------------------------
-- 7. Knowledge base
----------------------------------------------------------------------------

local KB = {}

KB.SAFETY = {
  "DeleteTopics has no dry-run flag, so the script only ever names topics that it generated and then "
    .. "verified absent with a Metadata request that also sets allow_auto_topic_creation=false.",
  "The topic-id form of the request uses an all-zero id. A real topic id is assigned by the controller, so "
    .. "the lookup cannot match any topic on the cluster; the request exists to observe how the broker "
    .. "answers that path.",
  "DeleteRecords is sent with offset 0 for every partition. Records below offset 0 do not exist and the log "
    .. "start offset of a partition is never negative, so the request is a no-op - while still being the call "
    .. "that reveals whether the caller holds the DELETE operation on the topic.",
  "The topic list is read before and after the probes and compared name by name. A difference is reported as "
    .. "a critical finding, because it means the cluster changed while the script was running.",
  "The request bodies are written by the shared engine, which refuses to send DeleteTopics for a name the "
    .. "caller flagged as existing (opts.expect_existing), so the guard is in the code that builds the frame "
    .. "and not only in the logic that decides to call it.",
}

KB.REMEDIATION = {
  {
    step = "Require authentication on the client listener (SASL mechanism plus JAAS for the listener), so a "
      .. "DeleteTopics request is attributed to a principal an ACL can match.",
    why = "Without authentication every caller is ANONYMOUS, and an ACL written for a wildcard principal "
      .. "covers the scanner exactly as it covers the attacker.",
  },
  {
    step = "Grant DELETE only where it belongs: 'kafka-acls.sh --remove --allow-principal User:* --operation "
      .. "Delete --topic \"*\"', then add the provisioning principal with --operation Delete --topic <prefix>.",
    why = "Delete is a destructive operation on a resource that holds the data; the pipelines that need to "
      .. "create topics for a release do not need to delete them afterwards.",
  },
  {
    step = "Review DELETE on the cluster resource as well: the topic-id form of DeleteTopics and the "
      .. "controller-side deletion path are authorized against the cluster, so a cluster-wide DELETE grant "
      .. "makes the per-topic ACLs irrelevant for anything the caller can name by id.",
    why = "The script measures both paths because a broker that refuses the name form can still accept the "
      .. "id form, and the report says which one answered.",
  },
  {
    step = "Protect the internal topics explicitly: keep DELETE revoked on __consumer_offsets and "
      .. "__transaction_state for every principal except the operator, and verify with a describe of the "
      .. "ACL rather than with a delete attempt.",
    why = "Deleting the offsets topic does not delete a topic's data; it deletes the cluster's ability to "
      .. "remember where its consumers were, which fails every consumer group at once.",
  },
  {
    step = "Set 'delete.topic.enable=false' on brokers where topic removal must be an operator action, and "
      .. "alert on DeleteTopics requests in the broker log.",
    why = "The setting turns an ACL problem into a configuration one: with deletion disabled at the broker, "
      .. "a caller that is authorized still cannot remove a topic.",
  },
  {
    step = "Re-run this script after the change and confirm that the name path reports 'denied' and that the "
      .. "topic list is identical before and after the scan.",
    why = "The claim being verified is about behaviour, and only a request measures behaviour: the ACL may "
      .. "be attached to the wrong resource and the broker will answer NONE anyway.",
  },
}

KB.VERIFICATION = {
  "kafka-acls.sh --bootstrap-server <broker> --list --topic <name>  (show the DELETE grant, or its absence)",
  "kafka-topics.sh --bootstrap-server <broker> --delete --topic <probe-name>  (run without credentials: the "
    .. "expected answer is TopicAuthorizationException)",
  "kafka-acls.sh --bootstrap-server <broker> --list --cluster  (show whether DELETE on the cluster resource "
    .. "was granted, which is the path the topic-id form uses)",
  "kafka-configs.sh --bootstrap-server <broker> --describe --entity-type brokers --entity-name <id>  "
    .. "(confirm delete.topic.enable)",
  "kafka-topics.sh --bootstrap-server <broker> --list  (confirm the topic list matches the one this script "
    .. "printed before and after its probes)",
  "grep -iE 'DeleteTopics|DeleteRecords' <broker server.log>  (confirm that the refused requests are logged "
    .. "and attributed)",
  "kafka-topics.sh --bootstrap-server <broker> --describe --topic <name>  (after a deliberate deletion in "
    .. "tests, confirm the timeline: the topic disappears from Metadata before the replica directories do)",
  "kafka-consumer-groups.sh --bootstrap-server <broker> --list  (after any attempt against __consumer_offsets, "
    .. "confirm the groups are still listed and their offsets still resolve)",
}

KB.METHOD_LIMITS = {
  "DeleteTopics answers per topic name, and a broker refuses a name it does not host after it has authorized "
    .. "the caller; the script reports the error code and states what that ordering proves, rather than "
    .. "claiming that a deletion happened.",
  "The DELETE operation can also be granted at the cluster level, and Kafka's topic-id path consults that "
    .. "grant. This script measures both paths separately and prints the answer each one produced; it does "
    .. "not claim which ACL produced it.",
  "DeleteRecords at offset 0 is a no-op on a healthy cluster, but a broker that answers INVALID_REQUEST for "
    .. "it (some releases reject an offset below the log start offset instead of accepting it) has still "
    .. "told the scanner that the request passed authorization.",
  "A proxy, load balancer or multi-listener deployment can route the probe to a broker whose authorizer "
    .. "differs from the controller's. The report shows which broker answered nothing when the controller "
    .. "itself was not reached.",
  "The topic list read before and after the probes is the broker's own metadata cache; a deletion performed "
    .. "by another actor during the scan would appear as a difference, which is why the finding says that the "
    .. "cluster changed and not that this script changed it.",
  "No request in the script carries an existing topic name in DeleteTopics, and the mock used to test it "
    .. "records a violation if one ever does, so the safety property is enforced by the test suite as well as "
    .. "by the code.",
  "The DeleteRecords probe touches at most kafka.records-topics topics and eight partitions of each. A "
    .. "cluster with a large topic count is therefore sampled rather than swept, and the report says how many "
    .. "partitions were asked about so the sample size is never implied to be the population.",
  "An answer of NONE to DeleteRecords at offset 0 confirms the permission but not the effect: the broker "
    .. "that accepted the request reported a low watermark equal to the requested offset, which is the "
    .. "protocol's way of saying that nothing changed at that partition.",
  "Deletion is asynchronous. Even a successful DeleteTopics is a request to the controller, and the "
    .. "partitions disappear when each leader processes the deletion; the two topic-list reads in this report "
    .. "are therefore a snapshot around the probes and not a proof about another actor's deletions.",
}

-- The three ways a caller can ask for a deletion, and what each one consults.
KB.PATH_REFERENCE = {
  { path = "DeleteTopics by name",
    schema = "Topics[] of names, v0+",
    authorized_against = "the topic resource (DELETE on the topic)",
    note = "the path every admin tool uses; the broker looks the name up only after the ACL allows it, which "
      .. "is what makes an existence error evidence of a permission" },
  { path = "DeleteTopics by topic id",
    schema = "Topics[] of {name, id}, v6+",
    authorized_against = "the cluster resource, because the id is what the controller owns",
    note = "added for the controller-side deletion path; a cluster that protects names one by one can still "
      .. "answer this path, and this script measures it separately for exactly that reason" },
  { path = "DeleteRecords",
    schema = "Topics[] of {name, partitions[] of {index, offset}}, v0+",
    authorized_against = "the topic resource (DELETE on the topic)",
    note = "the only API that removes records rather than a topic: it moves the log start offset forward, so "
      .. "the data a consumer has not read yet can be discarded without any configuration change" },
  { path = "Auto-deletion by retention",
    schema = "not an API call",
    authorized_against = "the topic's own retention settings",
    note = "the reason a deleted topic does not necessarily delete its data immediately: the replicas keep "
      .. "the segments until retention or the deletion markers reach them, which is the window an operator "
      .. "can still recover from" },
}

-- What each internal topic means, and what deleting or truncating it breaks.
KB.INTERNAL_TOPIC_IMPACT = {
  { topic = "__consumer_offsets",
    role = "the committed offset of every consumer group, and the group's membership state",
    impact = "every consumer group loses its position: consumers restart from the earliest or latest offset "
      .. "depending on auto.offset.reset, and either re-read or skip data" },
  { topic = "__transaction_state",
    role = "the transaction coordinator's record of open and completed transactions",
    impact = "transactional producers cannot recover their transactions, so an exactly-once pipeline is "
      .. "left with writes it cannot confirm" },
  { topic = "_schemas",
    role = "the schema history of a Schema Registry that stores schemas in Kafka",
    impact = "every producer and consumer that validates schemas loses the registry, which stops the "
      .. "pipeline before any record is written" },
  { topic = "__cluster_metadata",
    role = "the KRaft metadata log: the cluster's own configuration and topic state",
    impact = "the controller's state is the cluster; damage here is damage to the deployment itself, which "
      .. "is why this topic is never a target of a probe" },
  { topic = "connect-configs",
    role = "the connector definitions of a Kafka Connect cluster, including their credentials",
    impact = "connectors cannot be restarted, and the credentials inside them have to be re-entered" },
  { topic = "connect-offsets",
    role = "the position of every source connector",
    impact = "connectors re-read their sources from the beginning or from the configured policy" },
}

-- The order of events after a successful delete request, which is why the
-- report can say "the data is not gone yet" without contradicting itself.
KB.DELETE_TIMELINE = {
  "The controller receives DeleteTopics and marks each partition for deletion; the topic disappears from "
    .. "Metadata immediately, so every client that refreshes its metadata stops routing to it.",
  "Producers fail with UNKNOWN_TOPIC_OR_PARTITION on their next send; consumers fail at their next metadata "
    .. "refresh or continue reading from the replicas they are already connected to until the partitions go "
    .. "offline.",
  "Each leader stops serving the partition and each replica removes its log directory, which is the point at "
    .. "which the records are actually gone; until then the segments still exist on disk.",
  "If a replica cannot be reached, its copy survives until it comes back and the deletion is replayed, so a "
    .. "deleted topic is recoverable for as long as an isolated replica holds it - and readable by whoever "
    .. "can reach that replica.",
  "On the topic-id path the same sequence runs from an id rather than a name, which is why the report "
    .. "measures that path even when the name path is refused.",
}

KB.ATTACK_VALUE = {
  { exposure = "delete permission on a topic",
    value = "a topic that disappears stops a pipeline: no data is lost from the log at first, but every "
      .. "consumer of it fails at the next metadata refresh, and the records are gone once retention catches "
      .. "up with the replicas that still hold them" },
  { exposure = "delete permission measured by existence error",
    value = "the caller learns which names it may delete without deleting anything, so it can plan a "
      .. "targeted deletion and check the permission first" },
  { exposure = "topic-id delete path",
    value = "an API client that deletes by id does not need to know the name, so this path survives a rename "
      .. "and reveals whether the caller may delete topics it can only identify by id" },
  { exposure = "record deletion on existing topics",
    value = "moving the log start offset forward discards records that producers already consider written; "
      .. "the retention window is no longer a guarantee, and a consumer that re-reads loses them" },
  { exposure = "internal topic deletion",
    value = "deleting __consumer_offsets or __transaction_state breaks every consumer group or every "
      .. "transactional producer on the cluster at once, which makes the permission an availability risk "
      .. "rather than a data-confidentiality one" },
}

KB.RISK_RUBRIC = {
  { severity = "CRITICAL", condition = "a delete request removed something, or the topic list changed "
    .. "between the two reads while the script was running" },
  { severity = "HIGH", condition = "the name path or the topic-id path reached the broker's lookup, or "
    .. "DeleteRecords was accepted on a topic that holds data" },
  { severity = "MEDIUM", condition = "only an internal topic was in scope, or a name-path request failed "
    .. "validation after passing authorization" },
  { severity = "LOW", condition = "only a policy error (invalid request, not the controller) was returned, "
    .. "or only quotas were observed" },
  { severity = "INFO", condition = "every request was refused, the API was not offered, or nothing answered" },
}

----------------------------------------------------------------------------
-- 8. Findings
----------------------------------------------------------------------------

local findings = {}

local function rows_of(rows, limit)
  local out = {}
  for index = 1, math.min(#rows, limit or 8) do out[#out + 1] = rows[index] end
  return out
end

function findings.evaluate(records, name_path, id_path, records_path, safety, exposure, cfg)
  local list = {}
  local negotiate = records.negotiate or {}

  if safety.failed > 0 then
    local failed = {}
    for _, check in ipairs(safety.checks) do
      if not check.ok then failed[#failed + 1] = string.format("%s: %s", check.name, tostring(check.detail)) end
    end
    list[#list + 1] = finding("KAFKA-DELETE-INVENTORY-CHANGED",
      "The cluster's topic list changed while the audit was running",
      "CRITICAL",
      string.format("%d safety check(s) failed. The script only ever offered names it generated and verified "
        .. "absent, so a failing check means either that the cluster changed under it or that the broker did "
        .. "not honour the request the way the protocol says it does. Either way the deletion path must be "
        .. "reviewed with the cluster's own audit log before this report is trusted.",
        safety.failed),
      failed, { KB.REMEDIATION[5], KB.REMEDIATION[1], KB.REMEDIATION[6] })
  end

  if name_path.permitted > 0 then
    local evidence = {}
    for _, row in ipairs(name_path.rows) do
      if is_permitted_verdict(row.verdict) then
        evidence[#evidence + 1] = string.format("%s -> %s (%s)", tostring(row.name),
          tostring(row.error_name), tostring(row.verdict))
      end
    end
    list[#list + 1] = finding("KAFKA-ANONYMOUS-TOPIC-DELETE",
      "Topic deletion is authorized without authentication",
      "HIGH",
      string.format("DeleteTopics was offered %s that do not exist, and %s came back with an answer that "
        .. "proves the authorization check passed: the broker looked the name up, which it does only after "
        .. "the ACL allowed the DELETE operation. A caller that may delete a topic turns a running pipeline "
        .. "into a stopped one, and with a generated name it can probe for the permission without deleting "
        .. "anything. The topic list was identical before and after this run, so nothing was removed by this "
        .. "scan.", plural(name_path.attempted, "name"), plural(name_path.permitted, "request")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[2], KB.REMEDIATION[5] })
  end

  if name_path.denied > 0 then
    list[#list + 1] = finding("KAFKA-TOPIC-DELETE-DENIED",
      "Topic deletion was refused without authentication",
      "INFO",
      string.format("%s were refused with an authorization error, which is the intended behaviour and the "
        .. "baseline for the next run: if this row disappears, the ACL changed.",
        plural(name_path.denied, "request")),
      rows_of((function()
        local out = {}
        for _, row in ipairs(name_path.rows) do
          if row.verdict == "denied" then
            out[#out + 1] = string.format("%s -> %s", tostring(row.name), tostring(row.error_name))
          end
        end
        return out
      end)(), 4), { KB.REMEDIATION[2], KB.REMEDIATION[6] })
  end

  if not id_path.skipped and id_path.answered then
    if is_permitted_verdict(id_path.verdict) then
      list[#list + 1] = finding("KAFKA-TOPIC-DELETE-BY-ID-PERMITTED",
        "The topic-id deletion path is authorized without authentication",
        "HIGH",
        string.format("DeleteTopics v%s was sent with an all-zero topic id and answered %s. The id form is "
          .. "what a controller uses, and it is authorized against the cluster resource rather than the "
          .. "topic, so a cluster that protects names one by one can still accept a deletion by id. The "
          .. "lookup only happens after authorization, which is what makes this answer a permission.",
          num_text(id_path.version), tostring(id_path.error_name)),
        { string.format("all-zero id -> %s (v%s)", tostring(id_path.error_name), num_text(id_path.version)) },
        { KB.REMEDIATION[1], KB.REMEDIATION[3] })
    elseif id_path.verdict == "denied" then
      list[#list + 1] = finding("KAFKA-TOPIC-DELETE-BY-ID-DENIED",
        "The topic-id deletion path was refused",
        "INFO",
        string.format("The topic-id form answered %s while the name path was %s. Both paths are measured "
          .. "because they consult different resources: a deployment that authorizes one and not the other "
          .. "is telling the caller which form to use.",
          tostring(id_path.error_name), name_path.permitted > 0 and "permitted" or "not permitted"),
        { string.format("all-zero id -> %s", tostring(id_path.error_name)) },
        { KB.REMEDIATION[3] })
    end
  elseif not id_path.skipped and id_path.answered == false then
    list[#list + 1] = finding("KAFKA-TOPIC-DELETE-BY-ID-UNANSWERED",
      "The topic-id deletion path was not answered",
      "INFO",
      string.format("The topic-id request was not answered (%s). It may be a version the broker does not "
        .. "implement even though it advertises it, or a listener that drops the frame; the name path above "
        .. "is unaffected.", tostring(id_path.error)),
      { tostring(id_path.error) }, { KB.REMEDIATION[1] })
  end

  if records_path.skipped or records_path.answered == false then
    list[#list + 1] = finding("KAFKA-DELETE-RECORDS-NOT-PROBED",
      "The record deletion path was not measured",
      "INFO",
      tostring(records_path.skipped or records_path.error
        or "the broker does not advertise DeleteRecords"), {}, { KB.REMEDIATION[3] })
  elseif records_path.answered and records_path.permitted > 0 then
    local evidence = {}
    for _, row in ipairs(records_path.rows) do
      evidence[#evidence + 1] = string.format("%s/%s at offset 0 -> %s (low watermark %s)",
        tostring(row.topic), num_text(row.partition), tostring(row.error_name),
        tostring(row.low_watermark))
    end
    local internal = nil
    for topic in pairs(records_path.topics or {}) do
      if string.sub(tostring(topic), 1, 2) == "__" then internal = topic end
    end
    list[#list + 1] = finding("KAFKA-DELETE-RECORDS-PERMITTED",
      "Records can be discarded from existing topics without authentication",
      "HIGH",
      string.format("DeleteRecords with offset 0 was accepted for %s across %s. Offset 0 removes nothing, "
        .. "so this scan changed no data - but the same request with the partition's high watermark would "
        .. "have discarded everything written to it. The answer therefore measures the DELETE operation on a "
        .. "topic that exists, which is the permission that breaks a running pipeline without touching its "
        .. "configuration.",
        plural(#(records_path.rows or {}), "partition"), plural(#(records_path.topics or {}), "topic")),
      evidence, { KB.REMEDIATION[1], KB.REMEDIATION[2], KB.REMEDIATION[4] })
    if internal then
      list[#list + 1] = finding("KAFKA-INTERNAL-TOPIC-RECORDS-IN-SCOPE",
        "An internal topic was among the topics the caller may truncate",
        "MEDIUM",
        string.format("One of the partitions the broker accepted a DeleteRecords request for belongs to %s. "
          .. "Truncating an internal topic does not remove data: it removes the cluster's memory of it, and "
          .. "for __consumer_offsets that means every consumer group loses its position at once.",
          tostring(internal)),
        { string.format("%s was in the probed set", tostring(internal)) },
        { KB.REMEDIATION[4], KB.REMEDIATION[2] })
    end
  elseif records_path.answered and records_path.denied > 0 then
    list[#list + 1] = finding("KAFKA-DELETE-RECORDS-DENIED",
      "Record deletion on existing topics was refused",
      "INFO",
      string.format("%s were refused with an authorization error while the name path was %s. The DELETE "
        .. "operation on the topic resource is enforced, which is the setting that matters for the data "
        .. "itself.", plural(records_path.denied, "partition"),
        name_path.permitted > 0 and "permitted" or "not permitted"),
      { string.format("denied partitions: %s", num_text(records_path.denied)) },
      { KB.REMEDIATION[2], KB.REMEDIATION[6] })
  end

  if safety.offset_zero and records_path.answered and #(records_path.rows or {}) > 0 then
    list[#list + 1] = finding("KAFKA-DELETE-RECORDS-NOOP-MEASUREMENT",
      "The record deletion probe was a no-op by construction",
      "INFO",
      string.format("Every DeleteRecords request asked for offset 0 on %s. A partition's log start offset is "
        .. "never negative, so no record was eligible for deletion and the cluster's data is unchanged; the "
        .. "authorization answer is the measurement.", plural(#(records_path.rows or {}), "partition")),
      { "requested offset: 0 on every partition" }, { KB.REMEDIATION[6] })
  end

  if negotiate.answered and not negotiate.delete_topics_offered then
    list[#list + 1] = finding("KAFKA-DELETE-API-NOT-OFFERED",
      "The broker does not advertise DeleteTopics",
      "INFO",
      string.format("ApiVersions answered with %s but not with DeleteTopics, so the deletion permission "
        .. "could not be measured. A broker that hides the API from an unauthenticated caller is showing "
        .. "enforcement, not the absence of the permission.", plural(negotiate.api_count or 0, "API")),
      { "DeleteTopics was not in the version table" }, { KB.REMEDIATION[1] })
  end

  for _, row in ipairs(name_path.rows or {}) do
    if row.verdict == "not-controller" or row.verdict == "invalid-request" then
      list[#list + 1] = finding("KAFKA-DELETE-BROKER-DEPENDENT-ANSWER",
        "The answer depends on which broker handled the request",
        "LOW",
        string.format("A broker answered %s to a deletion request. Broker-side policy and controller "
          .. "ownership decide this answer, so a scan against another node of the same cluster can produce a "
          .. "different verdict; the controller is the only node that performs a deletion.",
          tostring(row.error_name)),
        { string.format("%s -> %s", tostring(row.name), tostring(row.error_name)) },
        { KB.REMEDIATION[1], KB.REMEDIATION[6] })
      break
    end
  end

  for _, record in ipairs({ records.delete_by_name, records.delete_records }) do
    if record and record.throttle_ms and record.throttle_ms > 0 then
      list[#list + 1] = finding("KAFKA-DELETE-QUOTA-OBSERVED",
        "A quota delayed a deletion request",
        "LOW",
        string.format("The broker reported %dms of throttle time on the %s request, so a quota is attached "
          .. "to the client that asked. Quotas bound how quickly a permission can be exercised, which matters "
          .. "most when the permission is held by an unauthenticated principal.",
          record.throttle_ms, tostring(record.stage or "deletion")),
        { string.format("throttle_time_ms=%s on %s", num_text(record.throttle_ms), tostring(record.stage)) },
        { KB.REMEDIATION[5] })
      break
    end
  end

  if not negotiate.answered then
    list[#list + 1] = finding("KAFKA-DELETE-PERMISSION-NOT-MEASURED",
      "The deletion permission could not be measured",
      "INFO",
      string.format("ApiVersions was not answered (%s), so no deletion request was sent and this report makes "
        .. "no claim about the cluster. A listener that requires authentication, a TLS-only listener and a "
        .. "filtered network path all look like this from outside.", tostring(negotiate.error)),
      { tostring(negotiate.error) }, { KB.REMEDIATION[1] })
  end

  if #list == 0 then
    list[#list + 1] = finding("KAFKA-DELETE-NO-FINDING",
      "No deletion exposure was measured",
      "NONE",
      "Every request either was refused or was answered in a way that proves nothing about the caller's "
        .. "permissions. The access matrix above shows which answer each request received.",
      { string.format("name path: %d permitted, %d denied", name_path.permitted, name_path.denied) },
      { KB.REMEDIATION[6] })
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
    string.format("Generated names offered: %s, topic-id form: %s, record probe: %s",
      plural(cfg.names, "name"), fmt_bool(cfg.topic_id_probe), fmt_bool(cfg.records_probe)),
  }
  if negotiate.answered then
    lines[#lines + 1] = string.format("DeleteTopics: %s, DeleteRecords: %s",
      negotiate.delete_topics_version ~= nil
        and ("v" .. num_text(negotiate.delete_topics_version)) or "not offered",
      negotiate.delete_records_version ~= nil
        and ("v" .. num_text(negotiate.delete_records_version)) or "not offered")
    if negotiate.topic_id_form then
      lines[#lines + 1] = "The broker advertises the topic-id form (DeleteTopics v6 or later), so the "
        .. "id path is measured separately from the name path."
    end
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
    string.format("Generated names verified absent before use: %s of %s",
      num_text(safety.names_checked - (safety.failed or 0) >= 0 and safety.names_checked or 0),
      num_text(safety.names_checked)),
    string.format("DeleteRecords offset on every request: %s", safety.offset_zero and "0" or "not 0"),
    string.format("Topic list: %s before, %s after, identical: %s", num_text(safety.topic_count_before),
      num_text(safety.topic_count_after), tostring(safety.inventory_identical)),
  }
  if safety.topic_delta and #safety.topic_delta > 0 then
    lines[#lines + 1] = "Difference: " .. fmt_list(safety.topic_delta, 10)
  end
  for _, check in ipairs(safety.checks or {}) do
    lines[#lines + 1] = string.format("[%s] %s%s", check.ok and "ok" or "FAILED", check.name,
      check.detail and (" - " .. tostring(check.detail)) or "")
  end
  for _, line in ipairs(KB.SAFETY) do lines[#lines + 1] = line end
  return lines
end

function report.access_section(exposure)
  local lines = { string.format("%-30s %-12s %-8s %s", "Request", "Access", "Version", "What came back") }
  for _, row in ipairs(exposure.rows or {}) do
    lines[#lines + 1] = string.format("%-30s %-12s %-8s %s", row.name, tostring(row.access),
      row.version and ("v" .. num_text(row.version)) or "-", tostring(row.detail or "-"))
  end
  lines[#lines + 1] = string.format("Summary: %d answered, %d refused, %d unanswered",
    exposure.granted or 0, exposure.denied or 0, exposure.unanswered or 0)
  return lines
end

function report.name_section(name_path, records)
  local lines = {}
  if not name_path.answered then
    return { string.format("The name path was not answered (%s).",
      tostring((records.delete_by_name or {}).error)) }
  end
  lines[#lines + 1] = string.format("%-46s %-28s %-24s %s", "Generated name", "Error", "Verdict", "Proves")
  for _, row in ipairs(name_path.rows or {}) do
    lines[#lines + 1] = string.format("%-46s %-28s %-24s %s", string.sub(tostring(row.name), 1, 46),
      tostring(row.error_name or row.error_code or "no answer"), tostring(row.verdict), tostring(row.meaning))
    if row.error_message and #tostring(row.error_message) > 0 then
      lines[#lines + 1] = "    broker message: " .. tostring(row.error_message)
    end
  end
  local parts = {}
  for _, verdict in ipairs(sorted_keys(name_path.verdicts)) do
    parts[#parts + 1] = string.format("%s x%s", tostring(verdict), num_text(name_path.verdicts[verdict]))
  end
  lines[#lines + 1] = "Verdicts: " .. fmt_list(parts, 8)
  lines[#lines + 1] = string.format("%s are names this run generated; none of them existed when the request "
    .. "was sent.", plural(name_path.attempted, "name"))
  return lines
end

function report.id_section(id_path, records, cfg)
  if not cfg.topic_id_probe then
    return { "The topic-id form was not probed (kafka.topic-id-probe=false)." }
  end
  if id_path.skipped then
    return { "The topic-id form was not probed: " .. tostring(id_path.skipped) }
  end
  if id_path.answered == false then
    return { string.format("The topic-id request was not answered (%s).", tostring(id_path.error)) }
  end
  return {
    string.format("Version: v%s", num_text(id_path.version)),
    string.format("Topic id sent: %s (random per run; a real id is chosen by the controller)", tostring(id_path.requested_id)),
    string.format("Answer: %s", tostring(id_path.error_name or id_path.error_code)),
    string.format("Verdict: %s - %s", tostring(id_path.verdict), tostring(id_path.meaning)),
    id_path.error_message and ("Broker message: " .. tostring(id_path.error_message)) or nil,
  }
end

function report.records_section(records_path, cfg)
  local lines = {}
  if not cfg.records_probe then
    return { "The record probe was not run (kafka.records-probe=false)." }
  end
  if records_path.skipped then
    return { "The record probe was not run: " .. tostring(records_path.skipped) }
  end
  if records_path.answered == false then
    return { string.format("The record probe was not answered (%s).",
      tostring(records_path.error or "no response")) }
  end
  if #(records_path.rows or {}) == 0 then
    return { "The record probe returned no partition." }
  end
  lines[#lines + 1] = string.format("%-32s %-8s %-9s %-28s %-12s %s", "Topic", "Partition", "Offset",
    "Error", "Low water", "Verdict")
  for _, row in ipairs(records_path.rows) do
    lines[#lines + 1] = string.format("%-32s %-8s %-9s %-28s %-12s %s",
      string.sub(tostring(row.topic), 1, 32), num_text(row.partition), num_text(row.offset),
      tostring(row.error_name or row.error_code or "no answer"),
      row.low_watermark ~= nil and num_text(row.low_watermark) or "-", tostring(row.verdict))
  end
  lines[#lines + 1] = string.format("Summary: %d permitted, %d denied, %d other across %s",
    records_path.permitted, records_path.denied, records_path.errored,
    plural(#(records_path.topics or {}), "topic"))
  local parts = {}
  for _, verdict in ipairs(sorted_keys(records_path.verdicts)) do
    parts[#parts + 1] = string.format("%s x%s", tostring(verdict), num_text(records_path.verdicts[verdict]))
  end
  lines[#lines + 1] = "Verdicts: " .. fmt_list(parts, 8)
  lines[#lines + 1] = "Every request asked for offset 0, so the low watermark in the answer is where the log "
    .. "already started and no record was eligible for deletion."
  return lines
end

function report.inventory_section(before, after, cfg)
  local lines = {}
  if not before.answered then
    return { string.format("The topic list was not read (%s).", tostring(before.error)) }
  end
  lines[#lines + 1] = string.format("Before the probes: %s (%d internal)", plural(before.count, "topic"),
    (function()
      local internal = 0
      for _, topic in ipairs(before.topics) do if topic.is_internal then internal = internal + 1 end end
      return internal
    end)())
  for index = 1, math.min(#before.topics, cfg.max_topics) do
    local topic = before.topics[index]
    lines[#lines + 1] = string.format("  %s%s: %s", tostring(topic.name),
      topic.is_internal and " (internal)" or "", plural(#(topic.partitions or {}), "partition"))
  end
  if #before.topics > cfg.max_topics then
    lines[#lines + 1] = string.format("  (%d further topic(s) not shown; raise kafka.max-topics)",
      #before.topics - cfg.max_topics)
  end
  if after.answered then
    lines[#lines + 1] = string.format("After the probes: %s, names identical to the first read: %s",
      plural(after.count, "topic"), fmt_bool((function()
        if before.count ~= after.count then return false end
        for name in pairs(before.names or {}) do
          if not (after.names or {})[name] then return false end
        end
        return true
      end)()))
  else
    lines[#lines + 1] = string.format("The second read was not answered (%s), so the report cannot state "
      .. "that the topic list is unchanged.", tostring(after.error))
  end
  return lines
end

function report.brokers_section(before, w, cfg)
  local lines = {}
  if not before.answered then
    return { "The broker inventory was not read." }
  end
  lines[#lines + 1] = string.format("The probe connected to %s:%s", tostring(w.host.ip or "target"),
    num_text(w.port.number))
  lines[#lines + 1] = string.format("Cluster id: %s, controller: %s", tostring(before.cluster_id or "withheld"),
    before.controller_id and num_text(before.controller_id) or "not returned")
  for _, broker in ipairs(before.brokers or {}) do
    lines[#lines + 1] = string.format("  node %s: %s:%s%s", num_text(broker.node_id), tostring(broker.host),
      num_text(broker.port), broker.rack and (" rack " .. tostring(broker.rack)) or "")
  end
  lines[#lines + 1] = "Deletion is performed by the controller, so a broker that is not the controller can "
    .. "answer a delete request with a redirecting error; the report shows the error it gave rather than "
    .. "treating it as a refusal."
  return lines
end

function report.path_section()
  local lines = { string.format("%-26s %-34s %-46s %s", "Path", "Schema", "Authorized against", "Why it matters") }
  for _, entry in ipairs(KB.PATH_REFERENCE) do
    lines[#lines + 1] = string.format("%-26s %-34s %-46s %s", entry.path, entry.schema,
      entry.authorized_against, entry.note)
  end
  return lines
end

function report.impact_section(before)
  local lines = {}
  local present = {}
  for _, topic in ipairs(before.topics or {}) do present[topic.name] = true end
  local shown = 0
  for _, entry in ipairs(KB.INTERNAL_TOPIC_IMPACT) do
    if present[entry.topic] then
      shown = shown + 1
      lines[#lines + 1] = string.format("%s: %s", entry.topic, entry.role)
      lines[#lines + 1] = "    if it is deleted or truncated: " .. entry.impact
    end
  end
  if shown == 0 then
    lines[#lines + 1] = "None of the internal topics this script knows about is present on the cluster, so "
      .. "the internal-topic impact section is empty by observation and not by omission."
  end
  return lines
end

function report.timeline_section()
  local lines = {}
  for index, step in ipairs(KB.DELETE_TIMELINE) do
    lines[#lines + 1] = string.format("%d. %s", index, step)
  end
  return lines
end

-- One table that puts the three paths next to each other, so the conclusion can
-- be read without walking the sections above.
function report.permission_section(name_path, id_path, records_path, cfg)
  local lines = { string.format("%-26s %-12s %-14s %-14s %s", "Path", "Attempted", "Permitted", "Refused",
    "Evidence") }
  local function row(label, attempted, permitted, refused, evidence)
    lines[#lines + 1] = string.format("%-26s %-12s %-14s %-14s %s", label, num_text(attempted),
      num_text(permitted), num_text(refused), tostring(evidence))
  end
  row("DeleteTopics by name", name_path.attempted or 0, name_path.permitted or 0, name_path.denied or 0,
    (name_path.permitted or 0) > 0
      and "the broker looked a generated name up, which it does after authorization"
      or ((name_path.denied or 0) > 0 and "the ACL refused every request" or "no conclusive answer"))
  if id_path.answered ~= nil or id_path.verdict then
    row("DeleteTopics by id", 1, is_permitted_verdict(id_path.verdict) and 1 or 0,
      id_path.verdict == "denied" and 1 or 0, tostring(id_path.error_name or "no answer"))
  else
    row("DeleteTopics by id", 0, 0, 0, tostring(id_path.skipped or "not probed"))
  end
  if records_path.rows and #records_path.rows > 0 then
    row("DeleteRecords at offset 0", #records_path.rows, records_path.permitted or 0,
      records_path.denied or 0, "offset 0 removes nothing; the answer is the permission")
  else
    row("DeleteRecords at offset 0", 0, 0, 0, tostring(records_path.skipped or "not probed"))
  end
  lines[#lines + 1] = "A permitted row means the broker reached its own business logic for that request; a "
    .. "refused row means an ACL stopped it before any state was consulted."
  return lines
end

function report.finding_section(list)
  if #list == 0 then
    return { "No finding: the deletion APIs published nothing to this caller." }
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

function report.verdict_section()
  local lines = { string.format("%-38s %-24s %s", "Error", "Verdict", "What it means") }
  for _, code in ipairs(sorted_keys(OUTCOMES)) do
    local entry = OUTCOMES[code]
    lines[#lines + 1] = string.format("%-38s %-24s %s",
      string.format("%s (%s)", tostring(kafka.error_name(code)), num_text(code)), entry.verdict, entry.meaning)
  end
  return lines
end

function report.build(cfg, host, port, records, name_path, id_path, records_path, safety, exposure, list, w)
  local out = stdnse.output_table()
  out["Target"] = report.target_section(cfg, host, port, w, records)
  out["Safety ledger"] = report.safety_section(safety, cfg, records)
  out["Access matrix"] = report.access_section(exposure)
  out["DeleteTopics by name"] = report.name_section(name_path, records)
  out["DeleteTopics by topic id"] = report.id_section(id_path, records, cfg)
  out["DeleteRecords at offset 0"] = report.records_section(records_path, cfg)
  out["Topic inventory"] = report.inventory_section(records.before or {}, records.after or {}, cfg)
  out["Brokers"] = report.brokers_section(records.before or {}, w, cfg)
  out["Deletion path reference"] = report.path_section()
  out["Internal topic impact"] = report.impact_section(records.before or {})
  out["What a deletion does"] = report.timeline_section()
  out["Permission matrix"] = report.permission_section(name_path, id_path, records_path, cfg)
  out["Findings"] = report.finding_section(list)
  out["Why the exposure matters"] = report.value_section(list)
  out["Remediation"] = report.remediation_section(list)
  out["Verification"] = KB.VERIFICATION
  out["Method limits"] = KB.METHOD_LIMITS
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

-- The existing topics the record probe is allowed to ask about: internal topics
-- are included on purpose, because a caller that may truncate one has a
-- cluster-wide effect, and the probe is a no-op either way.
local function select_record_targets(before, cfg)
  local entries, selected = {}, 0
  for _, topic in ipairs(before.topics or {}) do
    if selected >= cfg.records_topics then break end
    if topic.error_code == 0 and #(topic.partitions or {}) > 0 then
      local partitions = {}
      for index = 1, math.min(#topic.partitions, 8) do
        partitions[#partitions + 1] = { partition = topic.partitions[index].index, offset = 0 }
      end
      entries[#entries + 1] = { name = topic.name, partitions = partitions }
      selected = selected + 1
    end
  end
  return entries
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
      "The TCP connection failed, so no deletion request was sent. A TLS-only listener answers a plaintext "
        .. "Kafka probe exactly like this.",
    }
    return out
  end

  local records = {}
  records.negotiate = probe.negotiate(w)
  records.before = probe.topic_list(w, "metadata_before")

  -- Generate the names, then prove each of them absent before any of them is
  -- offered to the delete API.
  local names = generated_names("nmap-delete-audit", cfg.names)
  records.name_checks = {}
  for _, name in ipairs(names) do
    records.name_checks[#records.name_checks + 1] = probe.name_absent(w, name)
  end

  if records.negotiate.answered and records.negotiate.delete_topics_offered then
    records.delete_by_name = probe.delete_by_name(w, names)
    if cfg.topic_id_probe and records.negotiate.topic_id_form then
      records.delete_by_id = probe.delete_by_id(w, names[1] .. "-byid", random_topic_id())
    elseif cfg.topic_id_probe then
      records.delete_by_id = { skipped = "the broker does not advertise DeleteTopics v6 or later" }
    end
  end

  if cfg.records_probe and records.negotiate.answered and records.negotiate.delete_records_offered
    and cfg.records_topics > 0 then
    records.delete_records = probe.delete_records(w, select_record_targets(records.before, cfg))
  elseif cfg.records_probe and records.negotiate.answered and not records.negotiate.delete_records_offered then
    records.delete_records = { stage = "delete_records", answered = false, rows = {},
      error = "the broker does not advertise DeleteRecords" }
  elseif cfg.records_probe then
    records.delete_records = { stage = "delete_records", answered = true, rows = {},
      skipped = "no broker version was negotiated" }
  end

  records.after = probe.topic_list(w, "metadata_after")
  w:close()

  local name_path = analysis.name_path(records)
  local id_path = analysis.id_path(records, cfg)
  local records_path = analysis.records_path(records, cfg)
  local safety = analysis.safety(records, records.before, records.after, cfg)
  local exposure = analysis.exposure(records, name_path, id_path, records_path, safety)
  local list = findings.evaluate(records, name_path, id_path, records_path, safety, exposure, cfg)

  local result = report.build(cfg, host, port, records, name_path, id_path, records_path, safety, exposure,
    list, w)

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
