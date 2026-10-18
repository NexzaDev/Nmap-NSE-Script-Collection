local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Verifies whether RabbitMQ accepts the default guest/guest credential
pair over AMQP with a full connection.open, then measures what the
session can do with a passive sentinel probe.

Why it matters
- A working anonymous login is full message-bus compromise: an
  attacker can consume, produce and declare entities in the vhost.
- The passive queue.declare sentinel proves channel and declare
  reachability without touching any real queue.

What the script does
1. Runs connection.start/start-ok with PLAIN guest/guest.
2. On tune sends connection.open for vhost /.
3. If opened: channel.open plus a passive declare of the sentinel.
4. Grades the login outcome from open-ok vs close codes.

Safe operation: one login attempt with well-known defaults, no brute
force; the sentinel queue never exists so the declare is read-shaped
(passive) and the connection closes immediately after.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5672, "amqp", "tcp")

local SCRIPT_NAME = "rabbitmq-amqp-anonymous-login"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 48,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}
local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, maximum = 96, integer = true },
}

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local function trim(value)
  if type(value) ~= "string" then
    return value
  end
  value = string.gsub(value, "^%s+", "")
  value = string.gsub(value, "%s+$", "")
  return value
end

local function lower(value)
  if type(value) ~= "string" then
    return ""
  end
  return string.lower(trim(value))
end

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function ends_with(value, suffix)
  if #suffix > #value then
    return false
  end
  return string.sub(value, -#suffix) == suffix
end

local function contains(value, needle)
  return string.find(value or "", needle, 1, true) ~= nil
end

local function split(value, separator)
  local parts = {}
  if type(value) ~= "string" or #value == 0 then
    return parts
  end
  for chunk in string.gmatch(value, "([^" .. separator .. "]+)") do
    table.insert(parts, trim(chunk))
  end
  return parts
end

local function list_contains(list, needle)
  for _, item in ipairs(list or {}) do
    if item == needle then
      return true
    end
  end
  return false
end

local function table_size(tbl)
  local count = 0
  for _ in pairs(tbl or {}) do
    count = count + 1
  end
  return count
end

local function sorted_keys(tbl)
  local keys = {}
  for key in pairs(tbl or {}) do
    table.insert(keys, key)
  end
  table.sort(keys)
  return keys
end

local function unique_append(list, seen, value)
  if seen[value] then
    return false
  end
  seen[value] = true
  table.insert(list, value)
  return true
end

local function clamp(value, minimum, maximum)
  if value < minimum then
    return minimum
  end
  if value > maximum then
    return maximum
  end
  return value
end

local function byte_hex(value, count)
  local out = {}
  for i = 1, math.min(count or 16, #(value or "")) do
    table.insert(out, string.format("%02x", string.byte(value, i)))
  end
  return table.concat(out, " ")
end

local function truncate(value, limit)
  if type(value) ~= "string" then
    return tostring(value)
  end
  if #value <= limit then
    return value
  end
  return string.sub(value, 1, limit) .. "..."
end

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #(value or "") do
    hash = (hash ~ string.byte(value, i)) & 0xFFFFFFFF
    hash = (hash * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

local function entropy_bits(value)
  if type(value) ~= "string" or #value == 0 then
    return 0
  end
  local counts = {}
  for i = 1, #value do
    local char = string.sub(value, i, i)
    counts[char] = (counts[char] or 0) + 1
  end
  local length = #value
  local entropy = 0
  for _, count in pairs(counts) do
    local probability = count / length
    entropy = entropy - probability * (math.log(probability) / math.log(2))
  end
  return entropy
end

local function random_token(length, uppercase)
  local alphabet = uppercase and "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    or "abcdefghijklmnopqrstuvwxyz0123456789"
  local out = {}
  for _ = 1, length do
    local index = math.random(1, #alphabet)
    table.insert(out, string.sub(alphabet, index, index))
  end
  return table.concat(out)
end

local function seed_random(port)
  math.randomseed((os.time() * 65537) + ((port and port.number) or 0)
    + ((stdnse.clock_ms and stdnse.clock_ms()) or 0))
end

local state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }

local function reset_state()
  state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }
end

local function budget_exhausted(args)
  return state.requests >= args.maxrequests
end

local function sleep(seconds)
  if seconds and seconds > 0 then
    stdnse.sleep(seconds)
  end
end

local function read_args()
  local args = {}
  for key, value in pairs(DEFAULT_ARGS) do
    args[key] = value
  end

  for _, spec in ipairs(NUMERIC_ARGS) do
    local raw = stdnse.get_script_args(SCRIPT_NAME .. "." .. spec.key)
    local value = tonumber(raw)
    if value and value >= spec.minimum and (not spec.maximum or value <= spec.maximum) then
      if spec.integer then
        args[spec.key] = math.floor(value)
      else
        args[spec.key] = value
      end
    end
  end

  for _, key in ipairs(BOOLEAN_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if value ~= nil then
      args[key] = not (value == false or value == "false" or value == "no" or value == "0")
    end
  end

  for _, key in ipairs(STRING_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if type(value) == "string" and #trim(value) > 0 then
      args[key] = trim(value)
    elseif type(value) == "table" and #value > 0 then
      args[key] = trim(tostring(value[1]))
    end
  end

  local raw_list = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if raw_list and #tostring(raw_list) > 0 then
    local list = {}
    for candidate in string.gmatch(tostring(raw_list), "[^,]+") do
      local normalized = trim(candidate)
      if #normalized > 0 then
        if not starts_with(normalized, "/") then
          normalized = "/" .. normalized
        end
        table.insert(list, normalized)
      end
    end
    if #list > 0 then
      args.paths = list
    end
  end

  return args
end

KA = {}

KA.SENTINEL_TOPIC = "nse-audit-sentinel-zz0x"
KA.SENTINEL_QUEUE = "nse-audit-sentinel-zz0x"
KA.SENTINEL_VHOST = "/"

KA.w_i16 = function(n)
  n = math.floor(n or 0) % 65536
  return string.char(math.floor(n / 256) % 256, n % 256)
end

KA.w_i32 = function(n)
  n = math.floor(n or 0) % 4294967296
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256)
end

KA.b16 = function(s)
  if type(s) ~= "string" or #s < 2 then
    return 0
  end
  return s:byte(1) * 256 + s:byte(2)
end

KA.b32 = function(s)
  if type(s) ~= "string" or #s < 4 then
    return 0
  end
  return s:byte(1) * 16777216 + s:byte(2) * 65536 + s:byte(3) * 256 + s:byte(4)
end

KA.b16s = function(s)
  local n = KA.b16(s)
  if n >= 32768 then
    return n - 65536
  end
  return n
end

KA.b32s = function(s)
  local n = KA.b32(s)
  if n >= 2147483648 then
    return n - 4294967296
  end
  return n
end

KA.kafka_str = function(s)
  s = s or ""
  return KA.w_i16(#s) .. s
end

KA.read_kafka_str = function(data, off)
  local len = KA.b16s(data:sub(off, off + 1))
  if len < 0 or off + 2 + len > #data + 1 then
    return nil, off + 2
  end
  return data:sub(off + 2, off + 1 + len), off + 2 + len
end

KA.kafka_request = function(api_key, api_version, correlation_id, client_id, body)
  local header = KA.w_i16(api_key) .. KA.w_i16(api_version) .. KA.w_i32(correlation_id or 1) ..
    KA.kafka_str(client_id or "nse-audit")
  local payload = header .. (body or "")
  return KA.w_i32(#payload) .. payload
end

KA.kafka_response_parts = function(data)
  if type(data) ~= "string" or #data < 8 then
    return nil
  end
  local size = KA.b32(data:sub(1, 4))
  local correlation = KA.b32(data:sub(5, 8))
  return { size = size, correlation = correlation, body = data:sub(9, 8 + size - 4) }
end

KA.KAFKA_ERROR_NAMES = {
  [0] = "NO_ERROR", [1] = "OFFSET_OUT_OF_RANGE", [2] = "CORRUPT_MESSAGE",
  [3] = "UNKNOWN_TOPIC_OR_PARTITION", [4] = "INVALID_FETCH_SIZE", [5] = "LEADER_NOT_AVAILABLE",
  [6] = "NOT_LEADER_FOR_PARTITION", [7] = "REQUEST_TIMED_OUT", [8] = "BROKER_NOT_AVAILABLE",
  [9] = "REPLICA_NOT_AVAILABLE", [10] = "MESSAGE_TOO_LARGE", [11] = "STALE_CONTROLLER_EPOCH",
  [12] = "OFFSET_METADATA_TOO_LARGE", [13] = "NETWORK_EXCEPTION", [14] = "COORDINATOR_LOAD_IN_PROGRESS",
  [15] = "COORDINATOR_NOT_AVAILABLE", [16] = "NOT_COORDINATOR", [17] = "INVALID_TOPIC_EXCEPTION",
  [18] = "RECORD_LIST_TOO_LARGE", [19] = "NOT_ENOUGH_REPLICAS", [20] = "NOT_ENOUGH_REPLICAS_AFTER_APPEND",
  [21] = "INVALID_REQUIRED_ACKS", [22] = "ILLEGAL_GENERATION", [23] = "INCONSISTENT_GROUP_PROTOCOL",
  [24] = "INVALID_GROUP_ID", [25] = "UNKNOWN_MEMBER_ID", [26] = "INVALID_SESSION_TIMEOUT",
  [27] = "REBALANCE_IN_PROGRESS", [28] = "INVALID_COMMIT_OFFSET_SIZE", [29] = "TOPIC_AUTHORIZATION_FAILED",
  [30] = "GROUP_AUTHORIZATION_FAILED", [31] = "CLUSTER_AUTHORIZATION_FAILED", [32] = "INVALID_TIMESTAMP",
  [33] = "UNSUPPORTED_SASL_MECHANISM", [34] = "ILLEGAL_SASL_STATE", [35] = "UNSUPPORTED_VERSION",
  [36] = "TOPIC_ALREADY_EXISTS", [37] = "INVALID_PARTITIONS", [38] = "INVALID_REPLICATION_FACTOR",
  [39] = "INVALID_TOPIC_NULL", [40] = "INVALID_FETCH_SESSION", [42] = "INVALID_PRODUCER_EPOCH",
  [43] = "POLICY_VIOLATION", [45] = "DELEGATION_TOKEN_AUTH_DISABLED",
}

KA.kafka_error_name = function(code)
  return KA.KAFKA_ERROR_NAMES[code] or ("KAFKA_ERROR_" .. tostring(code))
end

KA.api_versions_request = function()
  return KA.kafka_request(18, 0, 1, "nse-audit", "")
end

KA.parse_api_versions = function(body)
  local out = { error_code = nil, apis = {}, version_floor = "unknown" }
  if type(body) ~= "string" or #body < 6 then
    return out
  end
  out.error_code = KA.b16s(body:sub(1, 2))
  local n = KA.b32(body:sub(3, 6))
  if n < 0 or n > 512 then
    n = 0
  end
  local off = 7
  for _ = 1, n do
    if off + 6 > #body + 1 then
      break
    end
    out.apis[#out.apis + 1] = {
      key = KA.b16s(body:sub(off, off + 1)),
      min = KA.b16s(body:sub(off + 2, off + 3)),
      max = KA.b16s(body:sub(off + 4, off + 5)),
    }
    off = off + 6
  end
  out.version_floor = KA.version_floor_from_apis(out.apis)
  return out
end

KA.VERSION_FLOORS = {
  [18] = "0.10.0", [19] = "0.10.1", [20] = "0.10.1", [21] = "0.11.0",
  [22] = "0.11.0", [27] = "0.11.0", [29] = "0.11.0", [32] = "1.0.0", [33] = "2.0.0",
  [34] = "2.2.0", [39] = "1.1.0", [41] = "2.3.0", [45] = "2.7.0",
}

KA.VERSION_ORDER = { "0.9", "0.10.0", "0.10.1", "0.11.0", "1.0.0", "1.1.0", "2.0.0", "2.2.0", "2.3.0", "2.7.0", "3.0.0" }

KA.version_rank = function(label)
  for i, v in ipairs(KA.VERSION_ORDER) do
    if v == label then
      return i
    end
  end
  return 0
end

KA.version_floor_from_apis = function(apis)
  local floor = "0.9"
  for _, api in ipairs(apis or {}) do
    local f = KA.VERSION_FLOORS[api.key]
    if f ~= nil and KA.version_rank(f) > KA.version_rank(floor) then
      floor = f
    end
  end
  return floor
end

KA.metadata_request = function(topics)
  local body
  if topics == nil then
    body = KA.w_i32(-1)
  else
    body = KA.w_i32(#topics)
    for _, t in ipairs(topics) do
      body = body .. KA.kafka_str(t)
    end
  end
  return KA.kafka_request(3, 0, 2, "nse-audit", body)
end

KA.parse_metadata = function(body)
  local out = { brokers = {}, controller_id = nil, topics = {} }
  if type(body) ~= "string" or #body < 8 then
    return out
  end
  local n = KA.b32(body:sub(1, 4))
  if n < 0 or n > 1024 then
    n = 0
  end
  local off = 5
  for _ = 1, n do
    local node_id = KA.b32s(body:sub(off, off + 3))
    local host
    host, off = KA.read_kafka_str(body, off + 4)
    local port = KA.b32(body:sub(off, off + 3))
    off = off + 4
    out.brokers[#out.brokers + 1] = { node_id = node_id, host = host or "?", port = port }
  end
  out.controller_id = KA.b32s(body:sub(off, off + 3))
  off = off + 4
  local tn = KA.b32(body:sub(off, off + 3))
  if tn < 0 or tn > 1024 then
    tn = 0
  end
  off = off + 4
  for _ = 1, tn do
    local err = KA.b16s(body:sub(off, off + 1))
    local name
    name, off = KA.read_kafka_str(body, off + 2)
    local pn = KA.b32(body:sub(off, off + 3))
    if pn < 0 or pn > 4096 then
      pn = 0
    end
    off = off + 4
    local parts = {}
    for _ = 2, pn + 1 do
      local perr = KA.b16s(body:sub(off, off + 1))
      local pid = KA.b32s(body:sub(off + 2, off + 5))
      local leader = KA.b32s(body:sub(off + 6, off + 9))
      off = off + 10
      local rc = KA.b32(body:sub(off, off + 3))
      if rc < 0 or rc > 1024 then
        rc = 0
      end
      off = off + 4 + rc * 4
      local ic = KA.b32(body:sub(off, off + 3))
      if ic < 0 or ic > 1024 then
        ic = 0
      end
      off = off + 4 + ic * 4
      parts[#parts + 1] = { error = perr, partition = pid, leader = leader, isr_count = ic, replica_count = rc }
    end
    out.topics[#out.topics + 1] = {
      error = err, error_name = KA.kafka_error_name(err), name = name or "?", partitions = parts,
    }
  end
  return out
end

KA.list_groups_request = function()
  return KA.kafka_request(16, 0, 3, "nse-audit", "")
end

KA.parse_list_groups = function(body)
  local out = { error_code = nil, groups = {} }
  if type(body) ~= "string" or #body < 6 then
    return out
  end
  out.error_code = KA.b16s(body:sub(1, 2))
  out.error_name = KA.kafka_error_name(out.error_code)
  local n = KA.b32(body:sub(3, 6))
  if n < 0 or n > 1024 then
    n = 0
  end
  local off = 7
  for _ = 1, n do
    local gid
    gid, off = KA.read_kafka_str(body, off)
    local ptype
    ptype, off = KA.read_kafka_str(body, off)
    out.groups[#out.groups + 1] = { id = gid or "?", protocol_type = ptype or "?" }
  end
  return out
end

KA.describe_groups_request = function(ids)
  local body = KA.w_i32(#ids)
  for _, id in ipairs(ids) do
    body = body .. KA.kafka_str(id)
  end
  return KA.kafka_request(15, 0, 4, "nse-audit", body)
end

KA.parse_describe_groups = function(body)
  local out = { groups = {} }
  if type(body) ~= "string" or #body < 4 then
    return out
  end
  local n = KA.b32(body:sub(1, 4))
  if n < 0 or n > 1024 then
    n = 0
  end
  local off = 5
  for _ = 1, n do
    local err = KA.b16s(body:sub(off, off + 1))
    local gid
    gid, off = KA.read_kafka_str(body, off + 2)
    local state
    state, off = KA.read_kafka_str(body, off)
    local ptype
    ptype, off = KA.read_kafka_str(body, off)
    local proto
    proto, off = KA.read_kafka_str(body, off)
    local mn = KA.b32(body:sub(off, off + 3))
    if mn < 0 or mn > 512 then
      mn = 0
    end
    off = off + 4
    local members = {}
    for _ = 2, mn + 1 do
      local mid
      mid, off = KA.read_kafka_str(body, off)
      local cid
      cid, off = KA.read_kafka_str(body, off)
      local chost
      chost, off = KA.read_kafka_str(body, off)
      local mmeta = KA.b32(body:sub(off, off + 3))
      off = off + 4 + math.max(mmeta, 0)
      local massign = KA.b32(body:sub(off, off + 3))
      off = off + 4 + math.max(massign, 0)
      members[#members + 1] = { member_id = mid or "?", client_id = cid or "?", client_host = chost or "?" }
    end
    out.groups[#out.groups + 1] = {
      error = err, error_name = KA.kafka_error_name(err), id = gid or "?", state = state or "?",
      protocol_type = ptype or "?", protocol = proto or "?", members = members,
    }
  end
  return out
end

KA.create_topic_request = function(topic, partitions, replication)
  local body = KA.w_i32(1) .. KA.kafka_str(topic) .. KA.w_i32(partitions or 1) ..
    KA.w_i16(replication or 1) .. KA.w_i32(0) .. KA.w_i32(0)
  return KA.kafka_request(19, 0, 5, "nse-audit", body)
end

KA.delete_topic_request = function(topic)
  local body = KA.w_i32(1) .. KA.kafka_str(topic) .. KA.w_i32(30000)
  return KA.kafka_request(20, 0, 6, "nse-audit", body)
end

KA.parse_topic_error_codes = function(body)
  local out = {}
  if type(body) ~= "string" or #body < 4 then
    return out
  end
  local n = KA.b32(body:sub(1, 4))
  if n < 0 or n > 256 then
    n = 0
  end
  local off = 5
  for _ = 1, n do
    local code = KA.b16s(body:sub(off, off + 1))
    local name
    name, off = KA.read_kafka_str(body, off + 2)
    out[#out + 1] = { topic = name or "?", error = code, error_name = KA.kafka_error_name(code) }
  end
  return out
end

KA.sasl_handshake_request = function(mechanism)
  return KA.kafka_request(17, 0, 7, "nse-audit", KA.kafka_str(mechanism))
end

KA.parse_sasl_handshake = function(body)
  local out = { error_code = nil, mechanisms = {} }
  if type(body) ~= "string" or #body < 6 then
    return out
  end
  out.error_code = KA.b16s(body:sub(1, 2))
  out.error_name = KA.kafka_error_name(out.error_code)
  local n = KA.b32(body:sub(3, 6))
  if n < 0 or n > 64 then
    n = 0
  end
  local off = 7
  for _ = 1, n do
    local m
    m, off = KA.read_kafka_str(body, off)
    out.mechanisms[#out.mechanisms + 1] = m or "?"
  end
  return out
end

KA.sasl_authenticate_request = function(auth_bytes)
  return KA.kafka_request(33, 0, 8, "nse-audit", KA.w_i32(#auth_bytes) .. auth_bytes)
end

KA.plain_bytes = function(user, pass)
  return "\0" .. (user or "") .. "\0" .. (pass or "")
end

KA.MECH_RANKS = { ["SCRAM-SHA-512"] = 5, ["SCRAM-SHA-256"] = 4, ["SCRAM-SHA-1"] = 3,
  ["GSSAPI"] = 3, ["OAUTHBEARER"] = 3, ["CRAM-MD5"] = 2, ["PLAIN"] = 1, AMQPLAIN = 1 }

KA.mech_strength = function(mechs)
  local best, names = nil, {}
  for _, m in ipairs(mechs or {}) do
    names[#names + 1] = m
    local rank = KA.MECH_RANKS[m] or 0
    if best == nil or rank > best.rank then
      best = { mechanism = m, rank = rank }
    end
  end
  table.sort(names)
  if best == nil then
    return { strongest = nil, names = names, strength = "none" }
  end
  local strength = "weak"
  if best.rank >= 3 then
    strength = "strong"
  elseif best.rank >= 1 then
    strength = "basic"
  end
  return { strongest = best.mechanism, names = names, strength = strength }
end

KA.KAFKA_ADVISORIES = {
  { floor = "0.10.0", items = { "SASL/GSSAPI authentication confusion era (CVE-2018-17196 lineage) - upgrade beyond the 2.x line" } },
  { floor = "0.11.0", items = { "pre-1.0 broker line out of support since 2018" } },
  { floor = "1.0.0", items = { "1.x broker line out of support - no TLS-hostname-verification fixes (CVE-2017-12610 lineage)" } },
  { floor = "2.0.0", items = { "2.0-2.2 era: SASL JAAS client-config abuse patterns documented (CVE-2023-25194 lineage on Connect)" } },
  { floor = "2.7.0", items = { "2.x line: review SASL JAAS configurations for JNDI injection patterns (CVE-2023-25194, CVE-2024-31141 lineage)" } },
}

KA.kafka_version_advisories = function(floor)
  local rank = KA.version_rank(floor or "0.9")
  local out = {}
  for _, e in ipairs(KA.KAFKA_ADVISORIES) do
    if rank <= KA.version_rank(e.floor) then
      for _, item in ipairs(e.items) do
        out[#out + 1] = item
      end
    end
  end
  return out
end

KA.analyze_topic_list = function(topics)
  local out = { total = #topics, internal = {}, user_topics = {}, partition_total = 0 }
  for _, t in ipairs(topics or {}) do
    if t.name:find("^__") then
      out.internal[#out.internal + 1] = t.name
    else
      out.user_topics[#out.user_topics + 1] = t.name
    end
    out.partition_total = out.partition_total + #t.partitions
  end
  return out
end

KA.broker_summary = function(metadata)
  local listeners = {}
  for _, b in ipairs(metadata.brokers or {}) do
    listeners[#listeners + 1] = b.node_id .. ":" .. b.host .. ":" .. b.port
  end
  return {
    broker_count = #listeners,
    controller_id = metadata.controller_id,
    listeners = listeners,
    compact = table.concat(listeners, ", "),
  }
end

KA.AMQP_HEADER = "AMQP\0\0\x09\x01"

KA.AMQP_FRAME_END = "\xCE"

KA.amqp_frame = function(frame_type, channel, payload)
  return string.char(frame_type) .. KA.w_i16(channel or 0) .. KA.w_i32(#payload) ..
    payload .. KA.AMQP_FRAME_END
end

KA.parse_amqp_frames = function(data)
  local out = {}
  if type(data) ~= "string" then
    return out
  end
  local i = 1
  while i + 7 <= #data do
    local ftype = data:byte(i)
    local channel = KA.b16(data:sub(i + 1, i + 2))
    local size = KA.b32(data:sub(i + 3, i + 6))
    if i + 7 + size > #data then
      break
    end
    local payload = data:sub(i + 7, i + 6 + size)
    local end_byte = data:byte(i + 7 + size)
    out[#out + 1] = { type = ftype, channel = channel, size = size, payload = payload,
      framed = end_byte == 0xCE }
    i = i + 8 + size
  end
  return out
end

KA.method_ids = function(payload)
  if type(payload) ~= "string" or #payload < 4 then
    return nil, nil
  end
  return KA.b16(payload:sub(1, 2)), KA.b16(payload:sub(3, 4))
end

KA.read_shortstr = function(data, off)
  local len = data:byte(off) or 0
  if len == 0 or off + len > #data then
    return "", off + 1
  end
  return data:sub(off + 1, off + len), off + 1 + len
end

KA.read_longstr = function(data, off)
  local len = KA.b32(data:sub(off, off + 3))
  if len <= 0 or off + 3 + len > #data then
    return "", off + 4
  end
  return data:sub(off + 4, off + 3 + len), off + 4 + len
end

KA.parse_field_table = function(data)
  local out = {}
  if type(data) ~= "string" or #data < 1 then
    return out
  end
  local total = #data
  local off = 1
  local end_at = #data
  while off < end_at do
    local name
    name, off = KA.read_shortstr(data, off)
    local vtype = data:sub(off, off)
    off = off + 1
    if vtype == "S" then
      local v
      v, off = KA.read_longstr(data, off)
      out[name] = v
    elseif vtype == "t" then
      out[name] = data:byte(off) == 1
      off = off + 1
    elseif vtype == "b" then
      out[name] = data:byte(off)
      off = off + 1
    elseif vtype == "i" then
      out[name] = KA.b32s(data:sub(off, off + 3))
      off = off + 4
    elseif vtype == "I" or vtype == "l" then
      out[name] = KA.b32s(data:sub(off, off + 3))
      off = off + 4
    elseif vtype == "F" then
      local inner_len = KA.b32(data:sub(off, off + 3))
      off = off + 4 + math.max(inner_len, 0)
      out[name] = "{table}"
    elseif vtype == "V" then
      out[name] = nil
    else
      break
    end
  end
  return out
end

KA.encode_field_value = function(v)
  local tv = type(v)
  if tv == "boolean" then
    return "t" .. (v and "\1" or "\0")
  elseif tv == "string" then
    return "S" .. KA.w_i32(#v) .. v
  elseif tv == "number" then
    return "i" .. KA.w_i32(math.floor(v))
  end
  return "V"
end

KA.encode_field_table = function(t)
  local entries = {}
  local names = {}
  for k in pairs(t or {}) do
    names[#names + 1] = k
  end
  table.sort(names)
  for _, k in ipairs(names) do
    entries[#entries + 1] = string.char(#k) .. k .. KA.encode_field_value(t[k])
  end
  local blob = table.concat(entries)
  return KA.w_i32(#blob) .. blob
end

KA.parse_connection_start = function(payload)
  local out = { major = nil, minor = nil, properties = {}, mechanisms = {}, locales = {} }
  if type(payload) ~= "string" or #payload < 6 then
    return out
  end
  out.major = payload:byte(5)
  out.minor = payload:byte(6)
  local props_raw, off = KA.read_longstr(payload, 7)
  out.properties = KA.parse_field_table(props_raw)
  local mech_raw
  mech_raw, off = KA.read_longstr(payload, off)
  for m in (mech_raw .. " "):gmatch("([^%s]+)%s") do
    out.mechanisms[#out.mechanisms + 1] = m
  end
  local loc_raw = KA.read_longstr(payload, off)
  for l in ((loc_raw or "") .. " "):gmatch("([^%s]+)%s") do
    out.locales[#out.locales + 1] = l
  end
  return out
end

KA.start_ok_payload = function(mechanism, response, client_props)
  local props = client_props or { product = "nse-audit", version = "1.0", platform = "Lua" }
  return KA.w_i16(0) .. KA.w_i16(9) .. KA.encode_field_table(props) ..
    string.char(#(mechanism or "")) .. (mechanism or "") ..
    KA.w_i32(#response) .. response .. string.char(5) .. "en_US"
end

KA.plain_response = function(user, pass)
  return "\0" .. (user or "") .. "\0" .. (pass or "")
end

KA.parse_start_ok = function(payload)
  local out = { properties = {}, mechanism = nil, response = nil, locale = nil }
  if type(payload) ~= "string" or #payload < 8 then
    return out
  end
  local props_raw, off = KA.read_longstr(payload, 5)
  out.properties = KA.parse_field_table(props_raw)
  out.mechanism, off = KA.read_shortstr(payload, off)
  out.response, off = KA.read_longstr(payload, off)
  out.locale = KA.read_shortstr(payload, off)
  local user, pass = out.response:match("^\0([^\0]*)\0([^\0]*)$")
  out.user = user
  out.pass = pass
  return out
end

KA.parse_tune = function(payload)
  if type(payload) ~= "string" or #payload < 12 then
    return { channel_max = 0, frame_max = 0, heartbeat = 0 }
  end
  return {
    channel_max = KA.b16(payload:sub(5, 6)),
    frame_max = KA.b32(payload:sub(7, 10)),
    heartbeat = KA.b16(payload:sub(11, 12)),
  }
end

KA.tune_ok_payload = function(tune)
  tune = tune or { channel_max = 0, frame_max = 131072, heartbeat = 60 }
  return KA.w_i16(tune.channel_max) .. KA.w_i32(tune.frame_max) .. KA.w_i16(tune.heartbeat)
end

KA.open_payload = function(vhost)
  return KA.kafka_str(vhost or "/") .. KA.kafka_str("") .. "\0"
end

KA.parse_open_ok = function(payload)
  local known, _ = KA.read_shortstr(payload or "", 1)
  return { known_hosts = known }
end

KA.close_payload = function(code, text, class_id, method_id)
  return KA.w_i16(code or 200) .. KA.kafka_str(text or "audit close") ..
    KA.w_i16(class_id or 0) .. KA.w_i16(method_id or 0)
end

KA.parse_close = function(payload)
  if type(payload) ~= "string" or #payload < 8 then
    return { code = nil, text = "" }
  end
  local code = KA.b16(payload:sub(5, 6))
  local text, _ = KA.read_shortstr(payload, 7)
  return { code = code, text = text, class_id = KA.b16(payload:sub(#payload - 3, #payload - 2)) }
end

KA.channel_open_payload = function()
  return KA.kafka_str("")
end

KA.queue_declare_passive_payload = function(queue)
  return KA.w_i16(0) .. KA.kafka_str(queue) .. "\1\0\0\0" .. KA.encode_field_table({})
end

KA.parse_declare_ok = function(payload)
  if type(payload) ~= "string" or #payload < 4 then
    return { queue = nil, messages = nil, consumers = nil }
  end
  local queue, off = KA.read_shortstr(payload, 5)
  return {
    queue = queue,
    messages = KA.b32(payload:sub(off, off + 3)),
    consumers = KA.b32(payload:sub(off + 4, off + 7)),
  }
end

KA.AMQP_METHOD_NAMES = {
  ["10:10"] = "connection.start", ["10:11"] = "connection.start-ok",
  ["10:20"] = "connection.secure", ["10:21"] = "connection.secure-ok",
  ["10:30"] = "connection.tune", ["10:31"] = "connection.tune-ok",
  ["10:40"] = "connection.open", ["10:41"] = "connection.open-ok",
  ["10:50"] = "connection.close", ["10:51"] = "connection.close-ok",
  ["20:10"] = "channel.open", ["20:11"] = "channel.open-ok",
  ["20:20"] = "channel.flow", ["20:40"] = "channel.close",
  ["40:10"] = "exchange.declare", ["50:10"] = "queue.declare",
  ["50:11"] = "queue.declare-ok", ["50:30"] = "queue.bind",
  ["60:40"] = "basic.get", ["60:71"] = "basic.get-ok",
  ["90:10"] = "sasl.start", ["90:11"] = "sasl.start-ok",
  ["90:20"] = "sasl.secure", ["90:21"] = "sasl.secure-ok",
}

KA.method_name = function(class_id, method_id)
  return KA.AMQP_METHOD_NAMES[class_id .. ":" .. method_id] or
    (class_id .. ":" .. method_id)
end

KA.AMQP_CLOSE_CODES = {
  [200] = "normal close", [311] = "content-too-large", [313] = "no-consumers",
  [320] = "connection-forced", [403] = "access-refused (authentication/authorization)",
  [404] = "not-found (entity does not exist)", [501] = "frame-error",
  [503] = "command-invalid", [504] = "channel-error", [505] = "unexpected-frame",
  [506] = "resource-error", [530] = "not-allowed", [540] = "not-implemented",
  [541] = "internal-error",
}

KA.close_code_name = function(code)
  return KA.AMQP_CLOSE_CODES[code] or ("AMQP_CLOSE_" .. tostring(code))
end

KA.RABBITMQ_ADVISORIES = {
  { max = "3.7.20", items = { "CVE-2019-11287: Management UI / HTTP API denial of service (fixed 3.7.21 / 3.8.1)" } },
  { max = "3.8.15", items = { "CVE-2021-22116: Management UI cross-site scripting via WebSocket (fixed 3.8.16)" } },
  { max = "3.11.23", items = { "CVE-2023-46120: TCP denial of service via crafted AMQP frames (fixed 3.11.24 / 3.12.8)" } },
}

KA.rabbitmq_version_advisories = function(version)
  local out = {}
  local function num(v)
    local a, b, c = tostring(v):match("^(%d+)%.(%d+)%.(%d+)")
    if a == nil then
      return nil
    end
    return a * 1000000 + b * 1000 + c
  end
  local cur = num(version)
  if cur == nil then
    return out
  end
  for _, e in ipairs(KA.RABBITMQ_ADVISORIES) do
    local lim = num(e.max)
    if lim ~= nil and cur <= lim then
      for _, item in ipairs(e.items) do
        out[#out + 1] = item
      end
    end
  end
  return out
end

KA.version_tuple_num = function(version)
  local a, b, c = tostring(version or ""):match("^(%d+)%.(%d+)%.(%d+)")
  if a == nil then
    return nil
  end
  return a * 1000000 + b * 1000 + c
end

local json_null = setmetatable({}, { __tostring = function() return "null" end })

local json_decode_value
local json_decode_string
local json_decode_number

json_decode_string = function(s, i)
  local out = {}
  i = i + 1
  while i <= #s do
    local c = s:sub(i, i)
    if c == '"' then
      return table.concat(out), i + 1
    end
    if c == "\\" then
      local n = s:sub(i + 1, i + 1)
      if n == "n" then
        out[#out + 1] = "\n"
      elseif n == "t" then
        out[#out + 1] = "\t"
      elseif n == "r" then
        out[#out + 1] = "\r"
      elseif n == "u" then
        local hex = s:sub(i + 2, i + 5)
        out[#out + 1] = string.char(tonumber(hex, 16) or 63)
        i = i + 4
      else
        out[#out + 1] = n
      end
      i = i + 2
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return table.concat(out), i
end

json_decode_number = function(s, i)
  local j = i
  while j <= #s and s:sub(j, j):match("[%d%+%-%.eE]") do
    j = j + 1
  end
  return tonumber(s:sub(i, j - 1)) or 0, j
end

json_decode_value = function(s, i)
  local c = s:sub(i, i)
  while c == " " or c == "\n" or c == "\t" or c == "\r" do
    i = i + 1
    c = s:sub(i, i)
  end
  if c == "{" then
    local obj = {}
    i = i + 1
    while i <= #s do
      c = s:sub(i, i)
      if c == "}" then
        return obj, i + 1
      end
      if c == '"' then
        local key
        key, i = json_decode_string(s, i)
        while s:sub(i, i):match("[%s:]") do
          i = i + 1
        end
        local v
        v, i = json_decode_value(s, i)
        obj[key] = v
      else
        i = i + 1
      end
    end
    return obj, i
  elseif c == "[" then
    local arr = {}
    i = i + 1
    while i <= #s do
      c = s:sub(i, i)
      if c == "]" then
        return arr, i + 1
      end
      if c == "," then
        i = i + 1
      else
        local v
        v, i = json_decode_value(s, i)
        if v ~= nil then
          arr[#arr + 1] = v
        end
      end
    end
    return arr, i
  elseif c == '"' then
    return json_decode_string(s, i)
  elseif s:sub(i, i + 3) == "true" then
    return true, i + 4
  elseif s:sub(i, i + 4) == "false" then
    return false, i + 5
  elseif s:sub(i, i + 3) == "null" then
    return json_null, i + 4
  else
    return json_decode_number(s, i)
  end
end

KA.json_decode = function(s)
  if type(s) ~= "string" or s == "" then
    return nil
  end
  local v = json_decode_value(s, 1)
  return v
end

KA.json_encode = function(v)
  local tv = type(v)
  if v == json_null then
    return "null"
  elseif tv == "table" then
    local is_array = (v[1] ~= nil or next(v) == nil)
    local parts = {}
    if is_array then
      for _, x in ipairs(v) do
        parts[#parts + 1] = KA.json_encode(x)
      end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    for k, x in pairs(v) do
      parts[#parts + 1] = '"' .. tostring(k) .. '":' .. KA.json_encode(x)
    end
    return "{" .. table.concat(parts, ",") .. "}"
  elseif tv == "boolean" then
    return tostring(v)
  elseif tv == "number" then
    return tostring(math.floor(v))
  elseif tv == "string" then
    return '"' .. v:gsub('[%c\\"]', "") .. '"'
  end
  return "null"
end

KA.http_get_request = function(host_header, path)
  return "GET " .. path .. " HTTP/1.1\r\nHost: " .. (host_header or "target") ..
    "\r\nUser-Agent: nse-audit\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
end

KA.parse_http_response = function(raw)
  local out = { status = nil, reason = nil, headers = {}, body = "" }
  if type(raw) ~= "string" or #raw < 12 then
    return out
  end
  local sep = raw:find("\r\n\r\n", 1, true)
  local head, body
  if sep ~= nil then
    head = raw:sub(1, sep + 3)
    body = raw:sub(sep + 4)
  else
    head = raw
    body = ""
  end
  out.status = tonumber(head:match("^HTTP/%d%.%d%s+(%d+)"))
  out.reason = head:match("^HTTP/%d%.%d%s+%d+%s+([^\r\n]+)")
  for line in head:gmatch("([^\r\n]+)") do
    local k, v = line:match("^([%w%-%_]+):%s*(.-)%s*$")
    if k ~= nil then
      out.headers[k:lower()] = v
    end
  end
  out.body = body or ""
  local clen = tonumber(out.headers["content-length"])
  if clen ~= nil and #out.body > clen then
    out.body = out.body:sub(1, clen)
  end
  if out.headers["transfer-encoding"] == "chunked" then
    local decoded = {}
    local pos = 1
    while pos <= #out.body do
      local hex = out.body:match("^([%x]+)\r\n", pos)
      if hex == nil then
        break
      end
      local n = tonumber(hex, 16)
      local chunk = out.body:sub(pos + #hex + 2, pos + #hex + 1 + n)
      decoded[#decoded + 1] = chunk
      pos = pos + #hex + 2 + n + 2
    end
    out.body = table.concat(decoded)
  end
  return out
end

KA.parse_overview = function(doc)
  local out = { version = nil, management_version = nil, listeners = {},
    queue_totals = {}, object_totals = {}, node = nil }
  if type(doc) ~= "table" then
    return out
  end
  out.version = doc.rabbitmq_version
  out.management_version = doc.management_version
  out.node = doc.node
  for _, l in ipairs(doc.listeners or {}) do
    out.listeners[#out.listeners + 1] = { protocol = l.protocol, port = l.port, interface = l.ip_address }
  end
  out.queue_totals = {
    messages = (doc.queue_totals or {}).messages,
    ready = (doc.queue_totals or {}).messages_ready,
    unacked = (doc.queue_totals or {}).messages_unacknowledged,
  }
  local ot = doc.object_totals or {}
  out.object_totals = {
    connections = ot.connections, channels = ot.channels, queues = ot.queues,
    exchanges = ot.exchanges, consumers = ot.consumers,
  }
  return out
end

KA.parse_definitions = function(doc)
  local out = { users = {}, vhosts = {}, permissions = 0, queues = 0, exchanges = 0,
    bindings = 0, policies = 0, guest_present = false, admin_users = {} }
  if type(doc) ~= "table" then
    return out
  end
  for _, u in ipairs(doc.users or {}) do
    out.users[#out.users + 1] = { name = u.name, tags = u.tags }
    if u.name == "guest" then
      out.guest_present = true
    end
    if (u.tags or ""):find("administrator") then
      out.admin_users[#out.admin_users + 1] = u.name
    end
  end
  for _, v in ipairs(doc.vhosts or {}) do
    out.vhosts[#out.vhosts + 1] = v.name
  end
  out.permissions = #(doc.permissions or {})
  out.queues = #(doc.queues or {})
  out.exchanges = #(doc.exchanges or {})
  out.bindings = #(doc.bindings or {})
  out.policies = #(doc.policies or {})
  return out
end

KA.parse_queues = function(doc)
  local out = {}
  for _, q in ipairs(doc or {}) do
    out[#out + 1] = {
      name = q.name, vhost = q.vhost, messages = q.messages or 0,
      ready = q.messages_ready or 0, unacked = q.messages_unacknowledged or 0,
      consumers = q.consumers or 0, durable = q.durable == true,
      auto_delete = q.auto_delete == true, arguments = q.arguments or {},
    }
  end
  return out
end

KA.queue_risk_summary = function(rows)
  local out = { total = #rows, message_total = 0, dead_queues = {}, unacked_total = 0,
    consumerless = 0 }
  for _, q in ipairs(rows or {}) do
    out.message_total = out.message_total + (q.messages or 0)
    out.unacked_total = out.unacked_total + (q.unacked or 0)
    if (q.consumers or 0) == 0 then
      out.consumerless = out.consumerless + 1
      if (q.messages or 0) > 0 then
        out.dead_queues[#out.dead_queues + 1] = q.name
      end
    end
  end
  return out
end

KA.tls_client_hello = function()
  local random = string.char(
    0xa1, 0x4f, 0x02, 0x9c, 0x77, 0x1b, 0xd3, 0x40,
    0x55, 0x90, 0xe8, 0x2f, 0x66, 0xab, 0x17, 0xc3,
    0x09, 0xd4, 0x2a, 0x58, 0xb1, 0x3e, 0x88, 0x72,
    0xe6, 0x04, 0xc9, 0xd5, 0x11, 0xfa, 0x6b, 0x20)
  local ciphers = KA.w_i16(0x002f) .. KA.w_i16(0x0035) .. KA.w_i16(0xc02f) .. KA.w_i16(0x009c)
  local body = KA.w_i16(0x0303) .. random .. "\0" .. KA.w_i16(#ciphers) .. ciphers .. "\1\0"
  local handshake = "\x01" .. string.char(math.floor(#body / 65536) % 256,
    math.floor(#body / 256) % 256, #body % 256) .. body
  return "\x16" .. KA.w_i16(0x0301) .. KA.w_i16(#handshake) .. handshake
end

KA.TLS_VERSION_NAMES = {
  [0x0300] = "SSLv3", [0x0301] = "TLS 1.0", [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2", [0x0304] = "TLS 1.3",
}

KA.parse_tls_greeting = function(data)
  local out = { is_tls = false, record_type = nil, version = nil, version_name = nil,
    alert = nil, handshake_type = nil, cipher = nil }
  if type(data) ~= "string" or #data < 6 then
    return out
  end
  out.record_type = data:byte(1)
  out.version = KA.b16(data:sub(2, 3))
  out.version_name = KA.TLS_VERSION_NAMES[out.version]
  if out.record_type == 0x16 then
    out.is_tls = true
    if #data >= 44 and data:byte(6) == 0x02 then
      out.handshake_type = 0x02
      out.version = KA.b16(data:sub(10, 11))
      out.version_name = KA.TLS_VERSION_NAMES[out.version]
      local sid_len = data:byte(44) or 0
      if #data >= 44 + sid_len + 2 then
        out.cipher = KA.b16(data:sub(44 + sid_len + 1, 44 + sid_len + 2))
      end
    end
  elseif out.record_type == 0x15 then
    out.alert = data:byte(6)
    out.is_tls = true
  end
  return out
end

KA.tls_version_grade = function(greeting)
  if not greeting.is_tls or greeting.record_type ~= 0x16 then
    return "none"
  end
  if greeting.version <= 0x0301 then
    return "weak (TLS 1.0-era or older)"
  elseif greeting.version == 0x0302 then
    return "weak (TLS 1.1)"
  end
  return "acceptable (TLS 1.2+)"
end

KA.selftest = function()
  local results = {}
  local failures = 0
  local expect_eq = function(a, b, label)
    if a == b then
      results[#results + 1] = "ok - " .. label
    else
      failures = failures + 1
      results[#results + 1] = "FAIL - " .. label
    end
  end
  expect_eq(KA.b16s(KA.w_i16(-1)), -1, "i16 roundtrip negative")
  expect_eq(KA.b32s(KA.w_i32(-123456)), -123456, "i32 roundtrip negative")
  local frame = KA.kafka_request(18, 0, 1, "t", "")
  expect_eq(#frame, 4 + 11, "kafka frame size")
  expect_eq(KA.b16(frame:sub(5, 6)), 18, "kafka frame api key")
  local resp = KA.kafka_response_parts(KA.w_i32(4) .. KA.w_i32(7) .. "x")
  expect_eq(resp ~= nil and resp.correlation or -1, 7, "kafka response correlation")
  local av = KA.parse_api_versions(KA.w_i16(0) .. KA.w_i32(2) ..
    KA.w_i16(18) .. KA.w_i16(0) .. KA.w_i16(2) .. KA.w_i16(33) .. KA.w_i16(0) .. KA.w_i16(0))
  expect_eq(av.error_code, 0, "apiversions error 0")
  expect_eq(av.version_floor, "2.0.0", "apiversions floor 2.0.0")
  local md_body = KA.w_i32(1) .. KA.w_i32(1) .. KA.kafka_str("b1") .. KA.w_i32(9092) ..
    KA.w_i32(1) .. KA.w_i32(1) .. KA.w_i16(0) .. KA.kafka_str("orders") .. KA.w_i32(1) ..
    KA.w_i16(0) .. KA.w_i32(0) .. KA.w_i32(1) .. KA.w_i32(1) .. KA.w_i32(1) .. KA.w_i32(1)
  local md = KA.parse_metadata(md_body)
  expect_eq(md.brokers[1].host, "b1", "metadata broker host")
  expect_eq(md.brokers[1].port, 9092, "metadata broker port")
  expect_eq(md.topics[1].name, "orders", "metadata topic name")
  expect_eq(md.topics[1].partitions[1].leader, 1, "metadata partition leader")
  local lg = KA.parse_list_groups(KA.w_i16(0) .. KA.w_i32(1) .. KA.kafka_str("g1") .. KA.kafka_str("consumer"))
  expect_eq(lg.groups[1].id, "g1", "listgroups group id")
  local dg_body = KA.w_i32(1) .. KA.w_i16(0) .. KA.kafka_str("g1") .. KA.kafka_str("Stable") ..
    KA.kafka_str("consumer") .. KA.kafka_str("range") .. KA.w_i32(1) ..
    KA.kafka_str("m1") .. KA.kafka_str("c1") .. KA.kafka_str("/10.0.0.1") ..
    KA.w_i32(0) .. KA.w_i32(0)
  local dg = KA.parse_describe_groups(dg_body)
  expect_eq(dg.groups[1].state, "Stable", "describegroups state")
  expect_eq(dg.groups[1].members[1].client_host, "/10.0.0.1", "describegroups member host")
  local tec = KA.parse_topic_error_codes(KA.w_i32(1) .. KA.w_i16(31) .. KA.kafka_str("t"))
  expect_eq(tec[1].error_name, "CLUSTER_AUTHORIZATION_FAILED", "topic error codes name")
  local sh = KA.parse_sasl_handshake(KA.w_i16(0) .. KA.w_i32(2) .. KA.kafka_str("PLAIN") .. KA.kafka_str("SCRAM-SHA-256"))
  expect_eq(sh.mechanisms[2], "SCRAM-SHA-256", "sasl handshake mechs")
  expect_eq(KA.plain_bytes("u", "p"), "\0u\0p", "plain bytes")
  expect_eq(KA.mech_strength({ "PLAIN", "SCRAM-SHA-256" }).strongest, "SCRAM-SHA-256", "mech strength")
  local af = KA.amqp_frame(1, 0, "\0\0\0\0")
  expect_eq(af:byte(#af), 0xCE, "amqp frame end byte")
  expect_eq(KA.b32(af:sub(4, 7)), 4, "amqp frame size field")
  local frames = KA.parse_amqp_frames(af .. KA.amqp_frame(1, 1, "\0\0\0\0"))
  expect_eq(#frames, 2, "amqp frames parse count")
  expect_eq(frames[2].channel, 1, "amqp frame channel")
  local start_payload = KA.w_i16(10) .. KA.w_i16(10) .. "\0\x09" ..
    KA.encode_field_table({ product = "RabbitMQ" }) ..
    KA.w_i32(5) .. "PLAIN" .. KA.w_i32(5) .. "en_US"
  local start = KA.parse_connection_start(start_payload)
  expect_eq(start.major, 0, "amqp start major")
  expect_eq(start.properties.product, "RabbitMQ", "amqp start properties")
  expect_eq(start.mechanisms[1], "PLAIN", "amqp start mechanisms")
  local tune = KA.parse_tune("\0\0\0\0" .. KA.w_i16(2047) .. KA.w_i32(131072) .. KA.w_i16(60))
  expect_eq(tune.frame_max, 131072, "amqp tune frame_max")
  expect_eq(tune.heartbeat, 60, "amqp tune heartbeat")
  local sok = KA.parse_start_ok(KA.w_i16(10) .. KA.w_i16(11) .. KA.encode_field_table({ product = "x" }) ..
    "\5PLAIN" .. KA.w_i32(4) .. "\0u\0p" .. "\5en_US")
  expect_eq(sok.user, "u", "start-ok user extract")
  expect_eq(sok.pass, "p", "start-ok pass extract")
  local close = KA.parse_close(KA.w_i16(10) .. KA.w_i16(50) .. KA.w_i16(403) ..
    KA.kafka_str("ACCESS_REFUSED") .. KA.w_i16(0) .. KA.w_i16(0))
  expect_eq(close.code, 403, "amqp close code")
  expect_eq(KA.close_code_name(403):find("access-refused", 1, true) ~= nil, true, "close code name")
  expect_eq(KA.method_name(10, 30), "connection.tune", "amqp method name")
  local qd = KA.parse_declare_ok(KA.w_i16(50) .. KA.w_i16(11) .. "\1q" .. KA.w_i32(5) .. KA.w_i32(2))
  expect_eq(qd.messages, 5, "declare-ok messages")
  expect_eq(qd.consumers, 2, "declare-ok consumers")
  local http_raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
  local http = KA.parse_http_response(http_raw)
  expect_eq(http.status, 200, "http status parse")
  expect_eq(http.body, "{}", "http body parse")
  local chunked = KA.parse_http_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n")
  expect_eq(chunked.body, "hi", "http chunked decode")
  local ov = KA.parse_overview(KA.json_decode('{"rabbitmq_version":"3.12.14","listeners":[{"protocol":"amqp","port":5672}],"queue_totals":{"messages":42,"messages_ready":18,"messages_unacknowledged":7}}'))
  expect_eq(ov.version, "3.12.14", "overview version")
  expect_eq(ov.queue_totals.messages, 42, "overview queue totals")
  local defs = KA.parse_definitions(KA.json_decode('{"users":[{"name":"guest","tags":"administrator"}],"vhosts":[{"name":"/"}],"permissions":[{}],"queues":[{},{}]}'))
  expect_eq(defs.guest_present, true, "definitions guest present")
  expect_eq(defs.permissions, 1, "definitions permission count")
  local qs = KA.parse_queues(KA.json_decode('[{"name":"q1","messages":9,"consumers":0}]'))
  expect_eq(qs[1].name, "q1", "queues parse name")
  local qsum = KA.queue_risk_summary(qs)
  expect_eq(qsum.dead_queues[1], "q1", "queue risk dead queue")
  expect_eq(KA.json_encode({ a = 1 }) == '{"a":1}', true, "json encode object")
  local greet = KA.parse_tls_greeting("\x16\x03\x01\x00\x2a\x02\x03\x03" .. string.rep("\0", 40))
  expect_eq(greet.is_tls, true, "tls greeting type")
  local hello = KA.tls_client_hello()
  expect_eq(hello:byte(1), 0x16, "client hello record type")
  expect_eq(KA.tls_version_grade({ is_tls = true, record_type = 0x16, version = 0x0301 }),
    "weak (TLS 1.0-era or older)", "tls grade weak")
  expect_eq(#KA.rabbitmq_version_advisories("3.7.10") >= 1, true, "rabbitmq advisories old version")
  expect_eq(#KA.rabbitmq_version_advisories("3.13.0"), 0, "rabbitmq advisories new version")
  expect_eq(#KA.kafka_version_advisories("0.9") >= 1, true, "kafka advisories old")
  return failures == 0, table.concat(results, "\n")
end

KAT = {}

function KAT.session_new(host, port, args)
  local s = {
    host = host, port = port,
    socket = nmap.new_socket(),
    requests = 0,
    audit_log = {},
    budget = {
      timeout = (args and args.timeout) or 8,
      maxrequests = (args and args.maxrequests) or 48,
    },
  }
  s.socket:set_timeout(s.budget.timeout * 1000)
  return s
end

function KAT.audit(sess, event, detail)
  sess.audit_log[#sess.audit_log + 1] = {
    event = event, detail = detail,
  }
end

function KAT.connect(sess)
  if sess.connected then
    return true
  end
  local ok, err = sess.socket:connect(sess.host, sess.port)
  if not ok then
    return false, "connect failed: " .. tostring(err or "unknown")
  end
  sess.connected = true
  KAT.audit(sess, "connect", sess.host.ip .. ":" .. tostring(sess.port.number))
  return true
end

function KAT.close(sess)
  if sess ~= nil and sess.socket ~= nil then
    sess.socket:close()
  end
  if sess ~= nil then
    sess.connected = false
  end
end

function KAT.status_open(status)
  return status == "open" or status == "open|filtered"
end

function KAT.kafka_exchange(host, port, args, frame)
  local sess = KAT.session_new(host, port, args)
  local ok, err = KAT.connect(sess)
  if not ok then
    KAT.close(sess)
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    KAT.close(sess)
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local sent, serr = sess.socket:send(frame)
  if not sent then
    KAT.close(sess)
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  KAT.audit(sess, "send", #frame .. "B kafka frame")
  local collected = ""
  local spins = 0
  while spins < 8 do
    spins = spins + 1
    local okr, chunk = sess.socket:receive()
    if not okr then
      break
    end
    collected = collected .. chunk
    if #collected >= 4 then
      local size = KA.b32(collected:sub(1, 4))
      if #collected >= 4 + size then
        break
      end
    end
  end
  KAT.close(sess)
  if collected == "" then
    return nil, "empty kafka response"
  end
  KAT.audit(sess, "recv", #collected .. "B kafka response")
  local parts = KA.kafka_response_parts(collected)
  if parts == nil then
    return nil, "unparseable kafka response"
  end
  return parts, collected
end

function KAT.amqp_session(host, port, args)
  local sess = KAT.session_new(host, port, args)
  sess.amqp_stage = 0
  return sess
end

function KAT.amqp_send(sess, bytes)
  local ok, err = KAT.connect(sess)
  if not ok then
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local sent, serr = sess.socket:send(bytes)
  if not sent then
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  KAT.audit(sess, "send", #bytes .. "B amqp")
  local collected = ""
  local spins = 0
  while spins < 8 do
    spins = spins + 1
    local okr, chunk = sess.socket:receive()
    if not okr then
      break
    end
    collected = collected .. chunk
    if #collected >= 8 then
      local size = KA.b32(collected:sub(4, 7))
      if #collected >= 8 + size then
        break
      end
    end
  end
  if collected == "" then
    return nil, "empty amqp response"
  end
  KAT.audit(sess, "recv", #collected .. "B amqp")
  return collected
end

function KAT.amqp_handshake(host, port, args, opts)
  opts = opts or {}
  local out = { protocol_ok = false, start = nil, tune = nil, opened = false,
    close = nil, stage_reached = 0, error = nil }
  local sess = KAT.amqp_session(host, port, args)
  local resp, err = KAT.amqp_send(sess, KA.AMQP_HEADER)
  if resp == nil then
    out.error = err
    KAT.close(sess)
    return out, sess
  end
  out.stage_reached = 1
  local frames = KA.parse_amqp_frames(resp)
  for _, f in ipairs(frames) do
    local cls, mid = KA.method_ids(f.payload)
    if cls == 10 and mid == 10 then
      out.protocol_ok = true
      out.start = KA.parse_connection_start(f.payload)
    end
  end
  if not out.protocol_ok or out.start == nil then
    KAT.close(sess)
    return out, sess
  end
  out.stage_reached = 2
  local user = opts.user or "guest"
  local pass = opts.pass or "guest"
  resp, err = KAT.amqp_send(sess, KA.amqp_frame(1, 0,
    KA.w_i16(10) .. KA.w_i16(11) .. KA.start_ok_payload("PLAIN", KA.plain_response(user, pass))))
  if resp == nil then
    out.error = err
    KAT.close(sess)
    return out, sess
  end
  frames = KA.parse_amqp_frames(resp)
  for _, f in ipairs(frames) do
    local cls, mid = KA.method_ids(f.payload)
    if cls == 10 and mid == 30 then
      out.tune = KA.parse_tune(f.payload)
      out.stage_reached = 3
    elseif cls == 10 and mid == 50 then
      out.close = KA.parse_close(f.payload)
      out.stage_reached = 3
    end
  end
  if out.tune == nil then
    KAT.close(sess)
    return out, sess
  end
  resp, err = KAT.amqp_send(sess, KA.amqp_frame(1, 0,
    KA.w_i16(10) .. KA.w_i16(40) .. KA.open_payload(opts.vhost or "/")))
  if resp == nil then
    out.error = err
    KAT.close(sess)
    return out, sess
  end
  frames = KA.parse_amqp_frames(resp)
  for _, f in ipairs(frames) do
    local cls, mid = KA.method_ids(f.payload)
    if cls == 10 and mid == 41 then
      out.opened = true
      out.stage_reached = 4
    elseif cls == 10 and mid == 50 then
      out.close = KA.parse_close(f.payload)
      out.stage_reached = 4
    end
  end
  KAT.close(sess)
  return out, sess
end

function KAT.amqp_channel_probe(host, port, args, opts)
  local out = { channel_opened = false, declare = nil, close = nil, error = nil }
  local hs, sess = KAT.amqp_handshake(host, port, args, opts)
  if not hs.opened then
    out.error = hs.error or "connection not opened"
    return out, hs
  end
  local resp, err = KAT.amqp_send(sess, KA.amqp_frame(1, 1,
    KA.w_i16(20) .. KA.w_i16(10) .. KA.channel_open_payload()))
  if resp == nil then
    out.error = err
    return out, hs
  end
  for _, f in ipairs(KA.parse_amqp_frames(resp)) do
    local cls, mid = KA.method_ids(f.payload)
    if cls == 20 and mid == 11 then
      out.channel_opened = true
    elseif cls == 20 and mid == 40 then
      out.close = KA.parse_close(f.payload)
    elseif cls == 10 and mid == 50 then
      out.close = KA.parse_close(f.payload)
    end
  end
  if not out.channel_opened then
    return out, hs
  end
  resp, err = KAT.amqp_send(sess, KA.amqp_frame(1, 1,
    KA.w_i16(50) .. KA.w_i16(10) .. KA.queue_declare_passive_payload(opts.queue or KA.SENTINEL_QUEUE)))
  if resp == nil then
    out.error = err
    return out, hs
  end
  for _, f in ipairs(KA.parse_amqp_frames(resp)) do
    local cls, mid = KA.method_ids(f.payload)
    if cls == 50 and mid == 11 then
      out.declare = KA.parse_declare_ok(f.payload)
    elseif cls == 20 and mid == 40 or cls == 10 and mid == 50 then
      out.close = KA.parse_close(f.payload)
    end
  end
  KAT.close(sess)
  return out, hs
end

function KAT.http_request(sess, method, path, body)
  local ok, err = KAT.connect(sess)
  if not ok then
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local req = method .. " " .. path .. " HTTP/1.1\r\nHost: " ..
    tostring(sess.host.ip or "target") .. "\r\nUser-Agent: nse-audit\r\n" ..
    "Accept: application/json\r\nConnection: close\r\n"
  if body ~= nil then
    req = req .. "Content-Type: application/json\r\nContent-Length: " .. #body .. "\r\n"
  end
  req = req .. "\r\n" .. (body or "")
  local sent, serr = sess.socket:send(req)
  if not sent then
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  KAT.audit(sess, "send", method .. " " .. path)
  local collected = ""
  local spins = 0
  while spins < 8 do
    spins = spins + 1
    local okr, chunk = sess.socket:receive()
    if not okr then
      break
    end
    collected = collected .. chunk
    if collected:find("\r\n0\r\n") or collected:find("</html>") or
      (collected:find("Content%-Length:") and #collected > 40) then
      break
    end
  end
  if collected == "" then
    return nil, "empty http response"
  end
  KAT.audit(sess, "recv", #collected .. "B http")
  return KA.parse_http_response(collected)
end

function KAT.raw_exchange(host, port, args, payload)
  local sess = KAT.session_new(host, port, args)
  local ok, err = KAT.connect(sess)
  if not ok then
    KAT.close(sess)
    return nil, err
  end
  sess.requests = sess.requests + 1
  if payload ~= nil and #payload > 0 then
    local sent = sess.socket:send(payload)
    if not sent then
      KAT.close(sess)
      return nil, "send failed"
    end
    KAT.audit(sess, "send", #payload .. "B raw")
  end
  local collected = ""
  local okr, chunk = sess.socket:receive()
  if okr then
    collected = chunk
  end
  KAT.close(sess)
  if collected == "" then
    return nil, "no response"
  end
  KAT.audit(sess, "recv", #collected .. "B raw")
  return collected
end

function KAT.tls_probe(host, port, args)
  local raw, err = KAT.raw_exchange(host, port, args, KA.tls_client_hello())
  if raw == nil then
    return { is_tls = false, error = err }
  end
  return KA.parse_tls_greeting(raw)
end

local findings = {}

local function add_finding(severity, detail, extra)
  local entry = {
    severity = severity,
    weight = SEVERITY[severity] or SEVERITY.INFO,
    detail = detail,
    path = extra and extra.path,
    subject = extra and extra.subject,
    confidence = extra and extra.confidence or "high",
    evidence = extra and extra.evidence,
  }
  if entry.confidence == "low" then
    entry.weight = math.max(0, math.floor(entry.weight / 2))
  end
  table.insert(findings, entry)
  return entry
end

local function reset_findings()
  findings = {}
end

local function dedupe_findings()
  local unique = {}
  local index = {}
  local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  for _, finding in ipairs(findings) do
    local key = tostring(finding.subject or "-") .. "|" .. finding.severity .. "|" .. finding.detail
    if not index[key] then
      index[key] = {
        severity = finding.severity,
        weight = finding.weight,
        subject = finding.subject,
        detail = finding.detail,
        confidence = finding.confidence,
        paths = {},
        evidence = {},
      }
      table.insert(unique, index[key])
    end
    local entry = index[key]
    if finding.path then
      local seen_path = false
      for _, existing in ipairs(entry.paths) do
        if existing == finding.path then
          seen_path = true
        end
      end
      if not seen_path then
        table.insert(entry.paths, finding.path)
      end
    end
    if finding.evidence then
      local sample = truncate(tostring(finding.evidence), 120)
      local seen_evidence = false
      for _, existing in ipairs(entry.evidence) do
        if existing == sample then
          seen_evidence = true
        end
      end
      if not seen_evidence and #entry.evidence < 4 then
        table.insert(entry.evidence, sample)
      end
    end
    counts[finding.severity] = (counts[finding.severity] or 0) + 1
  end

  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  table.sort(unique, function(a, b)
    local first = order[a.severity] or 9
    local second = order[b.severity] or 9
    if first ~= second then
      return first < second
    end
    if a.weight ~= b.weight then
      return a.weight > b.weight
    end
    return tostring(a.detail) < tostring(b.detail)
  end)

  return unique, counts
end

local function weighted_score(unique)
  local score = 0
  for _, finding in ipairs(unique) do
    local multiplier = 1
    local path_count = #(finding.paths or {})
    if path_count > 1 then
      multiplier = multiplier + math.min(path_count - 1, 5) * 0.1
    end
    score = score + (finding.weight or 0) * multiplier
  end
  return math.floor(score + 0.5)
end

local function render_findings(unique, include_info)
  local rendered = {}
  for _, finding in ipairs(unique) do
    if finding.severity ~= "INFO" or include_info then
      local line = string.format("[%s] %s", finding.severity, finding.detail)
      if finding.subject and finding.subject ~= "-" then
        line = line .. " (" .. tostring(finding.subject) .. ")"
      end
      if finding.paths and #finding.paths > 0 then
        local shown = finding.paths
        if #shown > 3 then
          shown = { shown[1], shown[2], string.format("+%d more", #finding.paths - 2) }
        end
        line = line .. " [paths: " .. table.concat(shown, ", ") .. "]"
      end
      if finding.evidence and #finding.evidence > 0 then
        line = line .. " [evidence: " .. table.concat(finding.evidence, " | ") .. "]"
      end
      if finding.confidence == "low" then
        line = line .. " [low confidence]"
      end
      table.insert(rendered, line)
    end
  end
  return rendered
end

local function new_output(risk, status)
  local out = stdnse.output_table()
  out["Risk Level"] = risk
  out["Status"] = status
  return out
end

local function finish_output(out, unique, counts, extra_sections)
  local rendered = render_findings(unique, false)
  if #rendered == 0 then
    table.insert(rendered, "no weaknesses detected by this audit")
  end
  out["Findings"] = rendered
  out["Severity counts"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
    counts.CRITICAL or 0, counts.HIGH or 0, counts.MEDIUM or 0,
    counts.LOW or 0, counts.INFO or 0)
  out["Weighted score"] = tostring(weighted_score(unique))
  for _, section in ipairs(extra_sections or {}) do
    if section.value ~= nil then
      out[section.key] = section.value
    end
  end
  out["Requests issued"] = tostring(state.requests)
  if state.rate_limited > 0 then
    out["Rate limited responses"] = tostring(state.rate_limited)
  end
  if state.errors > 0 then
    out["Transport errors"] = tostring(state.errors)
  end
  return out
end

local function ka_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - Kafka/RabbitMQ audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The messaging audit did not complete against this endpoint", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function bump_counters()
  local bump = function(fn)
    return function(...)
      state.requests = state.requests + 1
      return fn(...)
    end
  end
  KAT.kafka_exchange = bump(KAT.kafka_exchange)
  KAT.amqp_handshake = bump(KAT.amqp_handshake)
  KAT.amqp_channel_probe = bump(KAT.amqp_channel_probe)
  KAT.http_request = bump(KAT.http_request)
  KAT.raw_exchange = bump(KAT.raw_exchange)
  KAT.tls_probe = bump(KAT.tls_probe)
end

local KAFKA_REMEDIATION_BASE = {
  lockdown = "Restrict 9092 to application networks; interpose SASL + TLS on every listener.",
  audit = "Re-run this audit after broker configuration changes and after ACL tightening.",
}

local function run_audit(host, port, args)
  local sections = {}
  bump_counters()
  local hs = KAT.amqp_handshake(host, port, args,
    { user = "guest", pass = "guest", vhost = "/" })
  if hs.error ~= nil and not hs.protocol_ok then
    return ka_incomplete(hs.error, sections, "anonymous-login",
      "no connection.start answer")
  end
  sections[#sections + 1] = { key = "Login Stage", value = {
    protocol_ok = hs.protocol_ok,
    broker_version = hs.start and hs.start.properties.version or "unknown",
    mechanism = "PLAIN",
    credentials = "guest/guest (RabbitMQ defaults; single attempt)",
    tune_received = hs.tune ~= nil,
    tune = hs.tune,
  } }
  local channel_rows = {}
  if hs.opened then
    local probe = KAT.amqp_channel_probe(host, port, args,
      { user = "guest", pass = "guest", queue = KA.SENTINEL_QUEUE })
    channel_rows[#channel_rows + 1] = {
      stage = "channel.open + passive queue.declare on sentinel",
      channel_opened = probe.channel_opened,
      declare = probe.declare,
      close_code = probe.close and probe.close.code or nil,
      close_meaning = probe.close and KA.close_code_name(probe.close.code) or nil,
    }
    sections[#sections + 1] = { key = "Post-Login Capability Probe", value = channel_rows }
  end
  local close_row = {
    connection_close_seen = hs.close ~= nil,
    close_code = hs.close and hs.close.code or nil,
    close_meaning = hs.close and KA.close_code_name(hs.close.code) or nil,
    close_text = hs.close and hs.close.text or nil,
  }
  sections[#sections + 1] = { key = "Broker Response", value = close_row }
  local status_text
  if hs.opened then
    status_text = "VULNERABLE - anonymous/default credentials grant a working AMQP connection"
    add_finding("CRITICAL", "RabbitMQ accepts default guest credentials from the network", {
      subject = "listener " .. tostring(port.number),
      evidence = "connection.open-ok for vhost / with guest/guest; tune: " ..
        tostring(hs.tune and hs.tune.frame_max or "-"),
      confidence = "high",
    })
    KAFKA_REMEDIATION_BASE["1. Remove"] = "Delete or lock the guest user, set loopback_users.guest = true and create named application accounts."
    KAFKA_REMEDIATION_BASE["2. Vhosts"] = "Review vhost permissions; / should not be world-accessible."
  elseif hs.close ~= nil and hs.close.code == 403 then
    status_text = "SECURE - login refused with ACCESS_REFUSED"
    add_finding("INFO", "Default credentials rejected", {
      subject = "listener " .. tostring(port.number),
      evidence = "connection.close 403 during connection.start-ok",
      confidence = "high",
    })
    KAFKA_REMEDIATION_BASE["1. Maintain"] = "Keep default credentials disabled; audit user list quarterly for stale accounts."
  else
    status_text = "INFO - login stage inconclusive"
    add_finding("INFO", "Handshake ended without an open connection", {
      subject = "listener " .. tostring(port.number),
      evidence = "stage_reached=" .. tostring(hs.stage_reached) ..
        " close=" .. tostring(hs.close and hs.close.code),
      confidence = "medium",
    })
  end
  sections[#sections + 1] = { key = "Remediation", value = KAFKA_REMEDIATION_BASE }
  local out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()
seed_random(port)

return run_audit(host, port, args)

end
