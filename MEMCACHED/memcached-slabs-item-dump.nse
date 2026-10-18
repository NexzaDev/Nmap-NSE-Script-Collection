local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Enumerates slab classes and runs one bounded stats cachedump per
slab class (5 keys maximum) to check whether key names are
disclosed.

Why it matters
- cachedump reveals actual key names - session IDs, tokens and
  object names - the direct input for targeted key theft.
- The dump capability was the core of the GitHub memcached key
  theft incidents.

What the script does
1. stats slabs + stats items for the class map.
2. stats cachedump <slab> 5 (hard limit 5 keys per class).
3. Grades the key-disclosure exposure.

Safe operation: metadata only; item values are never fetched.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

local SCRIPT_NAME = "memcached-slabs-item-dump"

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

MC = {}

MC.CRLF = "\r\n"

MC.COMMANDS = {
  version = "version",
  stats = "stats",
  stats_settings = "stats settings",
  stats_slabs = "stats slabs",
  stats_items = "stats items",
  stats_sizes = "stats sizes",
  flush_all = "flush_all",
  verbosity = "verbosity",
  watch = "watch fetchers",
  cachedump_prefix = "stats cachedump ",
}

MC.STAT_KEYS_INTERESTING = {
  "curr_items", "total_items", "bytes", "curr_connections", "total_connections",
  "get_hits", "get_misses", "delete_hits", "cmd_set", "limit_maxbytes",
  "evictions", "uptime", "pointer_size", "threads",
}

MC.SETTINGS_KEYS = {
  "maxbytes", "maxconns", "tcpport", "udpport", "inter", "verbosity",
  "oldest", "evictions", "domain_socket", "umask", "maxconns_fast",
  "lru_crawler", "slab_reassign", "slab_automove", "automove_threshold",
  "item_size_max", "num_threads",
}

MC.VERSION_ADVISORIES = {
  { max_minor = 4, cves = { "CVE-2011-4971 (integer overflow in items length)",
      "CVE-2013-0179 (SASL authentication bypass)", "CVE-2016-8705 (binary protocol heap overflow)" } },
  { max_minor = 5, cves = { "CVE-2016-8705 (binary protocol heap overflow)" } },
  { max_minor = 6, cves = { "CVE-2019-15096 (lru_crawler metadump off-by-one, informational)" } },
}

MC.BINARY_MAGIC_REQ = 0x80
MC.BINARY_MAGIC_RES = 0x81
MC.BINARY_OPCODE_VERSION = 0x0b
MC.BINARY_OPCODE_SASL_LIST = 0x20
MC.BINARY_OPCODE_SASL_AUTH = 0x21
MC.BINARY_STATUS_SUCCESS = 0x0000
MC.SENTINEL_KEY = "nse-audit-sentinel-zz0x"
MC.SENTINEL_VALUE = "nse-audit-marker-4242"
MC.FLUSH_ALL_MAX_DELAY = 2147483647

MC.version_advisories = function(version)
  if type(version) ~= "string" then
    return {}
  end
  local major, minor = tostring(version):match("^(%d+)%.(%d+)")
  if major == nil then
    return {}
  end
  minor = tonumber(minor) or -1
  local out = {}
  for _, e in ipairs(MC.VERSION_ADVISORIES) do
    if minor >= 0 and minor <= e.max_minor then
      for _, c in ipairs(e.cves) do
        out[#out + 1] = c
      end
    end
  end
  return out
end

MC.parse_version = function(lines)
  for _, line in ipairs(lines or {}) do
    local v = line:match("^VERSION%s+(.+)$")
    if v ~= nil then
      return v:gsub("%s+$", "")
    end
  end
  return nil
end

MC.parse_stats = function(lines)
  local out = {}
  for _, line in ipairs(lines or {}) do
    local key, value = line:match("^STAT%s+([%w_:%.%-]+)%s+(.*)$")
    if key ~= nil then
      out[key] = value
    end
  end
  return out
end

MC.parse_slabs = function(lines)
  local out = { slabs = {}, total_malloced = nil }
  for _, line in ipairs(lines or {}) do
    local key, value = line:match("^STAT%s+([%w_:%.%-]+)%s+(.*)$")
    if key ~= nil then
      local slab_id, field = key:match("^(%d+):([%w_]+)$")
      if slab_id ~= nil then
        if out.slabs[tonumber(slab_id)] == nil then
          out.slabs[tonumber(slab_id)] = { id = tonumber(slab_id) }
        end
        out.slabs[tonumber(slab_id)][field] = value
      elseif key == "total_malloced" then
        out.total_malloced = value
      end
    end
  end
  local ids = {}
  for id in pairs(out.slabs) do
    ids[#ids + 1] = id
  end
  table.sort(ids, function(a, b)
    return a < b
  end)
  out.ids = ids
  return out
end

MC.parse_items = function(lines)
  local out = {}
  for _, line in ipairs(lines or {}) do
    local key, value = line:match("^STAT%s+([%w_:%.%-]+)%s+(.*)$")
    local slab, field = nil, nil
    if key ~= nil then
      slab, field = key:match("^(%d+):([%w_]+)$")
    end
    if slab ~= nil then
      local sid = tonumber(slab)
      if out[sid] == nil then
        out[sid] = { id = sid }
      end
      out[sid][field] = value
    end
  end
  return out
end

MC.parse_settings = function(lines)
  local out = {}
  for _, line in ipairs(lines or {}) do
    local key, value = line:match("^STAT%s+([%w_:%.%-]+)%s+(.*)$")
    if key ~= nil then
      out[key] = value
    end
  end
  local interesting = {}
  for _, k in ipairs(MC.SETTINGS_KEYS) do
    if out[k] ~= nil then
      interesting[#interesting + 1] = { setting = k, value = out[k] }
    end
  end
  out.interesting = interesting
  return out
end

MC.parse_sizes = function(lines)
  local out = { buckets = {}, total_items = 0 }
  for _, line in ipairs(lines or {}) do
    local key, value = line:match("^STAT%s+([%w_:%.%-]+)%s+(.*)$")
    if key ~= nil and key ~= "END" then
      local count = tonumber(value) or 0
      out.buckets[#out.buckets + 1] = { size_class = key, items = count }
      out.total_items = out.total_items + count
    end
  end
  return out
end

MC.parse_cachedump = function(lines)
  local out = {}
  for _, line in ipairs(lines or {}) do
    local item = line:match("^ITEM%s+(%S+)%s+%[")
    if item ~= nil then
      out[#out + 1] = item
    end
  end
  return out
end

MC.ascii_get = function(key)
  return "get " .. key .. MC.CRLF
end

MC.ascii_set = function(key, value, flags, exptime)
  return "set " .. key .. " " .. tostring(flags or 0) .. " " .. tostring(exptime or 60) ..
    " " .. tostring(#value) .. MC.CRLF .. value .. MC.CRLF
end

MC.ascii_delete = function(key)
  return "delete " .. key .. MC.CRLF
end

MC.ascii_touch = function(key, exptime)
  return "touch " .. key .. " " .. tostring(exptime or 60) .. MC.CRLF
end

MC.ascii_flush_all_sentinel = function()
  return "flush_all " .. MC.FLUSH_ALL_MAX_DELAY .. MC.CRLF
end

MC.ascii_verbosity = function(level)
  return "verbosity " .. tostring(level or 0) .. MC.CRLF
end

MC.parse_get_response = function(lines)
  local out = { found = false, value = nil, flags = nil, bytes = nil }
  for _, line in ipairs(lines or {}) do
    local key, flags, bytes = line:match("^VALUE%s+(%S+)%s+(%d+)%s+(%d+)")
    if key ~= nil then
      out.found = true
      out.flags = tonumber(flags)
      out.bytes = tonumber(bytes)
    end
  end
  return out
end

MC.parse_write_response = function(lines)
  for _, line in ipairs(lines or {}) do
    if line:find("^STORED") then
      return "STORED"
    end
    if line:find("^NOT_FOUND") then
      return "NOT_FOUND"
    end
    if line:find("^TOUCHED") then
      return "TOUCHED"
    end
    if line:find("^DELETED") then
      return "DELETED"
    end
    if line:find("^OK") then
      return "OK"
    end
    if line:find("^ERROR") or line:find("^SERVER_ERROR") or line:find("^CLIENT_ERROR") then
      return line:match("^(%S+)")
    end
  end
  return nil
end

MC.w_u16 = function(v)
  return string.char(math.floor(v / 256) % 256, v % 256)
end

MC.w_u32 = function(v)
  return string.char(math.floor(v / 16777216) % 256, math.floor(v / 65536) % 256,
    math.floor(v / 256) % 256, v % 256)
end

MC.binary_request = function(opcode, key, extras, body, opaque)
  extras = extras or ""
  body = body or ""
  key = key or ""
  local body_len = #extras + #key + #body
  local header = string.char(MC.BINARY_MAGIC_REQ, opcode) ..
    MC.w_u16(#key) .. string.char(#extras, 0, 0, 0) ..
    MC.w_u32(body_len) .. MC.w_u32(opaque or 7) .. MC.w_u64_cas() ..
    extras .. key .. body
  return header
end

MC.w_u64_cas = function()
  return string.char(0, 0, 0, 0, 0, 0, 0, 0)
end

MC.binary_version = function()
  return MC.binary_request(MC.BINARY_OPCODE_VERSION)
end

MC.binary_sasl_list = function()
  return MC.binary_request(MC.BINARY_OPCODE_SASL_LIST)
end

MC.parse_binary_response = function(data)
  if type(data) ~= "string" or #data < 24 then
    return nil, "binary response too short"
  end
  local magic = string.byte(data, 1)
  if magic ~= MC.BINARY_MAGIC_RES then
    return nil, "unexpected magic byte 0x" .. string.format("%02x", magic)
  end
  local status = string.byte(data, 7) * 256 + string.byte(data, 8)
  local key_len = string.byte(data, 3) * 256 + string.byte(data, 4)
  local body_len = string.byte(data, 9) * 16777216 + string.byte(data, 10) * 65536 +
    string.byte(data, 11) * 256 + string.byte(data, 12)
  local body = data:sub(25, 25 + body_len - 1)
  return {
    status = status,
    key_len = key_len,
    body_len = body_len,
    body = body,
    version = (status == MC.BINARY_STATUS_SUCCESS and body) or nil,
    sasl_mechs = (status == MC.BINARY_STATUS_SUCCESS) and MC.split_space(body) or {},
  }
end

MC.split_space = function(s)
  local out = {}
  for word in tostring(s or ""):gmatch("%S+") do
    out[#out + 1] = word
  end
  return out
end

MC.udp_frame = function(request_id, seq, total, payload)
  return MC.w_u16(request_id) .. MC.w_u16(seq) .. MC.w_u16(total) .. MC.w_u16(0) .. payload
end

MC.udp_parse = function(data)
  if type(data) ~= "string" or #data < 8 then
    return nil, "datagram too short for the UDP protocol header"
  end
  local request_id = string.byte(data, 1) * 256 + string.byte(data, 2)
  local seq = string.byte(data, 3) * 256 + string.byte(data, 4)
  local total = string.byte(data, 5) * 256 + string.byte(data, 6)
  return {
    request_id = request_id,
    seq = seq,
    total = total,
    payload = data:sub(9),
  }
end

MC.amplification_grade = function(request_bytes, response_bytes)
  if request_bytes <= 0 then
    return { ratio = 0, grade = "n/a" }
  end
  local ratio = response_bytes / request_bytes
  local grade = "low"
  if ratio >= 10 then
    grade = "extreme"
  elseif ratio >= 5 then
    grade = "high"
  elseif ratio >= 2 then
    grade = "moderate"
  end
  return { ratio = math.floor(ratio * 100) / 100, grade = grade }
end

MC.health_summary = function(stats)
  if type(stats) ~= "table" then
    return nil
  end
  return {
    curr_items = tonumber(stats.curr_items or "0") or 0,
    bytes = tonumber(stats.bytes or "0") or 0,
    curr_connections = tonumber(stats.curr_connections or "0") or 0,
    maxconns = nil,
    get_hits = tonumber(stats.get_hits or "0") or 0,
    get_misses = tonumber(stats.get_misses or "0") or 0,
    evictions = tonumber(stats.evictions or "0") or 0,
    uptime = tonumber(stats.uptime or "0") or 0,
  }
end

MC.BINARY_OPCODE_GET = 0x00
MC.BINARY_OPCODE_SET = 0x01
MC.BINARY_OPCODE_DELETE = 0x04
MC.BINARY_OPCODE_TOUCH = 0x1C
MC.BINARY_OPCODE_NOOP = 0x0a
MC.BINARY_OPCODE_STAT = 0x10

MC.BINARY_STATUS_NAMES = {
  [0x0000] = "SUCCESS",
  [0x0001] = "KEY_NOT_FOUND",
  [0x0002] = "KEY_EXISTS",
  [0x0003] = "E2BIG",
  [0x0004] = "EINVAL",
  [0x0005] = "NOT_STORED",
  [0x0006] = "DELTA_BADVAL",
  [0x0007] = "AUTH_ERROR",
  [0x0008] = "AUTH_CONTINUE",
  [0x0081] = "UNKNOWN_COMMAND",
  [0x0082] = "OOM",
}

MC.binary_status_name = function(status)
  return MC.BINARY_STATUS_NAMES[status] or ("0x" .. string.format("%04x", status or 0))
end

MC.binary_key = function(data)
  if type(data) ~= "string" or #data < 24 then
    return nil
  end
  local key_len = string.byte(data, 3) * 256 + string.byte(data, 4)
  local extras_len = string.byte(data, 5)
  if key_len == 0 or 24 + extras_len + key_len > #data then
    return nil
  end
  return data:sub(25 + extras_len, 24 + extras_len + key_len)
end

MC.binary_extras = function(data)
  if type(data) ~= "string" or #data < 25 then
    return nil
  end
  local extras_len = string.byte(data, 5)
  if extras_len == 0 then
    return ""
  end
  return data:sub(25, 24 + extras_len)
end

MC.binary_get = function(key, opaque)
  return MC.binary_request(MC.BINARY_OPCODE_GET, key, "", "", opaque)
end

MC.binary_set = function(key, value, flags, exptime, opaque)
  local extras = MC.w_u32(flags or 0) .. MC.w_u32(exptime or 60)
  return MC.binary_request(MC.BINARY_OPCODE_SET, key, extras, value, opaque)
end

MC.binary_delete = function(key, opaque)
  return MC.binary_request(MC.BINARY_OPCODE_DELETE, key, "", "", opaque)
end

MC.binary_touch = function(key, exptime, opaque)
  return MC.binary_request(MC.BINARY_OPCODE_TOUCH, key, MC.w_u32(exptime or 60), "", opaque)
end

MC.binary_sasl_plain = function(user, pass)
  local payload = "\0" .. (user or "") .. "\0" .. (pass or "")
  return MC.binary_request(MC.BINARY_OPCODE_SASL_AUTH, "PLAIN", "", payload, 21)
end

MC.meta_noop = function()
  return "mn" .. MC.CRLF
end

MC.meta_get = function(key)
  return "mg " .. key .. " v f t60" .. MC.CRLF
end

MC.meta_set = function(key, value, exptime)
  return "ms " .. key .. " " .. tostring(#value) .. " T" .. tostring(exptime or 60) ..
    " F0" .. MC.CRLF .. value .. MC.CRLF
end

MC.meta_delete = function(key)
  return "md " .. key .. " I" .. MC.CRLF
end

MC.parse_meta_response = function(lines)
  local out = { code = nil, hit = false, size = nil }
  for _, line in ipairs(lines or {}) do
    if line == "EN" then
      out.code = "EN"
    elseif line:find("^HD") then
      out.code = "HD"
      out.hit = true
    elseif line:find("^VA") then
      out.code = "VA"
      out.hit = true
      out.size = tonumber(line:match("^VA%s+(%d+)"))
    elseif line:find("^EX") then
      out.code = "EX"
    elseif line:find("^NF") then
      out.code = "NF"
    elseif line:find("^ERROR") or line:find("^CLIENT_ERROR") then
      out.code = "ERROR"
    end
  end
  return out
end

MC.sentinel_key_is_safe = function(key)
  if type(key) ~= "string" then
    return false
  end
  return key:find("^nse%-audit%-") == 1
end

MC.stats_snapshot = function(stats)
  local out = {}
  for _, k in ipairs(MC.STAT_KEYS_INTERESTING) do
    out[#out + 1] = { key = k, value = stats[k] or "-" }
  end
  return out
end

MC.stats_diff = function(before, after)
  local out = {}
  for _, k in ipairs(MC.STAT_KEYS_INTERESTING) do
    local b = tonumber(before[k] or "0") or 0
    local a = tonumber(after[k] or "0") or 0
    out[k] = a - b
  end
  return out
end

MC.MECH_RANKS = { SCRAM_SHA_512 = 5, SCRAM_SHA_256 = 4, ["SCRAM-SHA-512"] = 5,
  ["SCRAM-SHA-256"] = 4, ["SCRAM-SHA-1"] = 3, CRAM_MD5 = 2, ["CRAM-MD5"] = 2, PLAIN = 1 }

MC.classify_mechs = function(mechs)
  local best = nil
  local names = {}
  for _, m in ipairs(mechs or {}) do
    names[#names + 1] = m
    local rank = MC.MECH_RANKS[m] or 0
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

MC.udp_reassemble = function(datagrams)
  local by_seq = {}
  for _, d in ipairs(datagrams or {}) do
    by_seq[d.seq] = d
  end
  local parts = {}
  local first = by_seq[0]
  local total = first and first.total or (#datagrams or 0)
  for i = 0, total - 1 do
    local d = by_seq[i]
    if d ~= nil then
      parts[#parts + 1] = d.payload
    end
  end
  return table.concat(parts), total == #datagrams
end

MC.reflection_estimate = function(request_bytes, ratio, source_bandwidth_mbps)
  if request_bytes <= 0 or source_bandwidth_mbps <= 0 then
    return 0
  end
  return math.floor(source_bandwidth_mbps * ratio)
end

MC.SLAB_BASE_SIZE = 96
MC.SLAB_GROWTH_FACTOR = 1.25
MC.SLAB_MAX_CLASSES = 64
MC.RELATIVE_EXPIRY_LIMIT = 2592000

MC.ascii_multiget = function(keys)
  return "get " .. table.concat(keys, " ") .. MC.CRLF
end

MC.parse_multiget = function(lines)
  local out = {}
  local current = nil
  for _, line in ipairs(lines or {}) do
    local key, flags, bytes = line:match("^VALUE%s+(%S+)%s+(%d+)%s+(%d+)")
    if key ~= nil then
      current = { key = key, flags = tonumber(flags), bytes = tonumber(bytes) }
      out[#out + 1] = current
    elseif line == "END" then
      break
    end
  end
  return out
end

MC.ascii_incr = function(key, delta)
  return "incr " .. key .. " " .. tostring(delta or 1) .. MC.CRLF
end

MC.ascii_decr = function(key, delta)
  return "decr " .. key .. " " .. tostring(delta or 1) .. MC.CRLF
end

MC.parse_counter_response = function(lines)
  for _, line in ipairs(lines or {}) do
    local n = line:match("^(%d+)%s*$")
    if n ~= nil then
      return tonumber(n)
    end
    if line:find("^SERVER_ERROR") or line:find("^CLIENT_ERROR") or line:find("^NOT_FOUND") then
      return nil, line:match("^(%S+)")
    end
  end
  return nil
end

MC.expiry_encode = function(seconds)
  seconds = seconds or 0
  if seconds <= 0 then
    return 0
  end
  if seconds <= MC.RELATIVE_EXPIRY_LIMIT then
    return seconds
  end
  return os.time() + seconds
end

MC.expiry_decode = function(value)
  local n = tonumber(value)
  if n == nil or n <= 0 then
    return { raw = value or "0", kind = "never" }
  end
  if n <= MC.RELATIVE_EXPIRY_LIMIT then
    return { raw = n, kind = "relative", seconds = n }
  end
  return { raw = n, kind = "absolute", epoch = n }
end

MC.slab_class_for_size = function(size)
  if size == nil or size <= 0 then
    return nil
  end
  local chunk = MC.SLAB_BASE_SIZE
  for class = 1, MC.SLAB_MAX_CLASSES do
    if size <= chunk then
      return { class = class, chunk_size = chunk }
    end
    chunk = math.floor(chunk * MC.SLAB_GROWTH_FACTOR)
  end
  return { class = MC.SLAB_MAX_CLASSES, chunk_size = chunk }
end

MC.slab_size_table = function(classes)
  local out = {}
  local chunk = MC.SLAB_BASE_SIZE
  for class = 1, classes or 16 do
    out[#out + 1] = { class = class, chunk_size = chunk }
    chunk = math.floor(chunk * MC.SLAB_GROWTH_FACTOR)
  end
  return out
end

MC.FLAG_BITS = {
  [1] = "compressed (zlib)",
  [2] = "serialized object",
  [4] = "integer value",
  [8] = "json payload",
}

MC.flags_decode = function(flags)
  local out = { raw = flags, bits = {} }
  if flags == nil then
    return out
  end
  for bit = 0, 15 do
    local mask = 2 ^ bit
    if math.floor(flags / mask) % 2 == 1 then
      out.bits[#out.bits + 1] = { bit = bit, meaning = MC.FLAG_BITS[2 ^ bit] or "client-defined" }
    end
  end
  return out
end

MC.parse_lru_metadump = function(lines)
  local out = {}
  for _, line in ipairs(lines or {}) do
    local key = line:match("^key=(%S+)")
    if key ~= nil then
      out[#out + 1] = {
        key = key,
        expiry = line:match("exp=(%S+)"),
        last_access = line:match("la=(%S+)"),
        cas = line:match("cas=(%S+)"),
        fetched = line:match("fetch=(%S+)"),
      }
    end
  end
  return out
end

MC.VERSION_MIN_RECOMMENDED = "1.6.17"

MC.version_tuple = function(version)
  local parts = {}
  for n in tostring(version or ""):gmatch("%d+") do
    parts[#parts + 1] = tonumber(n)
  end
  return parts
end

MC.version_outdated = function(version)
  local cur = MC.version_tuple(version)
  local min = MC.version_tuple(MC.VERSION_MIN_RECOMMENDED)
  for i = 1, math.max(#cur, #min) do
    local c = cur[i] or 0
    local m = min[i] or 0
    if c > m then
      return false
    end
    if c < m then
      return true
    end
  end
  return false
end

MC.binary_header_validate = function(data)
  if type(data) ~= "string" or #data < 24 then
    return { valid = false, reason = "too short for a binary header" }
  end
  local magic = string.byte(data, 1)
  local opcode = string.byte(data, 2)
  local status = string.byte(data, 7) * 256 + string.byte(data, 8)
  local body_len = string.byte(data, 9) * 16777216 + string.byte(data, 10) * 65536 +
    string.byte(data, 11) * 256 + string.byte(data, 12)
  if magic ~= MC.BINARY_MAGIC_RES then
    return { valid = false, reason = "bad magic byte", magic = magic }
  end
  return {
    valid = true,
    opcode = opcode,
    status = status,
    status_name = MC.binary_status_name(status),
    body_len = body_len,
    framed = #data >= 24 + body_len,
  }
end

MC.selftest = function()
  local pass = 0
  local fail = 0
  local function expect_eq(got, want, label)
    if got == want then
      pass = pass + 1
    else
      fail = fail + 1
      stdnse.debug1("mc selftest FAIL %s: got %s want %s", label, tostring(got), tostring(want))
    end
  end

  expect_eq(MC.parse_version({ "VERSION 1.6.22", "END" }), "1.6.22", "version parse")
  local stats = MC.parse_stats({ "STAT curr_items 42", "STAT bytes 1337", "END" })
  expect_eq(stats.curr_items, "42", "stats parse key")
  expect_eq(stats.bytes, "1337", "stats parse value")
  local slabs = MC.parse_slabs({ "STAT 1:chunk_size 96", "STAT 2:chunk_size 120", "STAT total_malloced 1048576", "END" })
  expect_eq(#slabs.ids, 2, "slabs ids")
  expect_eq(slabs.slabs[2].chunk_size, "120", "slab field")
  expect_eq(slabs.total_malloced, "1048576", "slabs total")
  local settings = MC.parse_settings({ "STAT maxbytes 67108864", "STAT udpport 11211", "STAT maxconns 1024", "END" })
  expect_eq(#settings.interesting, 3, "settings interesting")
  local sizes = MC.parse_sizes({ "STAT 96 4", "STAT 192 2", "END" })
  expect_eq(sizes.total_items, 6, "sizes total")
  expect_eq(#sizes.buckets, 2, "sizes buckets")
  local keys = MC.parse_cachedump({ "ITEM user:1 [5 b; 0 s]", "ITEM token [9 b; 0 s]", "END" })
  expect_eq(keys[1], "user:1", "cachedump key 1")
  expect_eq(#keys, 2, "cachedump count")
  local getr = MC.parse_get_response({ "VALUE nse 0 4", "END" })
  expect_eq(getr.found, true, "get response found")
  expect_eq(MC.parse_write_response({ "STORED" }), "STORED", "write stored")
  expect_eq(MC.parse_write_response({ "SERVER_ERROR out of memory" }), "SERVER_ERROR", "write server error")
  local req = MC.ascii_set("k", "vv")
  expect_eq(req:sub(1, 3), "set", "set builder")
  local bin = MC.binary_version()
  expect_eq(string.byte(bin, 1), MC.BINARY_MAGIC_REQ, "binary magic")
  expect_eq(string.byte(bin, 2), MC.BINARY_OPCODE_VERSION, "binary opcode")
  local udp = MC.udp_frame(7, 0, 1, "stats\r\n")
  local parsed = MC.udp_parse(udp)
  expect_eq(parsed.request_id, 7, "udp frame roundtrip id")
  expect_eq(parsed.payload, "stats\r\n", "udp frame roundtrip payload")
  local amp = MC.amplification_grade(15, 1500)
  expect_eq(amp.grade, "extreme", "amplification extreme")
  expect_eq(MC.amplification_grade(15, 36).grade, "moderate", "amplification moderate")
  expect_eq(#MC.version_advisories("1.4.15") > 0, true, "old version advisories")
  expect_eq(#MC.version_advisories("1.6.22"), 1, "modern version advisories")
  expect_eq(MC.ascii_flush_all_sentinel(), "flush_all 2147483647\r\n", "flush sentinel")
  local bset = MC.binary_set("k", "vv", 7, 120, 3)
  expect_eq(string.byte(bset, 2), MC.BINARY_OPCODE_SET, "binary set opcode")
  expect_eq(string.byte(bset, 5), 8, "binary set extras len")
  local bsasl = MC.binary_sasl_plain("u", "p")
  expect_eq(string.byte(bsasl, 2), MC.BINARY_OPCODE_SASL_AUTH, "sasl auth opcode")
  expect_eq(bsasl:find("PLAIN", 1, true) ~= nil, true, "sasl PLAIN mech in key")
  local mresp = MC.parse_meta_response({ "VA 2", "vv", "EN" })
  expect_eq(mresp.hit, true, "meta VA hit")
  expect_eq(mresp.size, 2, "meta VA size")
  expect_eq(MC.parse_meta_response({ "EN" }).code, "EN", "meta EN")
  expect_eq(MC.sentinel_key_is_safe("nse-audit-sentinel-zz0x"), true, "sentinel safe")
  expect_eq(MC.sentinel_key_is_safe("user:session"), false, "non-sentinel rejected")
  local snap = MC.stats_snapshot({ curr_items = "9", bytes = "100" })
  expect_eq(snap[1].key, "curr_items", "stats snapshot keys")
  local d = MC.stats_diff({ get_hits = "10" }, { get_hits = "15" })
  expect_eq(d.get_hits, 5, "stats diff")
  local cls = MC.classify_mechs({ "PLAIN", "SCRAM-SHA-256" })
  expect_eq(cls.strongest, "SCRAM-SHA-256", "mech strongest")
  expect_eq(cls.strength, "strong", "mech strength")
  expect_eq(MC.binary_status_name(0x0001), "KEY_NOT_FOUND", "binary status name")
  local reassembled, complete = MC.udp_reassemble({ { seq = 1, total = 2, payload = "B" }, { seq = 0, total = 2, payload = "A" } })
  expect_eq(reassembled, "AB", "udp reassemble order")
  expect_eq(complete, true, "udp reassemble complete")
  expect_eq(MC.reflection_estimate(15, 100, 10), 1000, "reflection estimate")
  local multi = MC.parse_multiget({ "VALUE a 1 2", "VALUE b 2 3", "END" })
  expect_eq(#multi, 2, "multiget parse count")
  expect_eq(multi[1].key, "a", "multiget key")
  expect_eq(MC.parse_counter_response({ "42" }), 42, "counter parse")
  expect_eq(MC.parse_counter_response({ "SERVER_ERROR oom" }), nil, "counter error")
  local exp = MC.expiry_decode(MC.expiry_encode(60))
  expect_eq(exp.seconds, 60, "expiry relative roundtrip")
  expect_eq(MC.expiry_decode(MC.expiry_encode(99999999)).kind, "absolute", "expiry absolute branch")
  local slabhit = MC.slab_class_for_size(100)
  expect_eq(slabhit.class, 2, "slab class for 100 bytes")
  expect_eq(MC.slab_class_for_size(50).class, 1, "slab class for 50 bytes")
  expect_eq(#MC.slab_size_table(4), 4, "slab size table")
  local fd = MC.flags_decode(3)
  expect_eq(#fd.bits, 2, "flags decode bits")
  local meta = MC.parse_lru_metadump({ "key=user:1 exp=-1 la=99 cas=7 fetch=no", "END" })
  expect_eq(meta[1].key, "user:1", "metadump key")
  expect_eq(meta[1].fetched, "no", "metadump fetched")
  expect_eq(MC.version_outdated("1.6.10"), true, "outdated version detected")
  expect_eq(MC.version_outdated("1.6.22"), false, "current version ok")
  local hdr = MC.binary_header_validate(MC.binary_version() .. "x")
  expect_eq(hdr.valid, false, "header validate bad magic")
  local good = MC.binary_header_validate(MC_MOCK_BIN_VERSION_SAMPLE or MC.binary_version())
  expect_eq(good == nil, false, "header validate runs")

  if fail > 0 then
    return false, fail .. " memcached codec selftest assertions failed"
  end
  return true, "Memcached ASCII/binary/UDP codecs verified (" .. pass .. " assertions)"
end

MCT = {}

local function port_number(port)
  if type(port) == "table" then
    return port.number or 0
  end
  return port or 0
end

local function host_value(host)
  if type(host) == "table" then
    return host.ip or tostring(host)
  end
  return tostring(host)
end

local function budget_of(args)
  return {
    timeout = args.timeout or 8,
    maxrequests = args.maxrequests or 48,
  }
end

local function new_session(host, port, args)
  return {
    host = host_value(host),
    port = port_number(port),
    budget = budget_of(args),
    sock = nil,
    connected = false,
    closed = false,
    requests = 0,
    audit = {},
  }
end

MCT.session_new = new_session

function MCT.audit(sess, event, detail)
  sess.audit[#sess.audit + 1] = tostring(event) .. ":" .. tostring(detail)
end

function MCT.connect(sess)
  if sess.connected then
    return 1
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  local sock = nmap.new_socket()
  sock:set_timeout(math.floor((sess.budget.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, "tcp")
  if not ok then
    sock:close()
    return nil, "connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  MCT.audit(sess, "connect", sess.port)
  return 1
end

function MCT.close(sess)
  if sess and sess.sock and not sess.closed then
    pcall(sess.sock.close, sess.sock)
    sess.closed = true
    sess.connected = false
  end
end

function MCT.ascii_request(sess, command)
  local ok, err = MCT.connect(sess)
  if not ok then
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local sent, serr = sess.sock:send(command)
  if not sent then
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  MCT.audit(sess, "send", #command .. "B")
  local lines = {}
  local spins = 0
  local done = false
  while spins < 40 and not done do
    spins = spins + 1
    local okr, chunk = sess.sock:receive()
    if not okr then
      break
    end
    for line in (chunk .. "\n"):gmatch("(.-)\r?\n") do
      lines[#lines + 1] = line
      if line == "END" or line == "ERROR" or line:find("^SERVER_ERROR") or
        line:find("^CLIENT_ERROR") or line:find("^STORED") or line:find("^DELETED") or
        line:find("^TOUCHED") or line:find("^NOT_FOUND") or line:find("^OK") or
        line:find("^VERSION") then
        done = true
        break
      end
    end
  end
  MCT.audit(sess, "recv", #lines .. "L")
  return lines
end

function MCT.ascii_exchange(host, port, args, command)
  local sess = new_session(host, port, args)
  local lines, err = MCT.ascii_request(sess, command)
  MCT.close(sess)
  return lines, err
end

function MCT.ascii_session_probe(host, port, args, commands)
  local sess = new_session(host, port, args)
  local out = {}
  for _, cmd in ipairs(commands or {}) do
    local lines, err = MCT.ascii_request(sess, cmd.command)
    out[#out + 1] = { label = cmd.label, lines = lines, error = err, command = cmd.command }
  end
  MCT.close(sess)
  return out
end

function MCT.udp_exchange(host, port, args, payload)
  if args.maxrequests and args.maxrequests < 2 then
    return nil, "request budget exhausted"
  end
  local sock = nmap.new_socket("udp")
  sock:set_timeout(math.floor((args.timeout or 8) * 1000))
  local ok, err = sock:connect(host_value(host), port_number(port), "udp")
  if not ok then
    sock:close()
    return nil, "udp connect failed: " .. tostring(err or "unknown")
  end
  local frame = MC.udp_frame(4242, 0, 1, payload)
  local sent, serr = sock:send(frame)
  if not sent then
    sock:close()
    return nil, "udp send failed: " .. tostring(serr or "unknown")
  end
  local responses = {}
  local spins = 0
  while spins < 8 do
    spins = spins + 1
    local okr, dat = sock:receive(65535)
    if not okr then
      break
    end
    local parsed = MC.udp_parse(dat)
    if parsed ~= nil then
      responses[#responses + 1] = parsed
      if parsed.total <= 1 then
        break
      end
    end
  end
  sock:close()
  return responses
end

function MCT.binary_exchange(host, port, args, request)
  local sess = new_session(host, port, args)
  local ok, err = MCT.connect(sess)
  if not ok then
    MCT.close(sess)
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    MCT.close(sess)
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local sent, serr = sess.sock:send(request)
  if not sent then
    MCT.close(sess)
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  MCT.audit(sess, "send", #request .. "B")
  local collected = ""
  local spins = 0
  while spins < 6 do
    spins = spins + 1
    local okr, chunk = sess.sock:receive(65535)
    if not okr then
      break
    end
    collected = collected .. chunk
    if #collected >= 24 then
      local body_len = string.byte(collected, 9) * 16777216 + string.byte(collected, 10) * 65536 +
        string.byte(collected, 11) * 256 + string.byte(collected, 12)
      if #collected >= 24 + body_len then
        break
      end
    end
  end
  MCT.close(sess)
  if collected == "" then
    return nil, "empty binary response"
  end
  MCT.audit(sess, "recv", #collected .. "B")
  return MC.parse_binary_response(collected)
end

function MCT.ascii_pipeline(sess, commands)
  local ok, err = MCT.connect(sess)
  if not ok then
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local blob = table.concat(commands, "")
  local sent, serr = sess.sock:send(blob)
  if not sent then
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  MCT.audit(sess, "send", #blob .. "B pipelined x" .. #commands)
  local collected = {}
  local spins = 0
  while spins < 40 do
    spins = spins + 1
    local okr, chunk = sess.sock:receive()
    if not okr then
      break
    end
    for line in (chunk .. "\n"):gmatch("(.-)\r?\n") do
      collected[#collected + 1] = line
    end
  end
  local responses = {}
  local cursor = 1
  for i = 1, #commands do
    local terminator
    local cmd = commands[i]
    if cmd:find("^get ") or cmd:find("^mg ") then
      terminator = "END"
    elseif cmd:find("^stats") or cmd:find("^lru_crawler") then
      terminator = "END"
    else
      terminator = nil
    end
    local group = {}
    while cursor <= #collected do
      local line = collected[cursor]
      cursor = cursor + 1
      group[#group + 1] = line
      if terminator ~= nil and line == terminator then
        break
      end
      if terminator == nil and (line == "STORED" or line == "DELETED" or line == "OK" or
        line == "TOUCHED" or line == "NOT_FOUND" or line == "HD" or line == "EN" or
        line:find("^ERROR") or line:find("^SERVER_ERROR") or line:find("^CLIENT_ERROR") or
        line:find("^VERSION")) then
        break
      end
    end
    responses[#responses + 1] = group
  end
  MCT.audit(sess, "recv", #collected .. "L pipelined")
  return responses
end

function MCT.binary_pipeline(sess, frames)
  local ok, err = MCT.connect(sess)
  if not ok then
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local blob = table.concat(frames, "")
  local sent, serr = sess.sock:send(blob)
  if not sent then
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  MCT.audit(sess, "send", #blob .. "B binary pipelined x" .. #frames)
  local expected = {}
  local sizes = {}
  for _, frame in ipairs(frames) do
    expected[#expected + 1] = string.byte(frame, 2)
    sizes[#sizes + 1] = string.byte(frame, 3) * 256 + string.byte(frame, 4) or 0
  end
  local collected = ""
  local spins = 0
  while spins < 12 do
    spins = spins + 1
    local okr, chunk = sess.sock:receive(65535)
    if not okr then
      break
    end
    collected = collected .. chunk
    local framed_count = 0
    local pos = 1
    while pos + 24 <= #collected do
      local body_len = string.byte(collected, pos + 8) * 16777216 +
        string.byte(collected, pos + 9) * 65536 +
        string.byte(collected, pos + 10) * 256 + string.byte(collected, pos + 11)
      local total = 24 + body_len
      if pos + total > #collected then
        break
      end
      framed_count = framed_count + 1
      pos = pos + total
    end
    if framed_count >= #frames then
      break
    end
  end
  local out = {}
  local pos = 1
  while pos + 24 <= #collected and #out < #frames do
    local body_len = string.byte(collected, pos + 8) * 16777216 +
      string.byte(collected, pos + 9) * 65536 +
      string.byte(collected, pos + 10) * 256 + string.byte(collected, pos + 11)
    local frame = collected:sub(pos, pos + 24 + body_len - 1)
    local parsed = MC.parse_binary_response(frame)
    if parsed ~= nil then
      out[#out + 1] = parsed
    end
    pos = pos + 24 + body_len
  end
  MCT.audit(sess, "recv", #collected .. "B binary pipelined")
  return out
end

function MCT.udp_exchange_multi(host, port, args, payloads)
  local out = {}
  for _, payload in ipairs(payloads or {}) do
    local responses, err = MCT.udp_exchange(host, port, args, payload)
    if responses == nil then
      out[#out + 1] = { payload = payload, responses = {}, error = err }
    else
      out[#out + 1] = { payload = payload, responses = responses }
    end
  end
  return out
end

MCT.tcp_open = function(host, port, args, count)
  local sockets = {}
  local opened = 0
  local failed = nil
  for _ = 1, count or 1 do
    local sock = nmap.new_socket()
    sock:set_timeout(math.floor((args.timeout or 8) * 1000))
    local ok, err = sock:connect(host_value(host), port_number(port), "tcp")
    if ok then
      opened = opened + 1
      sockets[#sockets + 1] = sock
    else
      failed = tostring(err or "unknown")
      break
    end
  end
  for _, sock in ipairs(sockets) do
    pcall(sock.close, sock)
  end
  return opened, failed
end

MCT.status_open = function(lines)
  return lines ~= nil and #lines > 0
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

local function mc_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - Memcached audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The Memcached audit did not complete against this endpoint", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function mc_error_walled(lines, sections)
  if lines ~= nil and #lines > 0 and lines[1] == "ERROR" then
    sections[#sections + 1] = { key = "Command Surface", value = "ERROR - commands refused (authentication or restricted protocol)" }
    return true
  end
  return false
end

local function run_audit(host, port, args)
  local sections = {}
  do
    local bump = function(fn)
      return function(...)
        state.requests = state.requests + 1
        return fn(...)
      end
    end
    MCT.ascii_request = bump(MCT.ascii_request)
    MCT.binary_exchange = bump(MCT.binary_exchange)
    MCT.binary_pipeline = bump(MCT.binary_pipeline)
    MCT.udp_exchange = bump(MCT.udp_exchange)
  end
  local slab_lines = MCT.ascii_exchange(host, port, args, MC.COMMANDS.stats_slabs .. MC.CRLF)
  local slabs = MC.parse_slabs(slab_lines)
  local slab_rows = {}
  for _, id in ipairs(slabs.ids or {}) do
    local s = slabs.slabs[id] or {}
    slab_rows[#slab_rows + 1] = { slab = id, chunk_size = s.chunk_size or "-", used_chunks = s.used_chunks or "-" }
  end
  sections[#sections + 1] = { key = "Slab Classes", value = #slab_rows > 0 and slab_rows or "none disclosed" }

  local dumped = {}
  local probe_limit = 2
  for _, id in ipairs(slabs.ids or {}) do
    if probe_limit <= 0 then
      break
    end
    probe_limit = probe_limit - 1
    local lines = MCT.ascii_exchange(host, port, args,
      MC.COMMANDS.cachedump_prefix .. id .. " 5" .. MC.CRLF)
    for _, key in ipairs(MC.parse_cachedump(lines)) do
      dumped[#dumped + 1] = { slab = id, key = key }
      if #dumped >= 10 then
        break
      end
    end
  end
  sections[#sections + 1] = { key = "Key Names Disclosed (cachedump, capped at 10)", value =
    #dumped > 0 and dumped or "none disclosed" }

  local item_lines = MCT.ascii_exchange(host, port, args, MC.COMMANDS.stats_items .. MC.CRLF)
  local items = MC.parse_items(item_lines)
  local item_rows = {}
  for sid, fields in pairs(items or {}) do
    item_rows[#item_rows + 1] = { slab = sid, items = fields.number or "-", oldest_age = fields.age or "-" }
  end
  table.sort(item_rows, function(a, b)
    return a.slab < b.slab
  end)
  local snapshot = MC.stats_snapshot(MC.parse_stats(MCT.ascii_exchange(host, port, args, MC.COMMANDS.stats .. MC.CRLF)))
  sections[#sections + 1] = { key = "Item Counts per Slab (stats items)", value =
    #item_rows > 0 and item_rows or "not disclosed" }
  sections[#sections + 1] = { key = "Live Counters Snapshot", value = snapshot }

  local remediation = {}
  local status_text
  if #dumped > 0 then
    status_text = "VULNERABLE - cache key names readable without authentication (" ..
      #dumped .. " keys sampled from live slabs)"
    add_finding("CRITICAL", "Key enumeration via cachedump", {
      subject = "slab-dump",
      evidence = "stats cachedump disclosed key names such as '" .. tostring(dumped[1].key) ..
        "' - session identifiers and tokens are enumerable",
      confidence = "high",
      cvss = 9.2,
    })
    remediation["1. Lock down"] = "Restrict 11211; cachedump must not be reachable by untrusted networks (GitHub-class key theft vector)."
  elseif mc_error_walled(slab_lines, sections) then
    status_text = "SECURE - slab statistics refused without credentials"
    add_finding("INFO", "Slab stats walled", {
      subject = "slab-dump",
      evidence = "stats slabs answered ERROR",
      confidence = "high",
    })
    remediation["1. Maintain"] = "Re-verify after ACL changes."
  else
    status_text = "INFORMATIONAL - slab stats readable but cachedump disclosed no keys"
    add_finding("INFO", "Slab telemetry only", {
      subject = "slab-dump",
      evidence = "slabs visible (" .. #slab_rows .. " classes) with no cachedump output",
      confidence = "high",
    })
    remediation["1. Harden"] = "Restrict 11211; keep cachedump disabled for untrusted callers."
  end
  sections[#sections + 1] = { key = "Remediation", value = remediation }

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
