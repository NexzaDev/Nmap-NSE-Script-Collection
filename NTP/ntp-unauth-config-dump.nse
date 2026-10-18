local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Chains two unauthenticated mode 6 operations - Read Status (assoc list)
and per-association Read Variables - into a full peer-configuration dump
(upstream addresses, flags, strata) without any credential.

Why it matters
- The peer dump is effectively a network map: internal upstream IPs,
  broadcast services and their authentication state.
- This is the interface abused for remote configuration change; its
  unauthenticated readability almost always correlates with a writable
  control configuration.

What the script does
1. Sends mode 6 readstat and lists the associations.
2. For up to 4 associations issues readvar and captures the variables.
3. Reports the dumped peer matrix and grades the exposure.

Safe operation: read-only queries only (one readstat + up to four
readvar); nothing is written to the daemon.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  123,
  "ntp",
  "udp"
)

local SCRIPT_NAME = "ntp-unauth-config-dump"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 32,
  maxassocs = 4,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}

local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "maxassocs", minimum = 1, maximum = 8, integer = true },
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

NTP_T = {}

NTP_T.ERA_OFFSET = 2208988800

NTP_T.MODE_RESERVED = 0
NTP_T.MODE_SYMMETRIC_ACTIVE = 1
NTP_T.MODE_SYMMETRIC_PASSIVE = 2
NTP_T.MODE_CLIENT = 3
NTP_T.MODE_SERVER = 4
NTP_T.MODE_BROADCAST = 5
NTP_T.MODE_CONTROL = 6
NTP_T.MODE_PRIVATE = 7

NTP_T.CTLOP_READSTAT = 1
NTP_T.CTLOP_READVAR = 2
NTP_T.CTLOP_WRITEVAR = 3
NTP_T.CTLOP_READCLOCK = 4
NTP_T.CTLOP_WRITECLOCK = 5
NTP_T.CTLOP_SETTRAP = 6
NTP_T.CTLOP_ASYNCMSG = 7
NTP_T.CTLOP_UNSETTRAP = 8

NTP_T.CTLOP_NAMES = {
  [1] = "Read Status",
  [2] = "Read Variables",
  [3] = "Write Variables",
  [4] = "Read Clock Variables",
  [5] = "Write Clock Variables",
  [6] = "Set Trap",
  [7] = "Async Message",
  [8] = "Unset Trap",
}

NTP_T.IMPL_UNIV = 0
NTP_T.IMPL_XNTPD_OLD = 2
NTP_T.IMPL_XNTPD = 3

NTP_T.REQ_PEER_LIST = 0
NTP_T.REQ_PEER_INFO = 2
NTP_T.REQ_SYS_INFO = 4
NTP_T.REQ_GET_RESTRICT = 16
NTP_T.REQ_MON_GETLIST = 20
NTP_T.REQ_AUTH_INFO = 28
NTP_T.REQ_TRAPS = 29
NTP_T.REQ_MON_GETLIST_1 = 42

NTP_T.REQ_NAMES = {
  [0] = "peer list",
  [2] = "peer info",
  [4] = "sys info",
  [16] = "restrictions list",
  [20] = "monlist (legacy)",
  [28] = "auth info",
  [29] = "trap list",
  [42] = "monlist v1",
}

NTP_T.INFO_ERR_NAMES = {
  [0] = "no error",
  [1] = "incompatible implementation (mode 7 disabled)",
  [2] = "unimplemented request code",
  [3] = "format error",
  [4] = "no data available",
  [5] = "unknown error",
  [6] = "unknown error",
  [7] = "authentication required/failed",
}

NTP_T.KISS_CODES = {
  RATE = "rate exceeded (server is limiting this client)",
  DENY = "pending denial on policy grounds",
  RSTR = "restriction list reject",
  STRAT = "stratum limit reached",
  STEP = "step change in progress",
  AUTH = "authentication failure",
  NTS = "NTS required",
  "???",
}

NTP_T.LEAP_NAMES = {
  [0] = "no warning (in sync)",
  [1] = "last minute of day has 61 seconds (leap pending)",
  [2] = "last minute of day has 59 seconds (leap pending)",
  [3] = "alarm condition (unsynchronized)",
}

NTP_T.PEER_STATUS = {
  CONFIG = 0x80,
  AUTH_ENABLE = 0x40,
  AUTHENTIC = 0x20,
  REACH = 0x10,
  BROADCAST = 0x08,
}

NTP_T.PEER_SEL_NAMES = {
  [0] = "reject",
  [1] = "falsetick",
  [2] = "excess",
  [3] = "outlier",
  [4] = "candidate",
  [5] = "backup",
  [6] = "sys.peer",
  [7] = "pps.peer",
}

NTP_T.CLOCK_SOURCE_NAMES = {
  [0] = "unspecified",
  [1] = "radio clock",
  [2] = "GPS/CDMA",
  [3] = "Hummingbird/WWV",
  [4] = "CDMA (hex)",
  [5] = "NIST modem",
  [6] = "NTP-disciplined",
  [7] = "arbitrary",
}

NTP_T.MODE6_VAR_LIST = "version,processor,stratum,refid,leap,precision,rootdelay,rootdisp"

NTP_T.VERSION_ADVISORIES = {
  {
    match = "^4%.2%.6",
    family = "ntpd 4.2.6",
    advisories = "CVE-2013-5211 (monlist DRDoS enabled by default), CVE-2014-9293/9294 (weak default key, crypto-NAK), CVE-2014-9295 (buffer overflows in crypto_recv/ctl_putdata/configure)",
    verdict = "pre-4.2.8 series with multiple critical advisories",
  },
  {
    match = "^4%.2%.8p%1?0?[0-7]$",
    family = "ntpd 4.2.8p0-p7",
    advisories = "CVE-2014-9295 fixed only in p1+; KoD spoofing CVE-2015-7704/7705, control-mode issues CVE-2015-7855/7973 era",
    verdict = "early 4.2.8 patch level with known advisories",
  },
  {
    match = "^4%.2%.8p([0-9]|1[0-4])$",
    family = "ntpd 4.2.8p0-p14",
    advisories = "CVE-2016-2516/2517 (rate limiting), CVE-2016-9311/9312 (trap/mode 7 issues), CVE-2017-6462 era fixes missing",
    verdict = "mid 4.2.8 patch level with known advisories",
  },
  {
    match = "^4%.2%.8p1[5-7]$",
    family = "ntpd 4.2.8p15-p17",
    advisories = "CVE-2020-11868 (TSIG), CVE-2021-22222 era fixes missing",
    verdict = "older 4.2.8 patch level with moderate advisories",
  },
}

NTP_T.LEAP_ADVISORY = {
  [1] = "leap second pending: pre-4.2.8p9 era builds crash or smear incorrectly at insertion (2015/2016 leap events)",
  [2] = "leap second pending (deletion): verify the build handles negative smear correctly",
  [3] = "leap alarm stuck: server has been unsynchronized for a long interval and still answers clients",
}

NTP_T.MON_ITEM_SIZE = 72
NTP_T.MON_MAX_ENTRIES = 30

NTP_B = {}

NTP_B.u16be = function(v)
  return string.char(math.floor(v / 256) % 256, v % 256)
end

NTP_B.u32be = function(v)
  return string.char(
    math.floor(v / 16777216) % 256,
    math.floor(v / 65536) % 256,
    math.floor(v / 256) % 256,
    v % 256)
end

NTP_B.header_byte = function(li, vn, mode)
  return string.char((li % 4) * 64 + (vn % 8) * 8 + (mode % 8))
end

NTP_B.pack_short = function(value)
  local whole = math.floor(value or 0)
  local frac = math.floor(((value or 0) - whole) * 65536)
  return NTP_B.u16be(whole) .. NTP_B.u16be(frac)
end

NTP_B.pack_ts = function(seconds, fraction)
  return NTP_B.u32be(seconds) .. NTP_B.u32be(fraction or 0)
end

NTP_B.unix_to_ts_bytes = function(unix_seconds, fraction)
  return NTP_B.pack_ts(unix_seconds + NTP_T.ERA_OFFSET, fraction or 0)
end

NTP_B.pack_client = function(opts)
  opts = opts or {}
  local vn = opts.version or 4
  local mode = opts.mode or NTP_T.MODE_CLIENT
  local pkt = {}
  pkt[1] = NTP_B.header_byte(opts.leap or 0, vn, mode)
  pkt[2] = string.char(opts.stratum or 0, opts.poll or 0, opts.precision or 0)
  pkt[3] = NTP_B.pack_short(0)
  pkt[4] = NTP_B.pack_short(0)
  pkt[5] = "\x00\x00\x00\x00"
  pkt[6] = "\x00\x00\x00\x00\x00\x00\x00\x00"
  pkt[7] = "\x00\x00\x00\x00\x00\x00\x00\x00"
  pkt[8] = "\x00\x00\x00\x00\x00\x00\x00\x00"
  pkt[9] = NTP_B.unix_to_ts_bytes(opts.transmit_unix or os.time(), opts.transmit_frac or 0)
  return table.concat(pkt, "")
end

NTP_B.pack_mode6 = function(opts)
  opts = opts or {}
  local flags = 0
  if opts.is_response then
    flags = flags + 0x80
  end
  if opts.more then
    flags = flags + 0x40
  end
  if opts.error then
    flags = flags + 0x20
  end
  local head = NTP_B.header_byte(opts.leap or 0, opts.version or 2, NTP_T.MODE_CONTROL)
    .. string.char(flags + (opts.op % 32))
    .. NTP_B.u16be(opts.sequence or 1)
    .. NTP_B.u16be(opts.status or 0)
    .. NTP_B.u16be(opts.assoc or 0)
    .. NTP_B.u16be(opts.offset or 0)
    .. NTP_B.u16be(opts.data and #opts.data or 0)
  return head .. (opts.data or "")
end

NTP_B.pack_mode7 = function(impl, reqcode, opts)
  opts = opts or {}
  local vn = opts.version or 2
  local seq = opts.sequence or 0
  local head = NTP_B.header_byte(0, vn, NTP_T.MODE_PRIVATE)
    .. string.char((opts.auth and 0x80 or 0) + (seq % 128))
    .. string.char(impl % 256, reqcode % 256)
    .. NTP_B.u16be(opts.nitems or 1)
    .. NTP_B.u16be(0)
  local body = opts.data or ""
  if #body < 40 then
    body = body .. string.rep("\x00", 40 - #body)
  end
  return head .. body
end

NTP_B.fnv32 = function(data)
  local hash = 2166136261
  for i = 1, #(data or "") do
    hash = (hash ~ (data:byte(i) or 0)) & 4294967295
    hash = (hash * 16777619) & 4294967295
  end
  return hash
end

NTP_B.pack_mac = function(payload, keyid, digest16)
  if digest16 == nil then
    local h1 = NTP_B.fnv32(payload .. tostring(keyid))
    local h2 = NTP_B.fnv32(tostring(keyid) .. payload .. "mac")
    local h3 = NTP_B.fnv32("pad" .. payload .. keyid)
    local h4 = NTP_B.fnv32(keyid .. "final" .. payload)
    digest16 = NTP_B.u32be(h1) .. NTP_B.u32be(h2) .. NTP_B.u32be(h3) .. NTP_B.u32be(h4)
  end
  return NTP_B.u32be(keyid) .. digest16
end

NTP_B.ipv4_str = function(b4)
  return string.format("%d.%d.%d.%d", b4:byte(1), b4:byte(2), b4:byte(3), b4:byte(4))
end

NTP_X = {}

NTP_X.parse_header_byte = function(b)
  return {
    li = math.floor(b / 64) % 4,
    vn = math.floor(b / 8) % 8,
    mode = b % 8,
  }
end

NTP_X.short_to_seconds = function(b4)
  if b4 == nil or #b4 < 4 then
    return 0
  end
  return (b4:byte(1) * 65536 + b4:byte(2) * 256 + b4:byte(3) * 4 + b4:byte(4)) / 65536
end

NTP_X.ts_seconds = function(b8)
  if b8 == nil or #b8 < 8 then
    return 0
  end
  local sec = b8:byte(1) * 16777216 + b8:byte(2) * 65536 + b8:byte(3) * 256 + b8:byte(4)
  local frac = (b8:byte(5) * 16777216 + b8:byte(6) * 65536 + b8:byte(7) * 256 + b8:byte(8)) / 4294967296
  return sec + frac
end

NTP_X.ts_unix = function(b8)
  return NTP_X.ts_seconds(b8) - NTP_T.ERA_OFFSET
end

NTP_X.ts_zero = function(b8)
  for i = 1, 8 do
    if b8:byte(i) ~= 0 then
      return false
    end
  end
  return true
end

NTP_X.refid_classify = function(stratum, b4)
  local printable = true
  local text = ""
  for i = 1, 4 do
    local b = b4:byte(i)
    if b < 32 or b > 126 then
      printable = false
    end
    text = text .. string.char(b)
  end
  local out = { raw = NTP_B.ipv4_str(b4), text = text }
  if stratum == 0 then
    out.kind = "kiss"
    out.kiss = NTP_T.KISS_CODES[text] and text or ("unknown kiss code " .. NTP_B.ipv4_str(b4))
    out.kiss_note = NTP_T.KISS_CODES[text] or "undocumented kiss code"
  elseif stratum == 1 then
    out.kind = "ascii-source"
    out.value = text:gsub("%z", ""):gsub("^%s+", ""):gsub("%s+$", "")
  else
    out.kind = "ipv4"
    out.value = NTP_B.ipv4_str(b4)
  end
  return out
end

NTP_X.parse_client_response = function(data, opts)
  opts = opts or {}
  local out = { valid = false, mac_present = false, kiss = nil }
  if data == nil or #data < 48 then
    out.reason = "short response (" .. tostring(data and #data or 0) .. " bytes)"
    return out
  end
  local head = NTP_X.parse_header_byte(data:byte(1))
  out.li = head.li
  out.vn = head.vn
  out.mode = head.mode
  out.stratum = data:byte(2)
  out.poll = data:byte(3)
  local precision_raw = data:byte(4)
  if precision_raw > 127 then
    out.precision = precision_raw - 256
  else
    out.precision = precision_raw
  end
  out.root_delay = NTP_X.short_to_seconds(data:sub(5, 8))
  out.root_dispersion = NTP_X.short_to_seconds(data:sub(9, 12))
  out.refid = NTP_X.refid_classify(out.stratum, data:sub(13, 16))
  out.reference_ts = NTP_X.ts_seconds(data:sub(17, 24))
  out.origin_ts = NTP_X.ts_seconds(data:sub(25, 32))
  out.receive_ts = NTP_X.ts_seconds(data:sub(33, 40))
  out.transmit_ts = NTP_X.ts_seconds(data:sub(41, 48))
  out.receive_raw = data:sub(33, 40)
  out.transmit_raw = data:sub(41, 48)
  if #data > 48 then
    out.mac_present = true
    out.mac_bytes = #data - 48
  end
  out.origin_match = false
  if opts.request_transmit_raw ~= nil and #opts.request_transmit_raw == 8 then
    out.origin_match = opts.request_transmit_raw == data:sub(25, 32)
  end
  out.valid = (out.mode == NTP_T.MODE_SERVER or out.mode == NTP_T.MODE_BROADCAST)
    and out.stratum <= 16
  if out.stratum == 0 then
    out.kiss = out.refid.kiss
  end
  return out
end

NTP_X.parse_status_word = function(value)
  local out = {}
  out.leap = math.floor(value / 16384) % 4
  out.source = math.floor(value / 256) % 64
  out.count = math.floor(value / 16) % 16
  out.code = value % 16
  out.leap_name = NTP_T.LEAP_NAMES[out.leap] or "unknown"
  out.source_name = NTP_T.CLOCK_SOURCE_NAMES[out.source] or "source " .. tostring(out.source)
  return out
end

NTP_X.split_pairs = function(text)
  local vars = {}
  local order = {}
  local pos = 1
  while pos <= #text do
    local comma = text:find(",", pos, true)
    local chunk
    if comma == nil then
      chunk = text:sub(pos)
      pos = #text + 1
    else
      chunk = text:sub(pos, comma - 1)
      pos = comma + 1
    end
    local k, v = chunk:match("^%s*([%w_.%-]+)%s*=%s*(.-)%s*$")
    if k then
      if vars[k] == nil then
        order[#order + 1] = k
      end
      vars[k] = v
    end
  end
  return vars, order
end

NTP_X.parse_mode6 = function(data)
  local out = { valid = false, vars = {}, order = {} }
  if data == nil or #data < 12 then
    out.reason = "short control response"
    return out
  end
  local head = NTP_X.parse_header_byte(data:byte(1))
  out.li = head.li
  out.vn = head.vn
  out.mode = head.mode
  local flags = data:byte(2)
  out.is_response = (math.floor(flags / 128) % 2) == 1
  out.more = (math.floor(flags / 64) % 2) == 1
  out.error = (math.floor(flags / 32) % 2) == 1
  out.op = flags % 32
  out.op_name = NTP_T.CTLOP_NAMES[out.op] or ("op " .. tostring(out.op))
  out.sequence = data:byte(3) * 256 + data:byte(4)
  out.status_raw = data:byte(5) * 256 + data:byte(6)
  out.assoc = data:byte(7) * 256 + data:byte(8)
  out.offset = data:byte(9) * 256 + data:byte(10)
  out.count = data:byte(11) * 256 + data:byte(12)
  out.status = NTP_X.parse_status_word(out.status_raw)
  local body = data:sub(13, 12 + out.count)
  out.data = body
  if out.count > 0 and not out.error then
    local vars, order = NTP_X.split_pairs(body)
    out.vars = vars
    out.order = order
    out.assoc_rows = NTP_X.parse_assoc_list(body)
  end
  out.valid = out.is_response and out.mode == NTP_T.MODE_CONTROL
  return out
end

NTP_X.parse_assoc_list = function(text)
  local rows = {}
  if text == nil or #text == 0 then
    return rows
  end
  local pos = 1
  while pos <= #text do
    local comma = text:find(",", pos, true)
    local chunk
    if comma == nil then
      chunk = text:sub(pos)
      pos = #text + 1
    else
      chunk = text:sub(pos, comma - 1)
      pos = comma + 1
    end
    local id, status_hex = chunk:match("^%s*(%d+)%s*=%s*([0-9a-fA-F]+)%s*$")
    if id then
      local status = tonumber(status_hex, 16) or 0
      rows[#rows + 1] = NTP_X.decode_peer_status(tonumber(id), status)
    end
  end
  return rows
end

NTP_X.decode_peer_status = function(id, status)
  local row = { id = id, status_raw = status }
  row.configured = math.floor(status / 32768) % 2 == 1
  row.auth_enabled = math.floor(status / 16384) % 2 == 1
  row.authentic = math.floor(status / 8192) % 2 == 1
  row.reachable = math.floor(status / 4096) % 2 == 1
  row.broadcast = math.floor(status / 2048) % 2 == 1
  row.sel = status % 16
  row.sel_name = NTP_T.PEER_SEL_NAMES[row.sel] or "unknown"
  return row
end

NTP_X.parse_mode7 = function(data)
  local out = { valid = false, entries = {} }
  if data == nil or #data < 8 then
    out.reason = "short private-mode response"
    return out
  end
  local head = NTP_X.parse_header_byte(data:byte(1))
  out.li = head.li
  out.vn = head.vn
  out.mode = head.mode
  out.is_response = (math.floor(data:byte(1) / 128) % 2) == 1
  local seq_byte = data:byte(2)
  out.auth = (math.floor(seq_byte / 128) % 2) == 1
  out.sequence = seq_byte % 128
  out.impl = data:byte(3)
  out.req = data:byte(4)
  local err_nitems = data:byte(5) * 256 + data:byte(6)
  local more_items = data:byte(7) * 256 + data:byte(8)
  out.err = math.floor(err_nitems / 4096) % 16
  out.nitems = err_nitems % 4096
  out.more = math.floor(more_items / 4096) % 16
  out.item_size = more_items % 4096
  out.err_name = NTP_T.INFO_ERR_NAMES[out.err] or ("error " .. tostring(out.err))
  out.data = data:sub(9)
  out.valid = out.is_response and out.mode == NTP_T.MODE_PRIVATE
  if out.err == 0 and out.item_size > 0 and #out.data >= out.item_size then
    out.entries_count = math.floor(#out.data / out.item_size)
    if out.entries_count > NTP_T.MON_MAX_ENTRIES then
      out.entries_count = NTP_T.MON_MAX_ENTRIES
      out.truncated = true
    end
    for i = 1, out.entries_count do
      local entry = out.data:sub((i - 1) * out.item_size + 1, i * out.item_size)
      out.entries[#out.entries + 1] = entry
    end
  end
  return out
end

NTP_X.parse_mon_entry = function(entry)
  local out = {}
  if entry == nil or #entry < 6 then
    return out
  end
  out.src_ip = NTP_B.ipv4_str(entry:sub(1, 4))
  out.src_port = entry:byte(5) * 256 + entry:byte(6)
  return out
end

NTP_X.parse_restrict_entry = function(entry)
  local out = {}
  if entry == nil or #entry < 16 then
    return out
  end
  out.addr = NTP_B.ipv4_str(entry:sub(1, 4))
  out.mask = NTP_B.ipv4_str(entry:sub(5, 8))
  out.flags = entry:byte(9) * 16777216 + entry:byte(10) * 65536 + entry:byte(11) * 256 + entry:byte(12)
  out.count = entry:byte(13) * 16777216 + entry:byte(14) * 65536 + entry:byte(15) * 256 + entry:byte(16)
  out.flag_names = {}
  local flag_bits = {
    { 0x00000001, "ignore" },
    { 0x00000002, "noserv" },
    { 0x00000004, "limited" },
    { 0x00000008, "lowpriotrap" },
    { 0x00000010, "nomodify" },
    { 0x00000020, "noquery" },
    { 0x00000040, "nopeer" },
    { 0x00000080, "noserve" },
  }
  for _, fb in ipairs(flag_bits) do
    if math.floor(out.flags / fb[1]) % 2 == 1 then
      out.flag_names[#out.flag_names + 1] = fb[2]
    end
  end
  return out
end

NTP_X.parse_trap_entry = function(entry)
  local out = {}
  if entry == nil or #entry < 8 then
    return out
  end
  out.local_addr = NTP_B.ipv4_str(entry:sub(1, 4))
  out.trap_addr = NTP_B.ipv4_str(entry:sub(5, 8))
  if #entry >= 10 then
    out.port = entry:byte(9) * 256 + entry:byte(10)
  end
  if #entry >= 12 then
    out.flags = entry:byte(11) * 256 + entry:byte(12)
  end
  return out
end

NTP_X.parse_auth_counters = function(data)
  local names = { "timeresets", "timerecalls", "timeresets2", "keysin", "keyslast", "decrypted" }
  local counters = {}
  for i = 1, math.min(6, math.floor(#data / 4)) do
    local off = (i - 1) * 4
    counters[names[i]] = data:byte(off + 1) * 16777216 + data:byte(off + 2) * 65536
      + data:byte(off + 3) * 256 + data:byte(off + 4)
  end
  return counters
end

NTP_X.parse_version = function(version_string)
  local out = { raw = version_string or "", daemon = version_string and version_string:match("^(%S+)") or "" }
  local nums = version_string and version_string:match("(%d+%.%d+%.%d+p?%d*)") or nil
  if nums then
    out.numeric = nums
    out.major, out.minor, out.patch = nums:match("^(%d+)%.(%d+)%.(%d+)")
    out.patchlevel = nums:match("p(%d+)$")
  end
  for _, adv in ipairs(NTP_T.VERSION_ADVISORIES) do
    if nums and nums:match(adv.match) then
      out.advisory = adv
      break
    end
  end
  return out
end

NTP_A = {}

NTP_A.selftest = function()
  local pkt = NTP_B.pack_client({ version = 4, transmit_unix = 1789000000, transmit_frac = 0x20000000 })
  if #pkt ~= 48 then
    return false, "client packet must be 48 bytes"
  end
  local head = NTP_X.parse_header_byte(pkt:byte(1))
  if head.mode ~= NTP_T.MODE_CLIENT or head.vn ~= 4 then
    return false, "client header roundtrip failed"
  end
  if NTP_X.ts_seconds(pkt:sub(41, 48)) - NTP_T.ERA_OFFSET ~= 1789000000.125 then
    return false, "timestamp roundtrip failed"
  end
  local m6 = NTP_B.pack_mode6({ op = NTP_T.CTLOP_READVAR, assoc = 7, data = "version" })
  if #m6 ~= 12 + 7 then
    return false, "mode 6 framing failed"
  end
  local parsed = NTP_X.parse_mode6(m6)
  if parsed.mode ~= NTP_T.MODE_CONTROL or parsed.op ~= NTP_T.CTLOP_READVAR or parsed.assoc ~= 7 then
    return false, "mode 6 roundtrip failed"
  end
  local m7 = NTP_B.pack_mode7(NTP_T.IMPL_XNTPD, NTP_T.REQ_MON_GETLIST_1)
  if #m7 ~= 48 then
    return false, "mode 7 packet must be 48 bytes"
  end
  local p7 = NTP_X.parse_mode7(m7)
  if p7.impl ~= NTP_T.IMPL_XNTPD or p7.req ~= NTP_T.REQ_MON_GETLIST_1 or p7.nitems ~= 1 then
    return false, "mode 7 roundtrip failed"
  end
  local sw = NTP_X.parse_status_word(0x0614)
  if sw.leap ~= 0 or sw.source ~= 6 then
    return false, "status word decode failed"
  end
  local row = NTP_X.decode_peer_status(3, 0xb815)
  if not row.broadcast or row.sel ~= 5 then
    return false, "peer status decode failed"
  end
  return true, "pack/parse roundtrips verified"
end

NTP_A.offset_class = function(offset)
  local abs = offset
  if abs < 0 then
    abs = -abs
  end
  if abs > 60 then
    return "critical", abs
  elseif abs > 10 then
    return "major", abs
  elseif abs > 1 then
    return "elevated", abs
  elseif abs > 0.25 then
    return "minor", abs
  end
  return "tight", abs
end

NTP_A.amplification_class = function(factor)
  if factor >= 100 then
    return "high (DRDoS weapon class)"
  elseif factor >= 20 then
    return "significant"
  elseif factor >= 5 then
    return "moderate"
  elseif factor > 1 then
    return "low"
  end
  return "none"
end

local function ntp_session_new(host, port, args)
  local port_number = port
  if type(port_number) == "table" then
    port_number = port_number.number or port_number.port
  end
  return {
    host = host,
    port = port_number or 123,
    args = args,
    proto = "udp",
    sock = nil,
    connected = false,
    closed = false,
    connects = 0,
    sends = 0,
    recvs = 0,
    timeouts = 0,
    errors = 0,
    audit = {},
  }
end

local function ntp_audit(sess, kind, detail)
  sess.audit[#sess.audit + 1] = kind .. ":" .. tostring(detail)
end

local function ntp_connect(sess, proto)
  if sess.connected then
    return 1
  end
  local sock = nmap.new_socket(proto or sess.proto)
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, proto or sess.proto)
  if not ok then
    sock:close()
    return nil, "connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  sess.connects = sess.connects + 1
  ntp_audit(sess, "connect", (proto or sess.proto) .. "/" .. sess.port)
  return 1
end

local function ntp_close(sess)
  if sess and sess.sock and not sess.closed then
    sess.sock:close()
  end
  if sess then
    sess.closed = true
    sess.connected = false
  end
end

local function ntp_send_raw(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  sess.sends = sess.sends + 1
  ntp_audit(sess, "send", #data)
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function ntp_recv_udp(sess, wait_seconds)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  local deadline = os.time() + math.max(1, wait_seconds or sess.args.timeout or 8)
  while true do
    if budget_exhausted(sess.args) then
      return nil, "request budget exhausted"
    end
    local remaining = deadline - os.time()
    if remaining <= 0 then
      sess.timeouts = sess.timeouts + 1
      return nil, "timeout"
    end
    sess.sock:set_timeout(math.min(remaining, 3) * 1000)
    local ok, data = sess.sock:receive(65536)
    if ok then
      sess.recvs = sess.recvs + 1
      ntp_audit(sess, "recv", #data)
      return data
    end
    local err = data
    if err == "TIMEOUT" or err == "EOF" then
      sess.timeouts = sess.timeouts + 1
      return nil, "timeout"
    end
    sess.errors = sess.errors + 1
    return nil, "receive failed: " .. tostring(err or "unknown")
  end
end

local function ntp_recv_tcp_exact(sess, want, wait_seconds)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  local deadline = os.time() + math.max(1, wait_seconds or sess.args.timeout or 8)
  local buf = ""
  while #buf < want do
    local remaining = deadline - os.time()
    if remaining <= 0 then
      sess.timeouts = sess.timeouts + 1
      if #buf > 0 then
        return buf
      end
      return nil, "timeout"
    end
    sess.sock:set_timeout(math.min(remaining, 3) * 1000)
    local ok, chunk = sess.sock:receive(want - #buf)
    if ok then
      buf = buf .. chunk
      sess.recvs = sess.recvs + 1
    else
      local err = chunk
      if err == "TIMEOUT" or err == "EOF" then
        if #buf > 0 then
          return buf
        end
        sess.timeouts = sess.timeouts + 1
        return nil, "timeout"
      end
      sess.errors = sess.errors + 1
      return nil, "receive failed: " .. tostring(err or "unknown")
    end
  end
  return buf
end

local function ntp_client_exchange(host, port, args, opts)
  opts = opts or {}
  local sess = ntp_session_new(host, port, args)
  local ok, err = ntp_connect(sess, "udp")
  if not ok then
    ntp_close(sess)
    return nil, err
  end
  local t1 = os.time()
  local request = NTP_B.pack_client({
    version = opts.version or 4,
    transmit_unix = t1,
    transmit_frac = 0x20000000,
    leap = opts.leap or 0,
  })
  ok, err = ntp_send_raw(sess, request)
  if not ok then
    ntp_close(sess)
    return nil, err, sess
  end
  local t4_unix = nil
  local data
  local deadline = os.time() + math.max(1, args.timeout or 8)
  while data == nil and os.time() < deadline do
    data = ntp_recv_udp(sess, 2)
    if data == nil then
      break
    end
    t4_unix = os.time()
    local head = NTP_X.parse_header_byte(data:byte(1) or 0)
    if head.mode == NTP_T.MODE_SERVER or head.mode == NTP_T.MODE_BROADCAST or head.stratum == 0 then
      break
    end
    data = nil
  end
  ntp_close(sess)
  if data == nil then
    return nil, "timeout", sess
  end
  local parsed = NTP_X.parse_client_response(data, { request_transmit_raw = request:sub(41, 48) })
  if not parsed.valid then
    return parsed, parsed.reason or "unparseable response", sess
  end
  if t4_unix ~= nil then
    local t1_ntp = t1 + NTP_T.ERA_OFFSET + 0.125
    local t4_ntp = t4_unix + NTP_T.ERA_OFFSET
    parsed.offset = ((parsed.receive_ts - t1_ntp) + (parsed.transmit_ts - t4_ntp)) / 2
  else
    parsed.offset = nil
  end
  return parsed, nil, sess
end

local function ntp_mode6_query(host, port, args, opts)
  opts = opts or {}
  local sess = ntp_session_new(host, port, args)
  local ok, err = ntp_connect(sess, "udp")
  if not ok then
    ntp_close(sess)
    return nil, err
  end
  state.control_queries = (state.control_queries or 0) + 1
  local packet = NTP_B.pack_mode6({
    op = opts.op or NTP_T.CTLOP_READVAR,
    sequence = state.control_queries,
    assoc = opts.assoc or 0,
    data = opts.data,
    version = opts.version or 2,
    error = opts.force_error,
  })
  if opts.mac then
    packet = packet .. NTP_B.pack_mac(packet, opts.keyid or 1)
  end
  ok, err = ntp_send_raw(sess, packet)
  if not ok then
    ntp_close(sess)
    return nil, err
  end
  local data = ntp_recv_udp(sess, opts.wait or 2)
  ntp_close(sess)
  if data == nil then
    return nil, "timeout"
  end
  if #data < 12 or NTP_X.parse_header_byte(data:byte(1)).mode ~= NTP_T.MODE_CONTROL then
    return nil, "not a control response"
  end
  return NTP_X.parse_mode6(data)
end

local function ntp_mode6_readlist(host, port, args, opts)
  return ntp_mode6_query(host, port, args, {
    op = NTP_T.CTLOP_READSTAT,
    assoc = 0,
    data = nil,
    version = (opts or {}).version or 2,
  })
end

local function ntp_mode7_request(host, port, args, impl, reqcode, opts)
  opts = opts or {}
  local sess = ntp_session_new(host, port, args)
  local ok, err = ntp_connect(sess, "udp")
  if not ok then
    ntp_close(sess)
    return nil, err
  end
  state.private_queries = (state.private_queries or 0) + 1
  local packet = NTP_B.pack_mode7(impl, reqcode, {
    sequence = state.private_queries % 128,
    data = opts.data,
    nitems = opts.nitems or 1,
    auth = opts.auth,
  })
  if opts.mac then
    packet = packet .. NTP_B.pack_mac(packet, opts.keyid or 1)
  end
  ok, err = ntp_send_raw(sess, packet)
  if not ok then
    ntp_close(sess)
    return nil, err
  end
  local data
  local deadline = os.time() + math.max(1, args.timeout or 8)
  while data == nil and os.time() < deadline do
    local chunk = ntp_recv_udp(sess, 2)
    if chunk == nil then
      break
    end
    local head = NTP_X.parse_header_byte(chunk:byte(1) or 0)
    if head.mode == NTP_T.MODE_PRIVATE then
      data = chunk
    end
  end
  ntp_close(sess)
  if data == nil then
    return nil, "timeout"
  end
  return NTP_X.parse_mode7(data)
end

local function ntp_mode7_monlist(host, port, args, opts)
  opts = opts or {}
  local result = { enabled = false, attempts = {} }
  local variants = {
    { impl = NTP_T.IMPL_XNTPD, req = NTP_T.REQ_MON_GETLIST_1, label = "monlist v1 (impl 3, code 42)" },
    { impl = NTP_T.IMPL_XNTPD_OLD, req = NTP_T.REQ_MON_GETLIST, label = "monlist legacy (impl 2, code 20)" },
  }
  for _, variant in ipairs(variants) do
    if budget_exhausted(args) then
      result.reason = "request budget exhausted"
      return result
    end
    local resp, err = ntp_mode7_request(host, port, args, variant.impl, variant.req, { wait = opts.wait or 2 })
    local attempt = { variant = variant.label, request_bytes = 48 }
    if resp == nil then
      attempt.outcome = "no response: " .. tostring(err)
      result.attempts[#result.attempts + 1] = attempt
    else
      attempt.err = resp.err
      attempt.err_name = resp.err_name
      attempt.nitems = resp.nitems
      attempt.item_size = resp.item_size
      attempt.response_bytes = 8 + #resp.data
      attempt.amplification = attempt.response_bytes / 48
      result.attempts[#result.attempts + 1] = attempt
      if resp.err == 0 and resp.nitems > 0 and resp.item_size > 0 and #resp.entries > 0 then
        result.enabled = true
        result.variant = variant.label
        result.nitems = resp.nitems
        result.item_size = resp.item_size
        result.entries_seen = #resp.entries
        result.truncated = resp.truncated
        result.response_bytes = attempt.response_bytes
        result.amplification = attempt.amplification
        result.sources = {}
        for i, entry in ipairs(resp.entries) do
          local mon = NTP_X.parse_mon_entry(entry)
          if mon.src_ip then
            result.sources[#result.sources + 1] = mon
          end
          if i >= NTP_T.MON_MAX_ENTRIES then
            break
          end
        end
        break
      elseif resp.err ~= 0 then
        result.last_err = resp.err
        result.last_err_name = resp.err_name
      end
    end
  end
  return result
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

local function ntp_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - NTP audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The NTP audit did not complete against this target", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function ntp_exchange(host, port, args, opts)
  local parsed, err, sess = ntp_client_exchange(host, port, args, opts or {})
  return parsed, err, sess
end

local function ntp_control_open(host, port, args)
  local resp, err = ntp_mode6_query(host, port, args, {
    op = NTP_T.CTLOP_READVAR,
    assoc = 0,
    data = NTP_T.MODE6_VAR_LIST,
  })
  if resp == nil then
    return false, nil, tostring(err)
  end
  return not resp.error, resp, "ok"
end

local function run_audit(host, port, args)
  local sections = {}
  local list, err = ntp_mode6_readlist(host, port, args)
  if list == nil then
    return ntp_incomplete("mode 6 readstat failed: " .. tostring(err), sections, "control", err)
  end
  if list.error then
    add_finding("INFO", "Configuration dump refused (mode 6 error flag on readstat)", {
      subject = "config-dump",
      evidence = "opcode " .. list.op_name .. " refused",
      confidence = "high",
    })
    local out = new_output(RISK_LEVEL, "SECURE - configuration surface refused without authentication")
    local unique, counts = dedupe_findings()
    sections[#sections + 1] = { key = "Control Response", value = { error_flag = "true", opcode = list.op_name } }
    sections[#sections + 1] = { key = "Remediation", value = { ["1. Maintain"] = "Keep mode 6 control closed to untrusted networks." } }
    return finish_output(out, unique, counts, sections)
  end

  local dump = {}
  local dumped = 0
  for _, row in ipairs(list.assoc_rows) do
    if dumped >= (args.maxassocs or 4) or budget_exhausted(args) then
      break
    end
    local vars_resp, verr = ntp_mode6_query(host, port, args, {
      op = NTP_T.CTLOP_READVAR,
      assoc = row.id,
      data = "srcadr,srcport,stratum,flags,peerflags,refid",
    })
    local entry = {
      assoc_id = tostring(row.id),
      status = string.format("0x%04x", row.status_raw),
      broadcast_bit = tostring(row.broadcast),
      authentic_bit = tostring(row.authentic),
    }
    if vars_resp ~= nil and not vars_resp.error and vars_resp.vars.srcadr ~= nil then
      entry.srcadr = vars_resp.vars.srcadr
      entry.srcport = vars_resp.vars.srcport or "n/a"
      entry.stratum = vars_resp.vars.stratum or "n/a"
      entry.flags = vars_resp.vars.flags or "n/a"
      entry.peerflags = vars_resp.vars.peerflags or "n/a"
      entry.refid = vars_resp.vars.refid or "n/a"
    else
      entry.variables = "readvar refused: " .. tostring(verr or (vars_resp and vars_resp.op_name) or "unknown")
    end
    dump[#dump + 1] = entry
    dumped = dumped + 1
  end
  sections[#sections + 1] = { key = "Peer Configuration Dump", value = dump }

  local remediation = {}
  local status_text
  if #dump > 0 and dump[1].srcadr ~= nil then
    local addrs = {}
    for _, entry in ipairs(dump) do
      if entry.srcadr ~= nil then
        addrs[#addrs + 1] = entry.srcadr
      end
    end
    status_text = "VULNERABLE - full peer configuration readable without authentication (" .. tostring(#dump) .. " association(s): " .. table.concat(addrs, ", ") .. ")"
    add_finding("CRITICAL", "Unauthenticated mode 6 chain dumps peer configuration", {
      subject = "config-dump",
      evidence = "readstat + readvar chain returned " .. tostring(#dump) .. " association record(s) with addresses and flags",
      confidence = "high",
      cvss = 8.2,
    })
    remediation["1. Lock down"] = "Apply 'restrict default noquery nomodify' immediately; this interface often also accepts writes."
    remediation["2. Compensate"] = "Firewall UDP 123 control packets (mode 6) at the perimeter while reconfiguring."
  elseif #dump > 0 then
    status_text = "INFORMATIONAL - association IDs disclosed but per-assoc variables refused"
    add_finding("LOW", "Partial mode 6 disclosure (assoc list readable, variables protected)", {
      subject = "config-dump",
      evidence = tostring(#dump) .. " assoc id(s) readable; readvar refused",
      confidence = "high",
    })
    remediation["1. Tighten"] = "Restrict mode 6 readstat as well (noquery covers both opcodes)."
  else
    status_text = "INFORMATIONAL - control interface answered with no associations to dump"
    add_finding("LOW", "Mode 6 endpoint reachable with an empty association table", {
      subject = "config-dump",
      evidence = "readstat answered, count=" .. tostring(list.count),
      confidence = "medium",
    })
    remediation["1. Review"] = "Confirm the answering endpoint is approved."
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
