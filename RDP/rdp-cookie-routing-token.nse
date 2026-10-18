local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Tests whether the RDP endpoint honours the X.224 routing token
("Cookie: mstshash=...") used by session brokers and load balancers to
pin a client to a specific target server.

Why it matters
- Cookie-aware endpoints indicate a broker/farm in front of the host,
  which changes how session redirection and shadowing behave.
- Servers that ignore routing tokens can break farm affinity and leak
  connections to the wrong member.

What the script does
1. Opens two connections sending different mstshash cookies.
2. Compares the confirm PDUs for differences that indicate token
   processing (routing echo, distinct confirm shapes).
3. Reports whether the endpoint appears cookie-aware.

Safe operation: two negotiation exchanges with benign random cookies.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  3389,
  "ms-wbt-server",
  "tcp"
)

local SCRIPT_NAME = "rdp-cookie-routing-token"

local RISK_LEVEL = "🟢 LOW"

local DEFAULT_ARGS = {
  maxrequests = 24,
  timeout = 8,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
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

local RDP_T = {
  TPKT_VERSION = 3,
  X224_CR = 0xE0,
  X224_CC = 0xD0,
  X224_DR = 0x80,
  X224_DC = 0xC0,
  X224_DT = 0xF0,
  X224_ED = 0xF4,
  NEG_REQ = 0x01,
  NEG_RSP = 0x02,
  NEG_FAILURE = 0x03,
  PROTO_RDP = 0x00000000,
  PROTO_SSL = 0x00000001,
  PROTO_HYBRID = 0x00000002,
  PROTO_RDSTLS = 0x00000004,
  PROTO_HYBRID_EX = 0x00000008,
  PROTO_RDSAAD = 0x00000010,
  FAIL_SSL_REQUIRED = 0x01,
  FAIL_SSL_NOT_ALLOWED = 0x02,
  FAIL_SSL_CERT_NOT_ON_SERVER = 0x03,
  FAIL_INCONSISTENT_FLAGS = 0x04,
  FAIL_HYBRID_REQUIRED = 0x05,
  FAIL_SSL_WITH_USER_AUTH_REQUIRED = 0x06,
  FAIL_PASSWORD_EXPIRED = 0x07,
  FAIL_PASSWORD_MUST_CHANGE = 0x08,
  FAIL_INVALID_CREDENTIALS = 0x09,
  FAIL_NEGO_ALERT_5 = 0x0A,
  FAIL_REVOKED_CERT = 0x0B,
  FAIL_MFA_REQUIRED = 0x0D,
  TSREQUEST_VERSION_MIN = 1,
  TSREQUEST_VERSION_MAX = 6,
  UDP_VERSION = 0x02,
  UDP_SYN = 0x03,
  UDP_SYNACK = 0x00,
  UDP_ACK = 0x10,
}

local RDP_N = {
  NTLM_SIG = "NTLMSSP\0",
  NTLM_TYPE1 = 0x01,
  NTLM_TYPE2 = 0x02,
  NTLM_TYPE3 = 0x03,
  NTLM_FLAG_NEGOTIATE_56 = 0x80000000,
  NTLM_FLAG_NEGOTIATE_KEY_EXCH = 0x40000000,
  NTLM_FLAG_NEGOTIATE_128 = 0x20000000,
  NTLM_FLAG_NEGOTIATE_VERSION = 0x02000000,
  NTLM_FLAG_NEGOTIATE_TARGET_INFO = 0x00800000,
  NTLM_FLAG_NEGOTIATE_NTLM2 = 0x00080000,
  NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN = 0x00008000,
  NTLM_FLAG_NEGOTIATE_NTLM = 0x00000200,
  NTLM_FLAG_NEGOTIATE_DOMAIN_SUPPLIED = 0x00001000,
  NTLM_FLAG_NEGOTIATE_OEM = 0x00000002,
  NTLM_FLAG_NEGOTIATE_UNICODE = 0x00000001,
  AV_NB_COMPUTER_NAME = 0x01,
  AV_NB_DOMAIN_NAME = 0x02,
  AV_DNS_COMPUTER_NAME = 0x03,
  AV_DNS_DOMAIN_NAME = 0x04,
  AV_DNS_TREE_NAME = 0x05,
  AV_FLAGS = 0x06,
  AV_TIMESTAMP = 0x07,
  AV_SINGLE_HOST = 0x08,
  AV_TARGET_NAME = 0x09,
  AV_CHANNEL_BINDINGS = 0x0A,
  NTLM_OID = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a",
}

local RDP_G = {
  MCS_CONNECT_INITIAL = 0x65,
  MCS_CONNECT_RESPONSE = 0x66,
  MCS_ERECT_DOMAIN = 0x01,
  MCS_ATTACH_USER = 0x28,
  MCS_CHANNEL_JOIN = 0x38,
  CS_CORE = 0xC001,
  CS_SECURITY = 0xC002,
  CS_NET = 0xC003,
  CS_CLUSTER = 0xC004,
  SC_CORE = 0x0C01,
  SC_SECURITY = 0x0C02,
  SC_NET = 0x0C03,
  EARLY_CAP_SUPPORT_BMP_CODES = 0x02,
  EARLY_CAP_SUPPORT_FONT_SMOOTH = 0x08,
  EARLY_CAP_SUPPORT_DWM = 0x10,
  EARLY_CAP_SUPPORT_AERO = 0x100,
  EARLY_CAP_SUPPORT_DYN_VC = 0x0040,
  EARLY_CAP_SUPPORT_SKIP_CHANNELJOIN = 0x08000000,
}

local RDP_B = {}
local RDP_X = {}
local RDP_A = {}
local RDP_M = {}

RDP_B.rdp_u16 = function(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

RDP_B.rdp_u32 = function(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

RDP_B.rdp_u16le = function(n)
  return string.char(n % 256, math.floor(n / 256) % 256)
end

RDP_B.rdp_u32le = function(n)
  return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

RDP_B.rdp_b16 = function(b)
  return b:byte(1) * 256 + b:byte(2)
end

RDP_B.rdp_b32 = function(b)
  return b:byte(1) * 16777216 + b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
end

RDP_B.rdp_b16le = function(b)
  return b:byte(1) + b:byte(2) * 256
end

RDP_B.rdp_b32le = function(b)
  return b:byte(1) + b:byte(2) * 256 + b:byte(3) * 65536 + b:byte(4) * 16777216
end

RDP_X.rdp_tpkt_encode = function(payload)
  return string.char(RDP_T.TPKT_VERSION, 0) .. RDP_B.rdp_u16(4 + #payload) .. payload
end

RDP_X.rdp_tpkt_decode = function(buf, off)
  off = off or 1
  if #buf < off + 3 then
    return nil, "truncated-tpkt-header"
  end
  local ver = buf:byte(off)
  if ver ~= RDP_T.TPKT_VERSION then
    return nil, "bad-tpkt-version-" .. string.format("0x%02x", ver)
  end
  local len = RDP_B.rdp_b16(buf:sub(off + 2, off + 3))
  if len < 4 then
    return nil, "bad-tpkt-length-" .. tostring(len)
  end
  if #buf < off + len - 1 then
    return nil, "incomplete-tpkt-" .. tostring(len - (#buf - off + 1))
  end
  return buf:sub(off + 4, off + len - 1), len
end

RDP_X.rdp_tpkt_stream_extract = function(buf)
  local msgs = {}
  local off = 1
  while off + 3 <= #buf do
    if buf:byte(off) ~= RDP_T.TPKT_VERSION then
      break
    end
    local payload, len = RDP_X.rdp_tpkt_decode(buf, off)
    if payload == nil then
      break
    end
    msgs[#msgs + 1] = payload
    off = off + len
  end
  return msgs, off
end

RDP_X.rdp_neg_req = function(protocols, flags)
  return string.char(RDP_T.NEG_REQ, flags or 0x08) .. RDP_B.rdp_u16(8) .. RDP_B.rdp_u32(protocols)
end

RDP_X.rdp_x224_cr = function(opts)
  opts = opts or {}
  local body = RDP_B.rdp_u16(0x1234) .. RDP_B.rdp_u16(0) .. string.char(0x00)
  local pieces = {}
  local cookie = opts.cookie
  if cookie == nil then
    local hash_chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    local seed = (os.time() % 9000) + (math.random(900) or 1)
    local h = {}
    for i = 1, 9 do
      seed = (seed * 31 + i * 7) % 36
      h[#h + 1] = hash_chars:sub(seed + 1, seed + 1)
    end
    cookie = table.concat(h)
  end
  pieces[#pieces + 1] = "Cookie: mstshash=" .. cookie .. "\r\n"
  if opts.protocols ~= nil then
    pieces[#pieces + 1] = RDP_X.rdp_neg_req(opts.protocols, opts.neg_flags)
  end
  body = body .. table.concat(pieces)
  return RDP_X.rdp_tpkt_encode(string.char(RDP_T.X224_CR, #body + 6) .. body)
end

RDP_X.rdp_x224_cr_payload_len_match = function(payload)
  local claimed = payload:byte(2)
  if claimed ~= #payload then
    return false, claimed, #payload
  end
  return true
end

RDP_X.rdp_x224_parse = function(payload)
  if payload == nil or #payload < 7 then
    return nil, "short-x224"
  end
  local msg = {
    type = payload:byte(1),
    length_byte = payload:byte(2),
    dst_ref = RDP_B.rdp_b16(payload:sub(3, 4)),
    src_ref = RDP_B.rdp_b16(payload:sub(5, 6)),
    class = payload:byte(7),
    has_neg = false,
    raw = payload,
  }
  local ok, claimed, actual = RDP_X.rdp_x224_cr_payload_len_match(payload)
  msg.length_byte_consistent = ok
  msg.claimed_length = claimed
  msg.actual_length = actual
  local off = 8
  while off + 8 <= #payload - 8 + 1 and off <= #payload do
    local head = payload:byte(off)
    if head == 0x0A then
      local nlo = payload:byte(off + 1)
      if nlo == nil or off + 2 + nlo > #payload then
        break
      end
      msg.cookie = payload:sub(off + 2, off + 1 + nlo)
      msg.cookie_len = nlo
      off = off + 2 + nlo
    elseif payload:sub(off, off + 7) == "Cookie: " then
      local endl = payload:find("\r\n", off, true)
      if endl == nil then
        break
      end
      msg.cookie = payload:sub(off, endl + 1)
      msg.cookie_len = #msg.cookie
      off = endl + 2
    else
      break
    end
  end
  for nstart = math.max(off, 1), #payload - 7 do
    local ntype = payload:byte(nstart)
    if ntype == RDP_T.NEG_REQ or ntype == RDP_T.NEG_RSP or ntype == RDP_T.NEG_FAILURE then
      local declared = RDP_B.rdp_b16(payload:sub(nstart + 2, nstart + 3))
      local available = #payload - nstart + 1
      if declared >= 8 and declared <= available then
        msg.has_neg = true
        msg.neg = {
          type = ntype,
          flags = payload:byte(nstart + 1),
          length = declared,
          protocols = RDP_B.rdp_b32(payload:sub(nstart + 4, nstart + 7)),
          failure_code = nil,
        }
        if ntype == RDP_T.NEG_FAILURE and declared >= 9 then
          msg.neg.failure_code = payload:byte(nstart + 8)
        end
        break
      end
    end
  end
  return msg
end

RDP_X.rdp_selected_name = function(bits)
  if bits == nil then
    return "unknown"
  end
  local names = {}
  if bits == RDP_T.PROTO_RDP then
    return "standard-rdp-security"
  end
  if math.floor(bits / RDP_T.PROTO_RDSAAD) % 2 == 1 then
    names[#names + 1] = "RDSAAD"
  end
  if math.floor(bits / RDP_T.PROTO_HYBRID_EX) % 2 == 1 then
    names[#names + 1] = "HYBRID_EX"
  end
  if math.floor(bits / RDP_T.PROTO_RDSTLS) % 2 == 1 then
    names[#names + 1] = "RDSTLS"
  end
  if math.floor(bits / RDP_T.PROTO_HYBRID) % 2 == 1 then
    names[#names + 1] = "HYBRID"
  end
  if math.floor(bits / RDP_T.PROTO_SSL) % 2 == 1 then
    names[#names + 1] = "SSL"
  end
  if #names == 0 then
    return string.format("0x%08x", bits)
  end
  return table.concat(names, "|")
end

RDP_X.rdp_neg_type_name = function(t)
  if t == RDP_T.NEG_REQ then
    return "neg-req"
  elseif t == RDP_T.NEG_RSP then
    return "neg-rsp"
  elseif t == RDP_T.NEG_FAILURE then
    return "neg-failure"
  end
  return "none"
end

RDP_X.rdp_failure_name = function(code)
  local names = {
    [RDP_T.FAIL_SSL_REQUIRED] = "SSL_REQUIRED_BY_SERVER",
    [RDP_T.FAIL_SSL_NOT_ALLOWED] = "SSL_NOT_ALLOWED_BY_SERVER",
    [RDP_T.FAIL_SSL_CERT_NOT_ON_SERVER] = "SSL_CERT_NOT_ON_SERVER",
    [RDP_T.FAIL_INCONSISTENT_FLAGS] = "INCONSISTENT_FLAGS",
    [RDP_T.FAIL_HYBRID_REQUIRED] = "HYBRID_REQUIRED_BY_SERVER",
    [RDP_T.FAIL_SSL_WITH_USER_AUTH_REQUIRED] = "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
    [RDP_T.FAIL_PASSWORD_EXPIRED] = "PASSWORD_EXPIRED",
    [RDP_T.FAIL_PASSWORD_MUST_CHANGE] = "PASSWORD_MUST_CHANGE",
    [RDP_T.FAIL_INVALID_CREDENTIALS] = "INVALID_CREDENTIALS",
    [RDP_T.FAIL_NEGO_ALERT_5] = "NEGO_ALERT_5",
    [RDP_T.FAIL_REVOKED_CERT] = "REVOKED_CERT",
    [RDP_T.FAIL_MFA_REQUIRED] = "MFA_REQUIRED_BY_SERVER",
  }
  return names[code] or string.format("UNKNOWN_%d", code or -1)
end

RDP_A.rdp_ntlm_type1 = function(opts)
  opts = opts or {}
  local flags = opts.flags or (RDP_N.NTLM_FLAG_NEGOTIATE_KEY_EXCH + RDP_N.NTLM_FLAG_NEGOTIATE_128
    + RDP_N.NTLM_FLAG_NEGOTIATE_VERSION + RDP_N.NTLM_FLAG_NEGOTIATE_TARGET_INFO
    + RDP_N.NTLM_FLAG_NEGOTIATE_NTLM2 + RDP_N.NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN
    + RDP_N.NTLM_FLAG_NEGOTIATE_NTLM + RDP_N.NTLM_FLAG_NEGOTIATE_UNICODE)
  local body = RDP_B.rdp_u32le(0) .. RDP_B.rdp_u32le(flags)
    .. RDP_B.rdp_u16le(0) .. RDP_B.rdp_u16le(0) .. RDP_B.rdp_u32le(0)
    .. RDP_B.rdp_u16le(0) .. RDP_B.rdp_u16le(0) .. RDP_B.rdp_u32le(0)
  if math.floor(flags / RDP_N.NTLM_FLAG_NEGOTIATE_VERSION) % 2 == 1 then
    body = body .. string.char(opts.os_major or 0x06, opts.os_minor or 0x01, 0x00, 0x00)
      .. RDP_B.rdp_u16le(opts.os_build or 7601) .. string.char(0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00)
  end
  return RDP_N.NTLM_SIG .. string.char(RDP_N.NTLM_TYPE1) .. body
end

RDP_A.rdp_ntlm_parse_fields = function(msg)
  local out = {
    valid = false,
    type = nil,
    target_name = nil,
    flags = 0,
    os_major = nil,
    os_minor = nil,
    os_build = nil,
    av = {},
    av_host = nil,
    av_domain = nil,
    av_dnsdomain = nil,
    av_dnshost = nil,
    av_flags = nil,
    av_timestamp = nil,
    has_version = false,
  }
  if msg == nil or #msg < 12 then
    return out, "short-ntlm"
  end
  if msg:sub(1, 8) ~= RDP_N.NTLM_SIG then
    return out, "bad-ntlm-signature"
  end
  local mtype = msg:byte(9)
  out.type = mtype
  if mtype ~= RDP_N.NTLM_TYPE2 then
    return out, "not-type2"
  end
  local target_len = RDP_B.rdp_b16le(msg:sub(13, 14))
  local target_alloc = RDP_B.rdp_b16le(msg:sub(15, 16))
  local target_off = RDP_B.rdp_b32le(msg:sub(17, 20))
  if target_len > 0 and target_off + target_len - 1 <= #msg then
    out.target_name = msg:sub(target_off + 1, target_off + target_len)
  end
  out.target_alloc_consistent = (target_len == target_alloc)
  out.flags = RDP_B.rdp_b32le(msg:sub(21, 24))
  if #msg >= 56 and math.floor(out.flags / RDP_N.NTLM_FLAG_NEGOTIATE_VERSION) % 2 == 1 then
    local vmaj = msg:byte(49)
    local vmin = msg:byte(50)
    local build = RDP_B.rdp_b16le(msg:sub(51, 52))
    out.os_major = vmaj
    out.os_minor = vmin
    out.os_build = build
    out.has_version = (vmaj ~= 0 or build ~= 0)
  end
  if #msg >= 48 and math.floor(out.flags / RDP_N.NTLM_FLAG_NEGOTIATE_TARGET_INFO) % 2 == 1 then
    local ti_len = RDP_B.rdp_b16le(msg:sub(41, 42))
    local ti_off = RDP_B.rdp_b32le(msg:sub(45, 48))
    local endp = math.min(ti_off + ti_len, #msg + 1)
    local off = ti_off + 1
    while off + 4 <= endp and off + 4 <= #msg do
      local aid = RDP_B.rdp_b16le(msg:sub(off, off + 1))
      local alen = RDP_B.rdp_b16le(msg:sub(off + 2, off + 3))
      if alen < 0 or off + 4 + alen > #msg + 1 then
        break
      end
      local val = msg:sub(off + 4, off + 3 + alen)
      out.av[aid] = val
      if aid == RDP_N.AV_NB_COMPUTER_NAME then
        out.av_host = val
      elseif aid == RDP_N.AV_NB_DOMAIN_NAME then
        out.av_domain = val
      elseif aid == RDP_N.AV_DNS_DOMAIN_NAME then
        out.av_dnsdomain = val
      elseif aid == RDP_N.AV_DNS_COMPUTER_NAME then
        out.av_dnshost = val
      elseif aid == RDP_N.AV_FLAGS then
        out.av_flags = RDP_B.rdp_b32le(val .. "\0\0\0\0")
      elseif aid == RDP_N.AV_TIMESTAMP then
        out.av_timestamp = val
      end
      off = off + 4 + alen
    end
  end
  out.valid = true
  return out
end

RDP_A.rdp_ntlm_flag_list = function(flags)
  local names = {}
  local ordered = {
    { RDP_N.NTLM_FLAG_NEGOTIATE_56, "56-bit" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_KEY_EXCH, "key-exchange" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_128, "128-bit" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_VERSION, "version" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_TARGET_INFO, "target-info" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_NTLM2, "ntlm2" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN, "always-sign" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_NTLM, "ntlm" },
    { RDP_N.NTLM_FLAG_NEGOTIATE_UNICODE, "unicode" },
  }
  for _, item in ipairs(ordered) do
    if math.floor(flags / item[1]) % 2 == 1 then
      names[#names + 1] = item[2]
    end
  end
  if #names == 0 then
    names = { "none" }
  end
  return names
end

RDP_A.rdp_av_name = function(id)
  local names = {
    [RDP_N.AV_NB_COMPUTER_NAME] = "MsvAvNbComputerName",
    [RDP_N.AV_NB_DOMAIN_NAME] = "MsvAvNbDomainName",
    [RDP_N.AV_DNS_COMPUTER_NAME] = "MsvAvDnsComputerName",
    [RDP_N.AV_DNS_DOMAIN_NAME] = "MsvAvDnsDomainName",
    [RDP_N.AV_DNS_TREE_NAME] = "MsvAvDnsTreeName",
    [RDP_N.AV_FLAGS] = "MsvAvFlags",
    [RDP_N.AV_TIMESTAMP] = "MsvAvTimestamp",
    [RDP_N.AV_SINGLE_HOST] = "MsvAvSingleHost",
    [RDP_N.AV_TARGET_NAME] = "MsvAvTargetName",
    [RDP_N.AV_CHANNEL_BINDINGS] = "MsvAvChannelBindings",
  }
  return names[id] or string.format("Av_%d", id)
end

local RDP_SPNEGO_OID = "\x2b\x06\x01\x05\x05\x02"

RDP_A.rdp_der_len = function(n)
  if n < 128 then
    return string.char(n)
  end
  local bytes = {}
  local v = n
  while v > 0 do
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  end
  return string.char(0x80 + #bytes) .. table.concat(bytes)
end

RDP_A.rdp_der = function(tag, content)
  return string.char(tag) .. RDP_A.rdp_der_len(#content) .. content
end

RDP_A.rdp_der_tlv = function(data, off)
  off = off or 1
  if #data < off + 1 then
    return nil, "short-der"
  end
  local tag = data:byte(off)
  local pos = off + 1
  if #data < pos then
    return nil, "short-der-len"
  end
  local first = data:byte(pos)
  local len = 0
  local hdr = 2
  if first < 0x80 then
    len = first
  else
    local nlen = first - 0x80
    hdr = 2 + nlen
    if nlen > 4 or #data < pos + nlen then
      return nil, "bad-der-len"
    end
    for i = 1, nlen do
      len = len * 256 + data:byte(pos + i)
    end
  end
  return {
    tag = tag,
    class = math.floor(tag / 0xC0),
    constructed = (math.floor(tag / 0x20) % 2 == 1),
    header = hdr,
    off = off,
    content_off = off + hdr,
    content_len = len,
    total = hdr + len,
  }, data:sub(off + hdr, off + hdr + len - 1)
end

RDP_A.rdp_der_children = function(data, off, limit)
  local kids = {}
  local pos = off or 1
  local guard = 0
  while pos <= #data and guard < (limit or 64) do
    guard = guard + 1
    local node, content = RDP_A.rdp_der_tlv(data, pos)
    if node == nil then
      break
    end
    node.content = content
    kids[#kids + 1] = node
    pos = pos + node.total
  end
  return kids
end

RDP_A.rdp_tsrequest_encode = function(version, nego_token)
  local version_field = "\xa0\x03\x02\x01" .. string.char(version)
  local tok_field = ""
  if nego_token ~= nil and #nego_token > 0 then
    local inner = RDP_A.rdp_der(0xA0, nego_token)
    local seq = RDP_A.rdp_der(0x30, inner)
    tok_field = RDP_A.rdp_der(0xA1, seq)
  end
  return RDP_A.rdp_der(0x30, version_field .. tok_field)
end

RDP_A.rdp_tsrequest_parse = function(der)
  local out = { version = nil, nego_tokens = {}, auth_info = nil, pub_key_auth = nil, error_code = nil, valid = false }
  if der == nil or #der < 2 then
    return out, "short-tsrequest"
  end
  local root, content = RDP_A.rdp_der_tlv(der, 1)
  if root == nil or root.tag ~= 0x30 then
    return out, "bad-tsrequest-envelope"
  end
  local kids = RDP_A.rdp_der_children(content, 1)
  for _, k in ipairs(kids) do
    if k.tag == 0xA0 then
      local vkids = RDP_A.rdp_der_children(k.content, 1)
      for _, vk in ipairs(vkids) do
        if vk.tag == 0x02 and #vk.content >= 1 then
          out.version = vk.content:byte(1)
        end
      end
    elseif k.tag == 0xA1 then
      local seqs = RDP_A.rdp_der_children(k.content, 1)
      for _, sq in ipairs(seqs) do
        local elems = RDP_A.rdp_der_children(sq.content, 1)
        for _, el in ipairs(elems) do
          if el.tag == 0xA0 then
            local leaves = RDP_A.rdp_der_children(el.content, 1)
            if #leaves == 1 and leaves[1].tag == 0x04 then
              out.nego_tokens[#out.nego_tokens + 1] = leaves[1].content
            else
              out.nego_tokens[#out.nego_tokens + 1] = el.content
            end
          elseif el.tag == 0x04 then
            out.nego_tokens[#out.nego_tokens + 1] = el.content
          end
        end
      end
    elseif k.tag == 0xA2 then
      out.auth_info = k.content
    elseif k.tag == 0xA3 then
      out.pub_key_auth = k.content
    elseif k.tag == 0xA4 then
      local ekids = RDP_A.rdp_der_children(k.content, 1)
      for _, ek in ipairs(ekids) do
        if ek.tag == 0x02 and #ek.content >= 1 then
          out.error_code = ek.content:byte(1)
        end
      end
    end
  end
  out.valid = (out.version ~= nil or #out.nego_tokens > 0)
  return out
end

RDP_A.rdp_spnego_negotiate = function(ntlm_type1)
  local mech = RDP_A.rdp_der(0x06, RDP_SPNEGO_OID)
  local mech_seq = RDP_A.rdp_der(0x30, mech)
  local mech_list = RDP_A.rdp_der(0xA0, mech_seq)
  local ntlm_mech = RDP_A.rdp_der(0x06, RDP_N.NTLM_OID)
  local ntlm_token = RDP_A.rdp_der(0xA0, ntlm_mech .. RDP_A.rdp_der(0xA2, RDP_A.rdp_der(0x04, ntlm_type1)))
  return RDP_A.rdp_der(0x30, mech_list .. ntlm_token)
end

RDP_A.rdp_spnego_parse_challenge = function(token)
  if token == nil or #token < 2 then
    return nil, "empty-spnego"
  end
  local function find_octet(data, depth)
    if data == nil or #data < 2 or depth > 8 then
      return nil
    end
    local kids = RDP_A.rdp_der_children(data, 1)
    for _, k in ipairs(kids) do
      if k.tag == 0x04 and not k.constructed then
        return k.content
      end
      local hit = find_octet(k.content, depth + 1)
      if hit ~= nil then
        return hit
      end
    end
    return nil
  end
  local root, content = RDP_A.rdp_der_tlv(token, 1)
  if root == nil or root.tag ~= 0x30 then
    return nil, "bad-spnego"
  end
  local hit = find_octet(content, 1)
  if hit ~= nil then
    return hit
  end
  return nil, "no-ntlm-token-in-spnego"
end

RDP_M.rdp_ber_int = function(n)
  local parts = {}
  local v = n
  if v == 0 then
    parts[1] = "\0"
  else
    while v > 0 do
      table.insert(parts, 1, string.char(v % 256))
      v = math.floor(v / 256)
    end
    if parts[1]:byte(1) > 127 then
      table.insert(parts, 1, "\0")
    end
  end
  local content = table.concat(parts)
  return string.char(0x02) .. RDP_A.rdp_der_len(#content) .. content
end

RDP_M.rdp_ber_octet = function(s)
  return string.char(0x04) .. RDP_A.rdp_der_len(#s) .. s
end

RDP_M.rdp_mcs_domain_params = function(max_tokens, max_pdu, max_guid, max_send, max_recv, max_throughput)
  local body = RDP_M.rdp_ber_int(max_tokens) .. RDP_M.rdp_ber_int(max_tokens)
    .. RDP_M.rdp_ber_int(max_pdu) .. RDP_M.rdp_ber_int(max_guid)
    .. RDP_M.rdp_ber_int(max_send) .. RDP_M.rdp_ber_int(max_recv)
    .. RDP_M.rdp_ber_int(max_throughput)
  return string.char(0x30) .. RDP_A.rdp_der_len(#body) .. body
end

RDP_M.rdp_gcc_user_data_block = function(block_type, data)
  return RDP_B.rdp_u16le(block_type) .. RDP_B.rdp_u32le(#data + 4) .. data
end

local RDP_CHANNEL_FLAG_INITIATED = 0x00200000
local RDP_CHANNEL_FLAG_COMPRESSED = 0x00400000
local RDP_CHANNEL_FLAG_PRIORITY_LOW = 0x02000000
local RDP_CHANNEL_FLAG_COMPRESS_RDP = 0x00800000
local RDP_CHANNEL_FLAG_SHOW_PROTOCOL = 0x01000000

RDP_M.rdp_utf16le = function(s)
  local out = {}
  for i = 1, #s do
    out[#out + 1] = s:sub(i, i) .. "\0"
  end
  return table.concat(out)
end

RDP_M.rdp_channel_def = function(name, options)
  local nm = name:sub(1, 8)
  while #nm < 8 do
    nm = nm .. "\0"
  end
  return nm .. RDP_B.rdp_u32le(options or 0)
end

RDP_M.rdp_gcc_client_core = function(opts)
  opts = opts or {}
  local data = {}
  data[#data + 1] = RDP_B.rdp_u32le(opts.version or 0x00080004)
  data[#data + 1] = RDP_B.rdp_u16le(opts.desktop_width or 1280)
  data[#data + 1] = RDP_B.rdp_u16le(opts.desktop_height or 800)
  data[#data + 1] = RDP_B.rdp_u16le(opts.color_depth or 0xCA00)
  data[#data + 1] = RDP_B.rdp_u16le(opts.sas or 0xAA03)
  data[#data + 1] = RDP_B.rdp_u32le(opts.kbd_layout or 0x00000409)
  data[#data + 1] = RDP_B.rdp_u32le(opts.client_build or 2600)
  data[#data + 1] = RDP_M.rdp_utf16le((opts.client_name or "auditor"):sub(1, 15) .. "\0")
  while #data[#data] < 32 do
    data[#data] = data[#data] .. "\0"
  end
  data[#data + 1] = RDP_B.rdp_u32le(opts.kbd_type or 0x00000004)
  data[#data + 1] = RDP_B.rdp_u32le(opts.kbd_sub or 0)
  data[#data + 1] = RDP_B.rdp_u32le(opts.kbd_fnkey or 12)
  data[#data + 1] = RDP_B.rdp_u32le(opts.imm_file or 0)
  data[#data + 1] = RDP_B.rdp_u16le(opts.post_beta_depth or 0xCA00)
  data[#data + 1] = RDP_B.rdp_u16le(opts.product_id or 1)
  data[#data + 1] = RDP_B.rdp_u32le(opts.serial or 0)
  data[#data + 1] = RDP_B.rdp_u16le(opts.high_color or 0xCA01)
  data[#data + 1] = RDP_B.rdp_u16le(opts.supported_depths or 0x000F)
  data[#data + 1] = RDP_B.rdp_u16le(opts.early_caps or (RDP_G.EARLY_CAP_SUPPORT_BMP_CODES
    + RDP_G.EARLY_CAP_SUPPORT_DYN_VC))
  local dig = RDP_M.rdp_utf16le((opts.dig_product or ""):sub(1, 31))
  while #dig < 64 do
    dig = dig .. "\0"
  end
  data[#data + 1] = dig
  data[#data + 1] = string.char(opts.connection_type or 6)
  data[#data + 1] = "\0"
  data[#data + 1] = RDP_B.rdp_u32le(opts.selected_protocol or 0)
  return table.concat(data)
end

RDP_M.rdp_gcc_client_security = function(opts)
  opts = opts or {}
  local data = RDP_B.rdp_u32le(opts.encryption_methods or 0x00000003)
    .. RDP_B.rdp_u32le(opts.ext_encryption or 0)
  return data
end

RDP_M.rdp_gcc_client_network = function(channels)
  local defs = {}
  for _, ch in ipairs(channels or {}) do
    defs[#defs + 1] = RDP_M.rdp_channel_def(ch.name, ch.options)
  end
  local payload = RDP_B.rdp_u32le(#(channels or {})) .. table.concat(defs)
  return payload
end

RDP_M.rdp_gcc_cluster = function(opts)
  opts = opts or {}
  return RDP_B.rdp_u32le(opts.flags or 0xA)
    .. string.char(opts.redirected_session and 0x01 or 0x00, 0x00, 0x00, 0x00)
end

RDP_M.rdp_gcc_connect_initial = function(opts)
  opts = opts or {}
  local blocks = RDP_M.rdp_gcc_user_data_block(RDP_G.CS_CORE, RDP_M.rdp_gcc_client_core(opts))
    .. RDP_M.rdp_gcc_user_data_block(RDP_G.CS_SECURITY, RDP_M.rdp_gcc_client_security(opts))
    .. RDP_M.rdp_gcc_user_data_block(RDP_G.CS_CLUSTER, RDP_M.rdp_gcc_cluster(opts))
  if opts.channels ~= nil and #opts.channels > 0 then
    blocks = blocks .. RDP_M.rdp_gcc_user_data_block(RDP_G.CS_NET, RDP_M.rdp_gcc_client_network(opts.channels))
  end
  local gcc = "\x01" .. RDP_B.rdp_u16le(7 + #blocks) .. "\x00" .. RDP_B.rdp_u16le(0x4474)
    .. RDP_B.rdp_u16le(#blocks) .. blocks
  local called = RDP_M.rdp_ber_octet("Proxy")
  local body = RDP_M.rdp_mcs_domain_params(34, 65535, 8192, 3, 3, 2097152)
    .. RDP_M.rdp_mcs_domain_params(29, 65458, 8192, 3, 3, 2097152)
    .. called
    .. RDP_A.rdp_der(0x04, gcc)
  local conn = string.char(RDP_G.MCS_CONNECT_INITIAL) .. RDP_A.rdp_der_len(#body) .. body
  local data_pdu = string.char(0x02, RDP_T.X224_DT, 0x80) .. conn
  return RDP_X.rdp_tpkt_encode(data_pdu)
end

RDP_M.rdp_gcc_parse_user_blocks = function(data)
  local blocks = {}
  local off = 1
  while off + 6 <= #data do
    local btype = RDP_B.rdp_b16le(data:sub(off, off + 1))
    local blen = RDP_B.rdp_b32le(data:sub(off + 2, off + 5))
    if blen < 4 or off + blen > #data + 1 then
      break
    end
    blocks[#blocks + 1] = { type = btype, data = data:sub(off + 6, off + blen - 1) }
    off = off + blen
  end
  return blocks
end

RDP_M.rdp_gcc_parse_server_core = function(data)
  local out = { version = nil, requested_protocols = nil, early_caps = nil, valid = false }
  if #data < 4 then
    return out
  end
  out.version = RDP_B.rdp_b32le(data:sub(1, 4))
  local off = 5
  if #data >= off + 1 then
    out.client_requested_protocols_present = data:byte(off)
    off = off + 1
    if out.client_requested_protocols_present == 1 and #data >= off + 4 then
      out.requested_protocols = RDP_B.rdp_b32le(data:sub(off, off + 3))
      off = off + 4
    end
  end
  if #data >= off + 4 then
    out.early_caps = RDP_B.rdp_b32le(data:sub(off, off + 3))
  end
  out.valid = true
  return out
end

RDP_M.rdp_gcc_parse_server_security = function(data)
  local out = { encryption_methods = nil, ext_encryption = nil, valid = false }
  if #data < 8 then
    return out
  end
  out.encryption_methods = RDP_B.rdp_b32le(data:sub(1, 4))
  out.ext_encryption = RDP_B.rdp_b32le(data:sub(5, 8))
  out.valid = true
  return out
end

RDP_M.rdp_gcc_parse_server_network = function(data)
  local out = { count = 0, channels = {}, valid = false }
  if #data < 4 then
    return out
  end
  local n = RDP_B.rdp_b32le(data:sub(1, 4))
  if n > 31 then
    return out
  end
  out.count = n
  local off = 5
  for i = 1, n do
    if #data < off + 12 then
      break
    end
    local name = (data:sub(off, off + 7)):gsub("%z", "")
    local opts_bits = RDP_B.rdp_b32le(data:sub(off + 8, off + 11))
    out.channels[#out.channels + 1] = { name = name, options = opts_bits }
    off = off + 12
  end
  out.valid = true
  return out
end

RDP_M.rdp_mcs_connect_response_parse = function(payload)
  local out = { valid = false, server_core = nil, server_security = nil, server_net = nil, raw_gcc = nil }
  if payload == nil or #payload < 5 then
    return out, "short-mcs-response"
  end
  if payload:byte(1) == 0x02 and payload:byte(2) == 0xF0 then
    payload = payload:sub(4)
  end
  if #payload < 5 then
    return out, "short-mcs-response-after-dt"
  end
  local mtype = payload:byte(1)
  if mtype ~= RDP_G.MCS_CONNECT_RESPONSE then
    return out, "not-mcs-connect-response-0x" .. string.format("%02x", mtype or 0)
  end
  local _, root_content = RDP_A.rdp_der_tlv(payload, 1)
  if root_content == nil then
    return out, "bad-mcs-ber"
  end
  local kids = RDP_A.rdp_der_children(root_content, 1)
  local gcc_data = nil
  for _, k in ipairs(kids) do
    if k.tag == 0x04 then
      gcc_data = k.content
    end
  end
  if gcc_data == nil or #gcc_data < 3 then
    return out, "no-gcc-packet"
  end
  out.raw_gcc_len = #gcc_data
  local btype = gcc_data:byte(1)
  if btype ~= 0x01 and btype ~= 0x00 then
    return out, "bad-gcc-type"
  end
  if #gcc_data < 9 then
    return out, "short-gcc"
  end
  local blocks_len = RDP_B.rdp_b16le(gcc_data:sub(7, 8))
  if blocks_len < 4 or 9 + blocks_len - 1 > #gcc_data then
    return out, "bad-gcc-blocks-length"
  end
  local userdata = gcc_data:sub(9, 9 + blocks_len - 1)
  local blocks = RDP_M.rdp_gcc_parse_user_blocks(userdata)
  for _, b in ipairs(blocks) do
    if b.type == RDP_G.SC_CORE then
      out.server_core = RDP_M.rdp_gcc_parse_server_core(b.data)
    elseif b.type == RDP_G.SC_SECURITY then
      out.server_security = RDP_M.rdp_gcc_parse_server_security(b.data)
    elseif b.type == RDP_G.SC_NET then
      out.server_net = RDP_M.rdp_gcc_parse_server_network(b.data)
    end
  end
  out.blocks = blocks
  out.valid = (out.server_core ~= nil)
  return out
end

RDP_M.rdp_udp_syn_encode = function(cookie, src_port)
  local src = src_port or 49152 + (os.time() % 1024)
  local hdr = string.char(RDP_T.UDP_SYN)
    .. RDP_B.rdp_u16(8)
    .. RDP_B.rdp_u16(src)
    .. RDP_B.rdp_u32(cookie or 0)
  return hdr, src
end

RDP_M.rdp_udp_synack_parse = function(data)
  if data == nil or #data < 8 then
    return nil, "short-udp"
  end
  local flags = data:byte(1)
  local len = RDP_B.rdp_b16(data:sub(2, 3))
  local sport = RDP_B.rdp_b16(data:sub(4, 5))
  return {
    flags = flags,
    length = len,
    source_port = sport,
    looks_synack = (flags == RDP_T.UDP_SYNACK or flags == RDP_T.UDP_ACK or data:byte(1) == 0x00),
    raw = data,
  }
end

local function rdp_session_new(host, port, args)
  return {
    host = host,
    port = port or 3389,
    args = args,
    sock = nil,
    connected = false,
    closed = false,
    selected_protocol = nil,
    neg_failure = nil,
    server_plain_cc = false,
    tls_active = false,
    tls_summary = nil,
    server_core = nil,
    server_security = nil,
    server_net = nil,
    ntlm = nil,
    connects = 0,
    sends = 0,
    recvs = 0,
    timeouts = 0,
    errors = 0,
    audit = {},
  }
end

local function rdp_audit(sess, kind, detail)
  sess.audit[#sess.audit + 1] = kind .. ":" .. tostring(detail)
end

local function rdp_connect(sess)
  if sess.connected then
    return 1
  end
  local sock = nmap.new_socket("tcp")
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, "tcp")
  if not ok then
    sock:close()
    return nil, "TCP connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  sess.connects = sess.connects + 1
  rdp_audit(sess, "connect", sess.port)
  return 1
end

local function rdp_close(sess)
  if sess and sess.sock and not sess.closed then
    sess.sock:close()
  end
  if sess then
    sess.closed = true
    sess.connected = false
  end
end

local function rdp_send_raw(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  sess.sends = sess.sends + 1
  rdp_audit(sess, "send", #data)
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function rdp_recv_bytes(sess, want)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  local deadline = os.time() + math.max(1, sess.args.timeout or 8)
  local buf = ""
  while #buf < want do
    if budget_exhausted(sess.args) then
      return nil, "request budget exhausted"
    end
    local remaining = deadline - os.time()
    if remaining <= 0 then
      sess.timeouts = sess.timeouts + 1
      if #buf > 0 then
        return buf
      end
      return nil, "timeout"
    end
    sess.sock:set_timeout(math.min(remaining, 5) * 1000)
    local chunk_size = want - #buf
    local ok, data = sess.sock:receive_bytes(chunk_size)
    if ok and data and #data > 0 then
      buf = buf .. data
      sess.recvs = sess.recvs + 1
    else
      sess.timeouts = sess.timeouts + 1
      if #buf > 0 then
        return buf
      end
      return nil, tostring(data or "timeout")
    end
    if #buf >= want then
      break
    end
  end
  return buf
end

local function rdp_read_tpkt(sess)
  local head, herr = rdp_recv_bytes(sess, 4)
  if head == nil then
    return nil, herr
  end
  if head:byte(1) ~= 3 then
    return nil, "bad-tpkt-version"
  end
  local len = RDP_B.rdp_b16(head:sub(3, 4))
  if len < 4 or len > 65535 then
    return nil, "bad-tpkt-length"
  end
  if len == 4 then
    return ""
  end
  local rest, rerr = rdp_recv_bytes(sess, len - 4)
  if rest == nil then
    return nil, rerr
  end
  return head:sub(5) .. rest
end

local function rdp_negotiate(sess, protocols, opts)
  opts = opts or {}
  local cr = RDP_X.rdp_x224_cr({
    protocols = protocols,
    cookie = opts.cookie,
    neg_flags = opts.neg_flags,
  })
  local ok, serr = rdp_send_raw(sess, cr)
  if not ok then
    return nil, serr
  end
  local payload, rerr = rdp_read_tpkt(sess)
  if payload == nil then
    return nil, rerr
  end
  local msg = RDP_X.rdp_x224_parse(payload)
  if msg == nil then
    return nil, "x224 parse failed"
  end
  local result = {
    type = msg.type,
    plain_cc = (not msg.has_neg),
    cookie_seen = msg.cookie,
    class = msg.class,
    selected = nil,
    failure = nil,
    protocols = nil,
    neg_type = nil,
    raw = payload,
  }
  if msg.has_neg then
    result.neg_type = msg.neg.type
    if msg.neg.type == RDP_T.NEG_RSP then
      result.selected = msg.neg.protocols
    elseif msg.neg.type == RDP_T.NEG_FAILURE then
      result.failure = msg.neg.failure_code
    elseif msg.neg.type == RDP_T.NEG_REQ then
      result.protocols = msg.neg.protocols
    end
  end
  sess.selected_protocol = result.selected
  sess.neg_failure = result.failure
  sess.server_plain_cc = result.plain_cc
  rdp_audit(sess, "neg", RDP_X.rdp_selected_name(result.selected or 0) .. "/" .. tostring(result.failure or ""))
  return result
end

local function rdp_read_optional_tpkt(sess, wait_hint)
  local payload = rdp_read_tpkt(sess)
  if payload == nil then
    rdp_audit(sess, "no-extra-data", wait_hint or "")
    return nil
  end
  return payload
end

local function rdp_tls_upgrade(sess, opts)
  if sess.tls_active then
    return sess.tls_summary
  end
  if tl_client_hello == nil or tl_collect_server_flight == nil or tl_summarize_flight == nil then
    return nil, "tls helpers unavailable"
  end
  local hello = tl_client_hello({
    version = opts.version or 0x0303,
    ciphers = opts.ciphers,
    sni = opts.sni,
    extensions = opts.extensions,
  })
  local ok, serr = rdp_send_raw(sess, hello)
  if not ok then
    return nil, serr
  end
  local flight, alert, ferr = tl_collect_server_flight(sess.sock, opts.flight_limit or 8)
  if flight == nil or #flight == 0 then
    if alert ~= nil then
      return nil, "tls alert: " .. tostring(alert.name or alert.code)
    end
    return nil, ferr or "no tls flight"
  end
  local summary = tl_summarize_flight(flight)
  if summary == nil then
    return nil, "tls flight summarize failed"
  end
  summary.wire_messages = #flight
  if alert ~= nil then
    summary.post_flight_alert = alert.name or alert.code
  end
  sess.tls_active = true
  sess.tls_summary = summary
  rdp_audit(sess, "tls", tl_version_name(summary.version) or "?")
  return summary
end

local function rdp_ntlm_challenge(sess, opts)
  opts = opts or {}
  local type1 = RDP_A.rdp_ntlm_type1({ os_major = opts.os_major, os_minor = opts.os_minor, os_build = opts.os_build })
  local tsreq = RDP_A.rdp_tsrequest_encode(opts.client_version or 6, RDP_A.rdp_spnego_negotiate(type1))
  local wrapped = RDP_X.rdp_tpkt_encode(string.char(0x02, 0xF0, 0x80) .. tsreq)
  local ok, serr = rdp_send_raw(sess, wrapped)
  if not ok then
    return nil, serr
  end
  local payload, rerr = rdp_read_tpkt(sess)
  if payload == nil then
    return nil, rerr
  end
  if payload:byte(1) == 0x02 and payload:byte(2) == 0xF0 then
    payload = payload:sub(4)
  end
  local parsed = RDP_A.rdp_tsrequest_parse(payload)
  if not parsed.valid then
    return nil, "server did not return a TSRequest"
  end
  local result = {
    server_version = parsed.version,
    error_code = parsed.error_code,
    token_count = #parsed.nego_tokens,
    ntlm = nil,
    raw_error = nil,
  }
  if parsed.error_code ~= nil then
    result.raw_error = RDP_X.rdp_failure_name(parsed.error_code)
  end
  for _, tok in ipairs(parsed.nego_tokens) do
    local ntlm_bytes = RDP_A.rdp_spnego_parse_challenge(tok)
    if ntlm_bytes ~= nil then
      local fields, perr = RDP_A.rdp_ntlm_parse_fields(ntlm_bytes)
      if fields and fields.valid then
        result.ntlm = fields
        sess.ntlm = fields
        rdp_audit(sess, "ntlm", tostring(fields.av_host or fields.target_name or "no-av"))
        break
      else
        result.raw_error = perr
      end
    end
  end
  return result
end

local function rdp_mcs_connect(sess, opts)
  opts = opts or {}
  local gcc = RDP_M.rdp_gcc_connect_initial({
    channels = opts.channels,
    version = opts.version,
    desktop_width = opts.desktop_width,
    desktop_height = opts.desktop_height,
    selected_protocol = sess.selected_protocol or opts.selected_protocol or 0,
    early_caps = opts.early_caps,
  })
  local ok, serr = rdp_send_raw(sess, gcc)
  if not ok then
    return nil, serr
  end
  local payload, rerr = rdp_read_tpkt(sess)
  if payload == nil then
    return nil, rerr
  end
  local parsed, perr = RDP_M.rdp_mcs_connect_response_parse(payload)
  if parsed and parsed.valid then
    sess.server_core = parsed.server_core
    sess.server_security = parsed.server_security
    sess.server_net = parsed.server_net
    rdp_audit(sess, "mcs", string.format("0x%04x", parsed.server_core.version or 0))
  else
    rdp_audit(sess, "mcs-fail", tostring(perr))
  end
  return parsed, perr
end

local function rdp_udp_probe(host, port, args)
  args = args or {}
  local sock = nmap.new_socket("udp")
  if not sock then
    return nil, "udp socket allocation failed"
  end
  sock:set_timeout(math.floor((args.timeout or 6) * 1000))
  local ok, err = sock:connect(host, port or 3389, "udp")
  if not ok then
    sock:close()
    return nil, "UDP connect failed: " .. tostring(err or "unknown")
  end
  if budget_exhausted(args) then
    sock:close()
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local cookie = (os.time() % 2147483647) * 2654435761 % 2147483647
  local syn, src = RDP_M.rdp_udp_syn_encode(cookie)
  local sent_ok, send_err = sock:send(syn)
  if not sent_ok then
    sock:close()
    return nil, "udp send failed: " .. tostring(send_err or "unknown")
  end
  local started = os.time()
  local rok, rdata = sock:receive(65535)
  local data = (rok and rdata) or nil
  local elapsed = os.time() - started
  sock:close()
  if data == nil or data == "" then
    return nil, "no udp response"
  end
  local parsed = RDP_M.rdp_udp_synack_parse(data)
  if parsed == nil then
    return { raw_len = #data, parsed = false }
  end
  parsed.rtt_seconds = elapsed
  parsed.client_port = src
  parsed.cookie_echo = (RDP_B.rdp_b16(data:sub(4, 5)) == src) or nil
  return parsed
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

local function rdp_open_session(host, port, args)
  local sess = rdp_session_new(host.ip, port.number, args)
  local ok, err = rdp_connect(sess)
  if not ok then
    return nil, err
  end
  return sess
end

local function rdp_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - RDP audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The RDP audit did not complete against this target", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local RDP_SERVER_VERSION_NAMES = {
  [0x0400] = "RDP 4.0 / Windows NT 4.0 era",
  [0x0500] = "RDP 5.0-5.2 / Windows 2000-XP/2003 era",
  [0x0600] = "RDP 6.0-6.1 / Windows Vista-2008/7 era",
  [0x0601] = "RDP 6.1 / Windows 7 / 2008 R2",
  [0x0800] = "RDP 8.0+ / Windows 8/2012+ era",
  [0x0801] = "RDP 8.1 / Windows 8.1 era",
  [0x0A00] = "RDP 10 / Windows 10/2016+ era",
}

local function rdp_server_version_name(v)
  if v == nil then
    return "unknown"
  end
  return RDP_SERVER_VERSION_NAMES[v] or string.format("0x%04x", v)
end

local function rdp_selected_name(bits)
  return RDP_X.rdp_selected_name(bits)
end

local function rdp_failure_name(code)
  return RDP_X.rdp_failure_name(code)
end

local function rdp_encryption_names(bits)
  local names_map = {
    { 1, "40-bit RC4" },
    { 2, "56-bit RC4" },
    { 8, "128-bit RC4" },
    { 16, "FIPS" },
  }
  if bits == nil then
    return "unknown"
  end
  local names = {}
  for _, item in ipairs(names_map) do
    if math.floor(bits / item[1]) % 2 == 1 then
      names[#names + 1] = item[2]
    end
  end
  if #names == 0 then
    return "none advertised"
  end
  return table.concat(names, ", ")
end

local function run_audit(host, port, args)
  local sections = {}
  local sess, err = rdp_open_session(host, port, args)
  if not sess then
    return rdp_incomplete("no session: " .. tostring(err), sections, "connect", err)
  end

  local cookie_a = "audit" .. tostring((os.time() % 100000))
  local cookie_b = "probe" .. tostring(((os.time() * 7) % 100000))

  local first, first_err = rdp_negotiate(sess, RDP_T.PROTO_SSL + RDP_T.PROTO_HYBRID, { cookie = cookie_a })
  local first_row = stdnse.output_table()
  if first == nil then
    first_row["Result"] = "no confirm: " .. tostring(first_err)
  else
    first_row["Result"] = first.plain_cc and "plain confirm" or (first.failure and rdp_failure_name(first.failure) or rdp_selected_name(first.selected))
    first_row["Cookie sent"] = cookie_a
    first_row["Cookie echoed"] = first.cookie_seen and "yes" or "no"
    first_row["Confirm length"] = tostring(first.raw and #first.raw or 0)
  end
  sections[#sections + 1] = { key = "Probe A", value = first_row }

  local second, second_err = rdp_negotiate(sess, RDP_T.PROTO_SSL + RDP_T.PROTO_HYBRID, { cookie = cookie_b })
  local second_row = stdnse.output_table()
  local responses_differ = false
  if second == nil then
    second_row["Result"] = "no confirm: " .. tostring(second_err)
  else
    second_row["Result"] = second.plain_cc and "plain confirm" or (second.failure and rdp_failure_name(second.failure) or rdp_selected_name(second.selected))
    second_row["Cookie sent"] = cookie_b
    second_row["Cookie echoed"] = second.cookie_seen and "yes" or "no"
    second_row["Confirm length"] = tostring(second.raw and #second.raw or 0)
    if first ~= nil and first.raw ~= nil and second.raw ~= nil then
      responses_differ = (first.raw ~= second.raw)
    end
  end
  sections[#sections + 1] = { key = "Probe B", value = second_row }
  rdp_close(sess)

  local verdict_row = stdnse.output_table()
  verdict_row["Cookie accepted"] = (first ~= nil or second ~= nil) and "yes (confirm received)" or "inconclusive"
  verdict_row["Cookie echoed back"] = ((first and first.cookie_seen) or (second and second.cookie_seen)) and "yes" or "no"
  verdict_row["Responses differ per token"] = responses_differ and "yes (routing behaviour observed)" or "no (single-server behaviour)"
  verdict_row["Interpretation"] = responses_differ and "endpoint appears token-aware" or "no routing differentiation detected"
  sections[#sections + 1] = { key = "Cookie Analysis", value = verdict_row }

  local out = new_output(RISK_LEVEL, "INFORMATIONAL - routing token "
    .. (responses_differ and "influences confirmations (broker-like behaviour)" or "accepted without visible routing effect"))
  add_finding("INFO", "RDP routing token behaviour profiled", {
    subject = "cookie",
    evidence = "differ=" .. tostring(responses_differ),
    confidence = "medium",
  })
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
