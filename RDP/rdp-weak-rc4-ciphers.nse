local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Tests whether the RDP TLS security layer still accepts RC4 cipher
suites by completing a handshake that offers only RC4 suites.

Why it matters
- RC4 in TLS is biased and practically decryptable for reused
  plaintext; compliance regimes (PCI DSS, NIST SP 800-52r2) forbid it.
- RDP endpoints frequently retain legacy cipher configurations because
  old clients are still allowed to connect.

What the script does
1. Negotiates the TLS security layer with the server (or confirms the
   plain legacy path first when the server ignores negotiation).
2. Sends a ClientHello restricted to RC4 suites (128/128-SHA, MD5).
3. Reports the negotiated suite: RC4 acceptance is a finding, refusal
   or a handshake failure proves the legacy suites are disabled.

Safe operation: negotiation and one TLS handshake; no data is sent
through the established channel.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  3389,
  "ms-wbt-server",
  "tcp"
)

local SCRIPT_NAME = "rdp-weak-rc4-ciphers"

local RISK_LEVEL = "🟠 HIGH"

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

local RC4_SUITES = { 0x0005, 0x0004 }

local RC4_SUITE_NAMES = {
  [0x0004] = "TLS_RSA_WITH_RC4_128_MD5",
  [0x0005] = "TLS_RSA_WITH_RC4_128_SHA",
  [0x0013] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
  [0x0016] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
  [0x000A] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
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

local function tl_u16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function tl_u24(n)
  return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function tl_u32(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256)
end

local function tl_b16(b)
  return b:byte(1) * 256 + b:byte(2)
end

local function tl_b24(b)
  return b:byte(1) * 65536 + b:byte(2) * 256 + b:byte(3)
end

local function tl_b32(b)
  return b:byte(1) * 16777216 + b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
end

local function tl_record(type_byte, version, payload)
  return string.char(type_byte) .. tl_u16(version or 0x0303) .. tl_u16(#payload) .. payload
end

local function tl_handshake(type_byte, body)
  return string.char(type_byte) .. tl_u24(#body) .. body
end

local function tl_client_hello(opts)
  opts = opts or {}
  local version = opts.version or 0x0303
  local random = opts.random or string.char(
    0xa1, 0x4f, 0x02, 0x9c, 0x77, 0x1b, 0xd3, 0x40,
    0x55, 0x90, 0xe8, 0x2f, 0x66, 0xab, 0x17, 0xc3,
    0x09, 0xd4, 0x2a, 0x58, 0xb1, 0x3e, 0x88, 0x72,
    0xe6, 0x04, 0xc9, 0xd5, 0x11, 0xfa, 0x6b, 0x20)
  local session_id = opts.session_id or ""
  local ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x009d, 0x1301, 0x1302 }
  local comps = opts.comps or { 0 }
  local list = ""
  for _, c in ipairs(ciphers) do
    list = list .. tl_u16(c)
  end
  local comp_list = ""
  for _, c in ipairs(comps) do
    comp_list = comp_list .. string.char(c)
  end
  local exts = ""
  local function add_ext(id, data)
    exts = exts .. tl_u16(id) .. tl_u16(#data) .. data
  end
  if opts.sni then
    local entry = string.char(0) .. tl_u16(#opts.sni) .. opts.sni
    local inner = tl_u16(#entry) .. entry
    add_ext(0, inner)
  end
  if opts.ems ~= false then
    add_ext(0x0017, string.char(0))
  end
  if opts.alpn then
    local al = ""
    for _, p in ipairs(opts.alpn) do
      al = al .. string.char(#p) .. p
    end
    add_ext(16, tl_u16(#al) .. al)
  end
  if opts.status_request then
    add_ext(5, string.char(1, 0))
  end
  if opts.sig_algs then
    local sa = ""
    for _, s in ipairs(opts.sig_algs) do
      sa = sa .. tl_u16(s)
    end
    add_ext(13, tl_u16(#sa) .. sa)
  end
  if opts.supported_versions then
    local sv = ""
    for _, v in ipairs(opts.supported_versions) do
      sv = sv .. tl_u16(v)
    end
    add_ext(43, string.char(#sv) .. sv)
  end
  if opts.heartbeat then
    add_ext(15, tl_u16(1))
  end
  if opts.renegotiation_info then
    add_ext(0xff01, string.char(1, 0))
  end
  if opts.raw_exts then
    for _, re in ipairs(opts.raw_exts) do
      exts = exts .. tl_u16(re.id) .. tl_u16(#re.data) .. re.data
    end
  end
  local body = tl_u16(opts.record_version or version)
    .. random
    .. string.char(#session_id) .. session_id
    .. tl_u16(#list) .. list
    .. string.char(#comps) .. comp_list
    .. tl_u16(#exts) .. exts
  return tl_record(0x16, version, tl_handshake(0x01, body))
end

local function tl_parse_records(buf)
  local records = {}
  local i = 1
  while i + 4 <= #buf do
    local t = buf:byte(i)
    local v = tl_b16(buf:sub(i + 1, i + 2))
    local l = tl_b16(buf:sub(i + 3, i + 4))
    if i + 4 + l > #buf then
      break
    end
    records[#records + 1] = { type = t, version = v, payload = buf:sub(i + 5, i + 4 + l) }
    i = i + 5 + l
  end
  return records
end

local function tl_parse_handshake_messages(payload)
  local msgs = {}
  local i = 1
  while i + 3 <= #payload do
    local t = payload:byte(i)
    local l = tl_b24(payload:sub(i + 1, i + 3))
    if i + 3 + l > #payload then
      break
    end
    msgs[#msgs + 1] = { type = t, body = payload:sub(i + 4, i + 3 + l) }
    i = i + 4 + l
  end
  return msgs
end

local function tl_parse_extensions(body, off)
  local exts = {}
  if off == nil or off + 2 > #body then
    return exts, off
  end
  local total = tl_b16(body:sub(off, off + 1))
  local end_at = off + 2 + total
  local i = off + 2
  while i + 4 <= end_at and i + 3 <= #body do
    local id = tl_b16(body:sub(i, i + 1))
    local len = tl_b16(body:sub(i + 2, i + 3))
    exts[id] = body:sub(i + 4, i + 3 + len)
    i = i + 4 + len
  end
  return exts, i
end

local function tl_parse_server_hello(body)
  local out = {}
  if #body < 2 then
    return out
  end
  out.version = tl_b16(body:sub(1, 2))
  out.random = #body >= 34 and body:sub(3, 34) or nil
  if #body < 35 then
    return out
  end
  local sid_len = body:byte(35)
  if 35 + sid_len + 3 > #body then
    return out
  end
  out.session_id = body:sub(36, 35 + sid_len)
  local ci = 36 + sid_len
  out.cipher = tl_b16(body:sub(ci, ci + 1))
  out.compression = body:byte(ci + 2) or 0
  local ext_off = ci + 3
  if ext_off + 1 <= #body then
    out.extensions = tl_parse_extensions(body, ext_off)
  end
  return out
end

local function tl_parse_certificate(body)
  local out = { certs = {} }
  local total = tl_b24(body:sub(1, 3))
  local i = 4
  local end_at = 4 + total
  while i + 3 <= end_at and i + 3 <= #body do
    local l = tl_b24(body:sub(i, i + 2))
    out.certs[#out.certs + 1] = body:sub(i + 3, i + 2 + l)
    i = i + 3 + l
  end
  return out
end

local function tl_parse_server_key_exchange(body)
  local out = {}
  local i = 1
  if i + 1 > #body then
    return out
  end
  local p_len = tl_b16(body:sub(i, i + 1))
  if i + 1 + p_len > #body then
    return out
  end
  out.dh_prime = body:sub(i + 2, i + 1 + p_len)
  out.prime_bits = #out.dh_prime * 8
  i = i + 2 + p_len
  if i > #body then
    return out
  end
  local g_len = body:byte(i)
  if i + g_len > #body then
    return out
  end
  out.dh_gen = body:sub(i + 1, i + g_len)
  i = i + 1 + g_len
  if i + 1 <= #body then
    out.sig_len = tl_b16(body:sub(i, i + 1))
    i = i + 2
    if i <= #body then
      out.hash_len = body:byte(i)
    end
  end
  return out
end

local function tl_parse_alert(body)
  return { level = body:byte(1), code = body:byte(2) }
end

local function tl_parse_certificate_status(body)
  local out = { status_type = body:byte(1) }
  if out.status_type == 1 then
    local l = tl_b24(body:sub(2, 4))
    out.ocsp_len = l
    out.ocsp = body:sub(5, 4 + l)
  end
  return out
end

local function tl_parse_heartbeat(body)
  local out = {
    type = body:byte(1),
    payload_len = tl_b16(body:sub(2, 3)),
    random = body:sub(4, 19),
  }
  local data_end = math.min(19 + out.payload_len, #body)
  out.data = body:sub(20, data_end)
  out.trailer = #body - data_end
  return out
end

local function tl_alpn_selected(body)
  if body == nil or #body < 3 then
    return nil
  end
  local l = tl_b16(body:sub(1, 2))
  if l < 1 or 2 + l > #body then
    return nil
  end
  return body:sub(3, 2 + l)
end

local function tl_dh_prime_bits(prime)
  if prime == nil or #prime == 0 then
    return nil
  end
  local i = 1
  while i < #prime and prime:byte(i) == 0 do
    i = i + 1
  end
  if i > #prime then
    return 0
  end
  local top = prime:byte(i)
  local bits = 0
  while top > 0 do
    bits = bits + 1
    top = math.floor(top / 2)
  end
  return (#prime - i) * 8 + bits
end

local TL_ALERT_NAMES = {
  [0] = "close_notify", [10] = "unexpected_message", [20] = "bad_record_mac",
  [30] = "handshake_failure", [40] = "bad_certificate",
  [45] = "unsupported_certificate", [46] = "certificate_unknown",
  [50] = "decrypt_error", [70] = "protocol_version",
  [71] = "insufficient_security", [80] = "internal_error",
  [86] = "inappropriate_fallback", [90] = "user_canceled",
  [100] = "no_renegotiation", [109] = "missing_extension",
  [110] = "unsupported_extension", [112] = "unrecognized_name",
  [113] = "bad_certificate_status_response", [115] = "unknown_psk_identity",
  [116] = "certificate_required", [120] = "no_application_protocol",
}

local function tl_alert_name(level, code)
  if level == 2 then
    return "fatal:" .. (TL_ALERT_NAMES[code] or ("0x%02x"):format(code))
  end
  return "warning:" .. (TL_ALERT_NAMES[code] or ("0x%02x"):format(code))
end

local function tl_alert_record(code, version)
  return tl_record(0x15, version or 0x0303, string.char(2, code))
end

local TL_VERSION_NAMES = {
  [0x0300] = "SSL 3.0",
  [0x0301] = "TLS 1.0",
  [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2",
  [0x0304] = "TLS 1.3",
}

local function tl_version_name(v)
  return TL_VERSION_NAMES[v] or string.format("0x%04x", v or 0)
end

local function tl_der_tlv(data, off)
  local tag = data:byte(off)
  local len = data:byte(off + 1)
  local hdr = 2
  if len >= 0x80 then
    local n = len - 0x80
    if off + 1 + n > #data then
      return nil
    end
    len = 0
    for i = 1, n do
      len = len * 256 + data:byte(off + 1 + i)
    end
    hdr = 2 + n
  end
  if off + hdr + len - 1 > #data then
    return nil
  end
  return {
    tag = tag,
    len = len,
    hdr = hdr,
    content = data:sub(off + hdr, off + hdr + len - 1),
    next = off + hdr + len,
  }
end

local function tl_der_walk(data)
  local nodes = {}
  local function walk(off, depth)
    local t = tl_der_tlv(data, off)
    if t == nil then
      return nil
    end
    local idx = #nodes + 1
    nodes[idx] = {
      tag = t.tag, len = t.len, content = t.content,
      start = off, end_at = t.next, depth = depth, index = idx,
    }
    if t.tag == 0x30 or t.tag == 0x31 or (t.tag >= 0xa0 and t.tag <= 0xbf) then
      local i = off + t.hdr
      while i < t.next do
        i = walk(i, depth + 1)
        if i == nil then
          break
        end
      end
    end
    return t.next
  end
  walk(1, 0)
  return nodes
end

local function tl_child_list(nodes, parent)
  local list = {}
  local i = parent.index + 1
  while i <= #nodes do
    local n = nodes[i]
    if n == nil or n.start >= parent.end_at then
      break
    end
    if n.depth == parent.depth + 1 then
      list[#list + 1] = n
    end
    i = i + 1
  end
  return list
end

local TL_OID_NAMES = {
  ["1.2.840.113549.1.1.1"] = "rsaEncryption",
  ["1.2.840.113549.1.1.2"] = "md2WithRSAEncryption",
  ["1.2.840.113549.1.1.4"] = "md5WithRSAEncryption",
  ["1.2.840.113549.1.1.5"] = "sha1WithRSAEncryption",
  ["1.2.840.113549.1.1.11"] = "sha256WithRSAEncryption",
  ["1.2.840.113549.1.1.12"] = "sha384WithRSAEncryption",
  ["1.2.840.113549.1.1.13"] = "sha512WithRSAEncryption",
  ["1.2.840.113549.1.1.14"] = "sha224WithRSAEncryption",
  ["1.2.840.113549.1.1.15"] = "sha512-224WithRSAEncryption",
  ["1.2.840.113549.1.1.16"] = "sha512-256WithRSAEncryption",
  ["1.2.840.10045.2.1"] = "ecPublicKey",
  ["2.5.29.14"] = "keyUsage",
  ["2.5.29.15"] = "extendedKeyUsage",
  ["2.5.29.17"] = "subjectAltName",
  ["2.5.29.19"] = "basicConstraints",
  ["2.5.29.31"] = "crlDistributionPoints",
  ["1.3.6.1.5.5.7.1.1"] = "authorityInfoAccess",
  ["1.3.6.1.5.5.7.48.1"] = "ocsp",
  ["1.3.6.1.5.5.7.48.5"] = "caIssuers",
}

local TL_NAME_OIDS = {
  ["2.5.4.3"] = "CN",
  ["2.5.4.4"] = "SN",
  ["2.5.4.5"] = "serialNumber",
  ["2.5.4.6"] = "C",
  ["2.5.4.7"] = "L",
  ["2.5.4.8"] = "ST",
  ["2.5.4.9"] = "street",
  ["2.5.4.10"] = "O",
  ["2.5.4.11"] = "OU",
  ["0.9.2342.19200300.100.1.25"] = "DC",
  ["1.3.6.1.4.1.311.60.2.1.3"] = "jurisdictionC",
}

local function tl_der_oid_str(data)
  if data == nil or #data == 0 then
    return nil
  end
  local parts = {}
  local i = 1
  local function read_arc()
    local v = 0
    while i <= #data do
      local b = data:byte(i)
      i = i + 1
      v = v * 128 + (b & 0x7f)
      if (b & 0x80) == 0 then
        break
      end
    end
    return v
  end
  local first = data:byte(1)
  i = 2
  if first < 40 then
    parts[1] = "0." .. first
  elseif first < 80 then
    parts[1] = "1." .. (first - 40)
  else
    parts[1] = "2.5"
  end
  local rest = read_arc()
  parts[#parts + 1] = tostring(rest)
  while i <= #data do
    parts[#parts + 1] = tostring(read_arc())
  end
  return table.concat(parts, ".")
end

local function tl_der_name_str(nodes, parent)
  local parts = {}
  for _, rdn in ipairs(tl_child_list(nodes, parent)) do
    if rdn.tag == 0x31 then
      local attrs = {}
      for _, attr in ipairs(tl_child_list(nodes, rdn)) do
        if attr.tag == 0x30 then
          local ac = tl_child_list(nodes, attr)
          local oid_n = ac[1]
          local val_n = ac[2]
          if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil then
            local oid = tl_der_oid_str(oid_n.content)
            local label = TL_NAME_OIDS[oid] or oid
            attrs[#attrs + 1] = label .. "=" .. val_n.content
          end
        end
      end
      if #attrs > 0 then
        parts[#parts + 1] = table.concat(attrs, ", ")
      end
    end
  end
  return table.concat(parts, " / ")
end

local function tl_der_name_key(nodes, parent)
  local parts = {}
  for _, rdn in ipairs(tl_child_list(nodes, parent)) do
    if rdn.tag == 0x31 then
      local attrs = {}
      for _, attr in ipairs(tl_child_list(nodes, rdn)) do
        if attr.tag == 0x30 then
          local ac = tl_child_list(nodes, attr)
          local oid_n = ac[1]
          local val_n = ac[2]
          if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil then
            local oid = tl_der_oid_str(oid_n.content)
            local label = TL_NAME_OIDS[oid] or oid
            attrs[#attrs + 1] = label .. "=" .. val_n.content
          end
        end
      end
      if #attrs > 0 then
        table.sort(attrs)
        parts[#parts + 1] = table.concat(attrs, ",")
      end
    end
  end
  table.sort(parts)
  return table.concat(parts, "/")
end

local function tl_der_int_value(data)
  if data == nil or #data == 0 then
    return nil
  end
  local v = 0
  for i = 1, #data do
    v = v * 256 + data:byte(i)
  end
  return v
end

local function tl_utctime_to_epoch(s)
  if s == nil or #s < 12 then
    return nil
  end
  local yy = tonumber(s:sub(1, 2))
  local mm = tonumber(s:sub(3, 4))
  local dd = tonumber(s:sub(5, 6))
  local hh = tonumber(s:sub(7, 8))
  local mi = tonumber(s:sub(9, 10))
  local ss = tonumber(s:sub(11, 12))
  if yy == nil or mm == nil or dd == nil then
    return nil
  end
  hh = hh or 0
  mi = mi or 0
  ss = ss or 0
  if yy < 50 then
    yy = yy + 2000
  else
    yy = yy + 1900
  end
  local days = 0
  for y = 1970, yy - 1 do
    days = days + 365
    if (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0 then
      days = days + 1
    end
  end
  local mdays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
  if (yy % 4 == 0 and yy % 100 ~= 0) or yy % 400 == 0 then
    mdays[2] = 29
  end
  for m = 1, mm - 1 do
    days = days + mdays[m]
  end
  days = days + dd - 1
  return days * 86400 + hh * 3600 + mi * 60 + ss
end

local function tl_gentime_to_epoch(s)
  if s == nil or #s < 14 then
    return nil
  end
  local yyyy = tonumber(s:sub(1, 4))
  local mm = tonumber(s:sub(5, 6))
  local dd = tonumber(s:sub(7, 8))
  local hh = tonumber(s:sub(9, 10))
  local mi = tonumber(s:sub(11, 12))
  local ss = tonumber(s:sub(13, 14))
  if yyyy == nil or mm == nil or dd == nil then
    return nil
  end
  hh = hh or 0
  mi = mi or 0
  ss = ss or 0
  local days = 0
  for y = 1970, yyyy - 1 do
    days = days + 365
    if (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0 then
      days = days + 1
    end
  end
  local mdays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
  if (yyyy % 4 == 0 and yyyy % 100 ~= 0) or yyyy % 400 == 0 then
    mdays[2] = 29
  end
  for m = 1, mm - 1 do
    days = days + mdays[m]
  end
  days = days + dd - 1
  return days * 86400 + hh * 3600 + mi * 60 + ss
end

local function tl_parse_time(tag, content)
  if tag == 0x17 then
    return tl_utctime_to_epoch(content)
  end
  if tag == 0x18 then
    return tl_gentime_to_epoch(content)
  end
  return nil
end

local function tl_x509_parse(der)
  local cert = { raw_len = #der }
  local nodes = tl_der_walk(der)
  local root = nodes[1]
  if root == nil or root.tag ~= 0x30 or #nodes < 5 then
    return cert
  end
  local tbs = tl_child_list(nodes, root)[1]
  if tbs == nil or tbs.tag ~= 0x30 then
    return cert
  end
  local fields = tl_child_list(nodes, tbs)
  local pos = 1
  local function next_field()
    local n = fields[pos]
    if n == nil then
      return nil
    end
    pos = pos + 1
    return n
  end
  local n = next_field()
  if n ~= nil and n.tag == 0xa0 then
    cert.version = 2
  else
    cert.version = 1
    pos = pos - 1
  end
  n = next_field()
  if n ~= nil and n.tag == 0x02 then
    cert.serial = tl_der_int_value(n.content)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    local alg = tl_child_list(nodes, n)
    local oid = alg[1]
    if oid ~= nil and oid.tag == 0x06 then
      cert.sig_oid = tl_der_oid_str(oid.content)
      cert.sig_algorithm = TL_OID_NAMES[cert.sig_oid] or cert.sig_oid
    end
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.issuer = tl_der_name_str(nodes, n)
    cert.issuer_key = tl_der_name_key(nodes, n)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    local times = {}
    for _, c in ipairs(tl_child_list(nodes, n)) do
      if c.tag == 0x17 or c.tag == 0x18 then
        times[#times + 1] = c
      end
    end
    if #times >= 1 then
      cert.not_before = tl_parse_time(times[1].tag, times[1].content)
      cert.not_before_raw = times[1].content
    end
    if #times >= 2 then
      cert.not_after = tl_parse_time(times[#times].tag, times[#times].content)
      cert.not_after_raw = times[#times].content
    end
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.subject = tl_der_name_str(nodes, n)
    cert.subject_key = tl_der_name_key(nodes, n)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.spki = {}
    local children = tl_child_list(nodes, n)
    local alg = children[1]
    if alg ~= nil and alg.tag == 0x30 then
      local oid = tl_child_list(nodes, alg)[1]
      if oid ~= nil and oid.tag == 0x06 then
        cert.spki.oid = tl_der_oid_str(oid.content)
        cert.spki.algorithm = TL_OID_NAMES[cert.spki.oid] or cert.spki.oid
      end
    end
    for _, c in ipairs(children) do
      if c.tag == 0x03 then
        local key_bytes = c.content:sub(2)
        local inner = tl_der_walk(key_bytes)
        local ints = {}
        for _, ic in ipairs(inner) do
          if ic.tag == 0x02 then
            ints[#ints + 1] = ic
          end
        end
        if cert.spki.algorithm == "rsaEncryption" and #ints >= 1 then
          local modulus = ints[1].content
          if #modulus > 0 and modulus:byte(1) == 0 then
            modulus = modulus:sub(2)
          end
          local rsa_bits = 0
          if #modulus > 0 then
            local first = modulus:byte(1)
            local top = 0
            while first > 0 do
              top = top + 1
              first = math.floor(first / 2)
            end
            rsa_bits = (#modulus - 1) * 8 + top
          end
          cert.spki.bits = rsa_bits
          cert.spki.type = "RSA"
        end
        if cert.spki.algorithm == "ecPublicKey" then
          cert.spki.type = "EC"
        end
        break
      end
    end
  end
  for _, c in ipairs(fields) do
    if c.tag == 0xa3 then
      cert.extensions = {}
      local list = tl_child_list(nodes, c)[1]
      if list ~= nil and list.tag == 0x30 then
        for _, e in ipairs(tl_child_list(nodes, list)) do
          if e.tag == 0x30 then
            local ec = tl_child_list(nodes, e)
            local oid_n = ec[1]
            local val_n = ec[2]
            if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil and val_n.tag == 0x04 then
              local oid = tl_der_oid_str(oid_n.content)
              local entry = { oid = oid, name = TL_OID_NAMES[oid] or oid, value = val_n.content }
              if oid == "2.5.29.17" then
                entry.sans = {}
                local san_nodes = tl_der_walk(val_n.content)
                for _, sn in ipairs(san_nodes) do
                  if sn.tag == 0x82 then
                    entry.sans[#entry.sans + 1] = { type = "DNS", value = sn.content }
                  elseif sn.tag == 0x87 then
                    entry.sans[#entry.sans + 1] = { type = "IP", value = sn.content }
                  elseif sn.tag == 0x84 then
                    entry.sans[#entry.sans + 1] = { type = "URI", value = sn.content }
                  elseif sn.tag == 0x88 then
                    entry.sans[#entry.sans + 1] = { type = "email", value = sn.content }
                  end
                end
              end
              cert.extensions[#cert.extensions + 1] = entry
            end
          end
        end
      end
      break
    end
  end
  cert.self_signed = (cert.issuer_key ~= nil and cert.subject_key ~= nil and cert.issuer_key == cert.subject_key)
  return cert
end

local function tl_hex(data)
  if data == nil then
    return ""
  end
  local out = {}
  for i = 1, #data do
    out[#out + 1] = string.format("%02x", data:byte(i))
  end
  return table.concat(out)
end

local function tl_days_between(a, b)
  if a == nil or b == nil then
    return nil
  end
  return math.floor(math.abs(b - a) / 86400)
end

local TL_VERSIONS = {
  [0x0300] = "SSLv3",
  [0x0301] = "TLS 1.0",
  [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2",
  [0x0304] = "TLS 1.3",
}

local TL_CIPHER_INFO = {
  [0x0001] = { name = "TLS_RSA_WITH_NULL_MD5", kx = "RSA", cipher = "NULL", mac = "MD5" },
  [0x0002] = { name = "TLS_RSA_WITH_NULL_SHA", kx = "RSA", cipher = "NULL", mac = "SHA1" },
  [0x0003] = { name = "TLS_RSA_WITH_RC4_128_MD5", kx = "RSA", cipher = "RC4", mac = "MD5" },
  [0x0005] = { name = "TLS_RSA_WITH_RC4_128_SHA", kx = "RSA", cipher = "RC4", mac = "SHA1" },
  [0x0006] = { name = "TLS_RSA_WITH_DES_CBC_SHA", kx = "RSA", cipher = "DES", mac = "SHA1" },
  [0x0004] = { name = "TLS_RSA_WITH_RC4_40_MD5", kx = "RSA", cipher = "RC4", mac = "MD5" },
  [0x0007] = { name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kx = "RSA", cipher = "3DES", mac = "SHA1" },
  [0x000a] = { name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kx = "RSA", cipher = "3DES", mac = "SHA1" },
  [0x0008] = { name = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", kx = "DH_d", cipher = "3DES", mac = "SHA1" },
  [0x0009] = { name = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "DH_s", cipher = "3DES", mac = "SHA1" },
  [0x000c] = { name = "TLS_EDH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "DHE", cipher = "3DES", mac = "SHA1" },
  [0x000d] = { name = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", kx = "DHE", cipher = "3DES", mac = "SHA1" },
  [0x0013] = { name = "TLS_RSA_WITH_IDEA_CBC_SHA", kx = "RSA", cipher = "IDEA", mac = "SHA1" },
  [0x0016] = { name = "TLS_KRB5_WITH_RC4_128_SHA", kx = "KRB5", cipher = "RC4", mac = "SHA1" },
  [0x0019] = { name = "TLS_KRB5_WITH_DES_CBC_SHA", kx = "KRB5", cipher = "DES", mac = "SHA1" },
  [0x001c] = { name = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", kx = "KRB5", cipher = "3DES", mac = "SHA1" },
  [0x002f] = { name = "TLS_RSA_WITH_AES_128_CBC_SHA", kx = "RSA", cipher = "AES128", mac = "SHA1" },
  [0x0033] = { name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", kx = "DHE", cipher = "AES128", mac = "SHA1" },
  [0x0035] = { name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", kx = "DHE", cipher = "AES256", mac = "SHA1" },
  [0x0039] = { name = "TLS_RSA_WITH_AES_128_GCM_SHA256", kx = "RSA", cipher = "AES128-GCM", mac = "SHA256" },
  [0x003c] = { name = "TLS_RSA_WITH_AES_256_CBC_SHA", kx = "RSA", cipher = "AES256", mac = "SHA1" },
  [0x0067] = { name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", kx = "DHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0x006b] = { name = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", kx = "DHE", cipher = "AES256-GCM", mac = "SHA384" },
  [0x009c] = { name = "TLS_RSA_WITH_AES_256_GCM_SHA384", kx = "RSA", cipher = "AES256-GCM", mac = "SHA384" },
  [0x009d] = { name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", kx = "DHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0xc008] = { name = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc009] = { name = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", kx = "ECDHE", cipher = "AES128", mac = "SHA1" },
  [0xc00a] = { name = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", kx = "ECDHE", cipher = "AES256", mac = "SHA1" },
  [0xc012] = { name = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc023] = { name = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", kx = "ECDHE", cipher = "AES128", mac = "SHA1" },
  [0xc027] = { name = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", kx = "ECDHE", cipher = "AES256", mac = "SHA1" },
  [0xc02b] = { name = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc02f] = { name = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", kx = "ECDHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0xc030] = { name = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", kx = "ECDHE", cipher = "AES256-GCM", mac = "SHA384" },
  [0xcc0a] = { name = "TLS_PSK_WITH_3DES_EDE_CBC_SHA", kx = "PSK", cipher = "3DES", mac = "SHA1" },
  [0x1301] = { name = "TLS_AES_128_GCM_SHA256", kx = "(1.3)", cipher = "AES128-GCM", mac = "SHA256" },
  [0x1302] = { name = "TLS_AES_256_GCM_SHA384", kx = "(1.3)", cipher = "AES256-GCM", mac = "SHA384" },
  [0x1303] = { name = "TLS_CHACHA20_POLY1305_SHA256", kx = "(1.3)", cipher = "CHACHA20", mac = "SHA256" },
}

local function tl_cipher_name(id)
  local info = TL_CIPHER_INFO[id]
  if info ~= nil then
    return info.name
  end
  return string.format("0x%04x", id or 0)
end

local function tl_cipher_class(id)
  local info = TL_CIPHER_INFO[id]
  if info == nil then
    return "unknown"
  end
  if info.cipher == "NULL" then
    return "null"
  end
  if info.cipher == "RC4" then
    return "rc4"
  end
  if info.cipher == "DES" then
    return "export-des"
  end
  if info.cipher == "3DES" then
    return "3des"
  end
  if info.mac == "MD5" then
    return "md5"
  end
  if info.kx == "KRB5" and (info.cipher == "RC4" or info.cipher == "DES" or info.cipher == "3DES") then
    return "krb5-legacy"
  end
  return "acceptable"
end

local function tl_connect(host, port)
  local sock = nmap.new_socket("tcp")
  local ok, err = sock:connect(host.ip, port)
  if not ok then
    return nil, err
  end
  sock:set_timeout(10)
  return sock, nil
end

local function tl_read_record(sock)
  local ok, hdr, rerr = sock:receive_bytes(5)
  if not ok or hdr == nil or #hdr < 5 then
    return nil, rerr or "TIMEOUT"
  end
  local rtype = hdr:byte(1)
  local rlen = hdr:byte(4) * 256 + hdr:byte(5)
  local ok2, payload, rerr2 = sock:receive_bytes(rlen)
  if not ok2 or payload == nil then
    return nil, rerr2 or "TIMEOUT"
  end
  return { type = rtype, version = hdr:byte(2) * 256 + hdr:byte(3), payload = payload }, nil
end

local function tl_collect_server_flight(sock, limit)
  local msgs = {}
  local alert = nil
  for _ = 1, limit or 12 do
    local rec, err = tl_read_record(sock)
    if rec == nil then
      return msgs, alert, err
    end
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      alert = {
        level = parsed.level,
        code = parsed.code,
        name = tl_alert_name(parsed.level, parsed.code),
      }
      return msgs, alert, nil
    elseif rec.type == 22 then
      local hs = tl_parse_handshake_messages(rec.payload)
      for _, m in ipairs(hs) do
        msgs[#msgs + 1] = m
        if m.type == 14 then
          return msgs, alert, nil
        end
      end
    end
  end
  return msgs, alert, nil
end

local function tl_summarize_flight(msgs)
  local info = {}
  for _, m in ipairs(msgs) do
    if m.type == 2 then
      local sh = tl_parse_server_hello(m.body)
      info.version = sh.version
      info.cipher = sh.cipher
      info.cipher_name = tl_cipher_name(sh.cipher)
      info.compression = sh.compression
      local exts = sh.extensions or {}
      info.exts = exts
      local sv = exts[43]
      if sv ~= nil and #sv >= 2 then
        info.negotiated_version = sv:byte(1) * 256 + sv:byte(2)
      else
        info.negotiated_version = sh.version
      end
      info.version_name = TL_VERSIONS[info.negotiated_version]
        or tl_version_name(info.negotiated_version)
      local alpn = exts[16]
      if alpn ~= nil then
        info.alpn = tl_alpn_selected(alpn)
      end
      if exts[5] ~= nil then
        info.status_request_echo = true
      end
      if exts[0xff01] ~= nil then
        info.renegotiation_info = true
      end
    elseif m.type == 11 then
      local parsed = tl_parse_certificate(m.body)
      info.cert_count = #parsed.certs
      if parsed.certs[1] ~= nil then
        info.cert_der = parsed.certs[1]
        info.cert = tl_x509_parse(parsed.certs[1])
      end
    elseif m.type == 12 then
      info.ske = tl_parse_server_key_exchange(m.body)
      if info.ske.dh_prime ~= nil then
        info.dh_bits = info.ske.prime_bits or tl_dh_prime_bits(info.ske.dh_prime)
      end
    elseif m.type == 5 then
      info.ocsp = tl_parse_certificate_status(m.body)
    elseif m.type == 4 then
      info.session_ticket = true
    end
  end
  return info
end

local function tl_read_records_until(sock, wanted, limit)
  for _ = 1, limit or 8 do
    local rec, err = tl_read_record(sock)
    if rec == nil then
      return false, err
    end
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      return false, "alert:" .. tl_alert_name(parsed.level, parsed.code)
    end
    if rec.type == 22 then
      local hs = tl_parse_handshake_messages(rec.payload)
      for _, m in ipairs(hs) do
        if m.type == wanted then
          return true, nil
        end
      end
    end
  end
  return false, "NO_MESSAGE"
end

local function tl_finish_client_flight(sock)
  local pre = string.rep("k", 32)
  local cke = tl_record(0x16, 0x0303, tl_handshake(0x10, tl_u16(#pre) .. pre))
  local ccs = tl_record(0x14, 0x0303, "")
  local fin = tl_record(0x16, 0x0303, tl_handshake(0x14, string.rep("f", 12)))
  sock:send(cke)
  sock:send(ccs)
  sock:send(fin)
  return tl_read_records_until(sock, 20)
end

local function tl_perform_handshake(host, port, opts)
  opts = opts or {}
  local sock, cerr = tl_connect(host, port)
  if sock == nil then
    return { status = "connect_error", error = cerr }
  end
  local hello_opts = {
    version = opts.version or 0x0303,
    ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x0039 },
    comps = opts.comps or { 0 },
    sni = opts.sni,
    alpn = opts.alpn,
    status_request = opts.status_request,
    supported_versions = opts.supported_versions,
    heartbeat = opts.heartbeat,
    renegotiation_info = opts.renegotiation_info,
    ems = opts.ems ~= nil and opts.ems or false,
  }
  if opts.scsv then
    hello_opts.ciphers = { 0x0035, 0xc02f, 0x5600 }
    hello_opts.version = opts.version or 0x0302
  end
  local hello = tl_client_hello(hello_opts)
  local ok, serr = pcall(sock.send, sock, hello)
  if not ok then
    sock:close()
    return { status = "send_error", error = serr }
  end
  local msgs, alert = tl_collect_server_flight(sock)
  local server = tl_summarize_flight(msgs)
  local result = { status = "handshake", server = server, sock = sock }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
    return result
  end
  if server.version == nil then
    sock:close()
    result.status = "no_server_hello"
    return result
  end
  local done, dterr = tl_finish_client_flight(sock)
  result.completed = done
  if not done then
    result.completion_error = dterr
  end
  return result
end

local function tl_close(result)
  if result ~= nil and result.sock ~= nil then
    local ok = pcall(result.sock.close, result.sock)
    if ok then
      result.sock = nil
    end
  end
  return result
end

local function tl_probe_version(host, port, version, supported, ciphers)
  local opts = { version = version, ciphers = ciphers }
  if supported ~= nil then
    opts.supported_versions = supported
  end
  return tl_close(tl_perform_handshake(host, port, opts))
end

local function tl_supported_versions(result)
  local server = result.server or {}
  local neg = server.negotiated_version
  local accepted = neg ~= nil and result.status == "handshake"
  return accepted, neg
end

local function tl_probe_cipher_set(host, port, ciphers, version)
  return tl_close(tl_perform_handshake(host, port, {
    version = version or 0x0303,
    ciphers = ciphers,
  }))
end

local function tl_cipher_accepted(result)
  if result.status ~= "handshake" then
    return false, nil
  end
  local server = result.server or {}
  return true, server.cipher
end

local function tl_renegotiation_probe(host, port, with_info)
  local first = tl_perform_handshake(host, port, {
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
  })
  if first.status ~= "handshake" then
    return tl_close(first)
  end
  local hello = tl_client_hello({
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
    renegotiation_info = with_info,
  })
  local ok, serr = pcall(first.sock.send, first.sock, hello)
  if not ok then
    first.status = "send_error"
    first.error = serr
    return tl_close(first)
  end
  local msgs, alert = tl_collect_server_flight(first.sock)
  local server = tl_summarize_flight(msgs)
  local result = {
    status = "renegotiated",
    server = server,
    base_version = first.server.negotiated_version,
  }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
  elseif server.version == nil then
    result.status = "no_server_hello"
  end
  return tl_close(result)
end

local function tl_heartbeat_probe(host, port, payload)
  local first = tl_perform_handshake(host, port, {
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
    heartbeat = true,
  })
  if first.status ~= "handshake" then
    return tl_close(first)
  end
  local p = payload or "tl-heartbeat-probe"
  local body = string.char(0) .. tl_u16(#p) .. string.rep("h", 16) .. p
    .. string.rep("\0", 16)
  local ok, serr = pcall(first.sock.send, first.sock, tl_record(0x18, 0x0303, body))
  if not ok then
    first.status = "send_error"
    first.error = serr
    return tl_close(first)
  end
  local rec, rerr = tl_read_record(first.sock)
  local result = { status = "no_response", error = rerr }
  if rec ~= nil then
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      result.status = "alert"
      result.alert = {
        level = parsed.level,
        code = parsed.code,
        name = tl_alert_name(parsed.level, parsed.code),
      }
    elseif rec.type == 24 then
      local hb = tl_parse_heartbeat(rec.payload)
      result.status = "response"
      result.heartbeat = hb
      result.overread = hb.trailer > 0
    else
      result.status = "unexpected"
      result.record_type = rec.type
    end
  end
  return tl_close(result)
end

local function tl_read_all(sock)
  local parts = {}
  while true do
    local ok, chunk, err = sock:receive_bytes(65536)
    if not ok or chunk == nil or #chunk == 0 then
      return table.concat(parts), err
    end
    parts[#parts + 1] = chunk
    if #chunk < 65536 then
      break
    end
  end
  return table.concat(parts), nil
end

local function tl_parse_http_response(raw)
  local parsed = { raw = raw }
  local status = raw:match("^HTTP/1%.%d (%d%d%d)")
  parsed.status = tonumber(status)
  local headers_end = raw:find("\r\n\r\n", 1, true)
  if headers_end == nil then
    return parsed
  end
  parsed.headers = {}
  for line in raw:sub(1, headers_end - 1):gmatch("([^\r\n]+)") do
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k ~= nil then
      parsed.headers[k:lower()] = v
    end
  end
  parsed.body = raw:sub(headers_end + 4)
  return parsed
end

local function tl_http_over_tls(result, path)
  if result == nil or result.sock == nil or result.status ~= "handshake" then
    return nil, "no_open_session"
  end
  local req = "GET " .. (path or "/") .. " HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
  local ok, serr = pcall(result.sock.send, result.sock, req)
  if not ok then
    return nil, serr
  end
  local raw, rerr = tl_read_all(result.sock)
  if raw == nil or #raw == 0 then
    return nil, rerr or "EMPTY_RESPONSE"
  end
  return tl_parse_http_response(raw), nil
end

local function tl_classify_cert_window(cert, now, warndays)
  if cert == nil or cert.not_before == nil or cert.not_after == nil then
    return "unknown"
  end
  if now < cert.not_before then
    return "not_yet_valid"
  end
  if now > cert.not_after then
    return "expired"
  end
  local days = tl_days_between(now, cert.not_after)
  if days <= (warndays or 30) then
    return "expiring_soon"
  end
  return "valid"
end

local function tl_cert_days_to_expiry(cert, now)
  if cert == nil or cert.not_after == nil then
    return nil
  end
  return tl_days_between(now, cert.not_after)
end

local function tl_hostname_matches_pattern(pattern, hostname)
  if pattern == nil or hostname == nil then
    return false
  end
  pattern = pattern:lower()
  hostname = hostname:lower()
  if pattern == hostname then
    return true
  end
  if pattern:sub(1, 2) ~= "*." then
    return false
  end
  local suffix = pattern:sub(3)
  if #hostname <= #suffix then
    return false
  end
  if hostname:sub(-#suffix) ~= suffix then
    return false
  end
  local label = hostname:sub(1, #hostname - #suffix - 1)
  if label:find(".", 1, true) then
    return false
  end
  if #label == 0 then
    return false
  end
  return true
end

local function tl_extract_cn(subject)
  if subject == nil then
    return nil
  end
  for part in subject:gmatch("[^/]+") do
    local key, val = part:match("^%s*(%w+)%s*=%s*(.-)%s*$")
    if key ~= nil and key:upper() == "CN" then
      return val
    end
  end
  return nil
end

local function tl_hostname_check(cert, hostname)
  local result = { match = false, sources = {}, wildcards = 0 }
  if cert == nil then
    return result
  end
  local sans = {}
  for _, e in ipairs(cert.extensions or {}) do
    if e.name == "subjectAltName" then
      for _, s in ipairs(e.sans or {}) do
        if s.type == "DNS" then
          sans[#sans + 1] = s.value
        end
      end
    end
  end
  if #sans > 0 then
    for _, s in ipairs(sans) do
      if tl_hostname_matches_pattern(s, hostname) then
        result.match = true
        result.sources[#result.sources + 1] = "SAN:" .. s
        if s:find("^%*%.") then
          result.wildcards = result.wildcards + 1
        end
      end
    end
    result.uses_san = true
  end
  local cn = tl_extract_cn(cert.subject)
  if cn ~= nil and not result.match then
    if tl_hostname_matches_pattern(cn, hostname) then
      result.match = true
      result.sources[#result.sources + 1] = "CN:" .. cn
    end
  end
  return result
end

local TL_WEAK_SIG_ALGS = {
  ["md5WithRSAEncryption"] = "MD5",
  ["sha1WithRSAEncryption"] = "SHA-1",
  ["shaWithRSAEncryption"] = "SHA-0",
  ["md5WithRSA"] = "MD5",
  ["sha1WithRSA"] = "SHA-1",
}

local function tl_sig_algorithm_class(cert)
  if cert == nil or cert.sig_algorithm == nil then
    return "unknown", nil
  end
  local weak = TL_WEAK_SIG_ALGS[cert.sig_algorithm]
  if weak ~= nil then
    return "weak", weak
  end
  if cert.sig_oid ~= nil then
    local rsa_sig_weak = { "2", "4", "5" }
    for _, suffix in ipairs(rsa_sig_weak) do
      if cert.sig_oid == ("1.2.840.113549.1.1." .. suffix) then
        return "weak", cert.sig_algorithm
      end
    end
  end
  return "strong", nil
end

local function tl_known_dh_group(prime)
  if prime == nil or #prime < 16 then
    return nil
  end
  local head = ""
  for i = 1, 21 do
    if i > #prime then
      return nil
    end
    head = head .. string.format("%02x", prime:byte(i))
  end
  if #prime == 128 and head:sub(1, 40) == "ffffffffffffffffc90fdaa22168c234c4c6628b" then
    return "RFC 3526 group 14 (1024-bit MODP)"
  end
  if #prime == 256 and head == "04ffffffffffffffffc90fdaa22168c234c4c6628b" then
    return "RFC 7919 ffdhe2048"
  end
  return nil
end

local function tl_dh_strength(bits)
  if bits == nil then
    return "unknown"
  end
  if bits < 1024 then
    return "critically_weak"
  end
  if bits < 2048 then
    return "weak"
  end
  return "acceptable"
end

local function tl_scsv_probe(host, port)
  return tl_close(tl_perform_handshake(host, port, {
    scsv = true,
    version = 0x0302,
  }))
end

local function tl_weak_cipher_groups()
  return {
    null = { 0x0001, 0x0002 },
    rc4 = { 0x0005, 0x0004, 0x0016, 0x0013 },
    export_des = { 0x0006, 0x0007 },
    md5 = { 0x0003 },
    three_des = { 0x000a, 0x0008, 0x0009, 0x000c, 0x000d, 0xc008, 0xc012, 0xc02b },
  }
end

local function tl_probe_each_group(host, port, groups)
  local results = {}
  for group, ciphers in pairs(groups) do
    local result = tl_probe_cipher_set(host, port, ciphers)
    local accepted, cipher = tl_cipher_accepted(result)
    results[group] = {
      accepted = accepted,
      cipher = cipher,
      cipher_name = accepted and tl_cipher_name(cipher) or nil,
      status = result.status,
      alert = result.alert,
    }
  end
  return results
end

local function tl_version_probe_battery(host, port)
  local probes = {
    { label = "SSLv3", version = 0x0300, supported = nil },
    { label = "TLS 1.0", version = 0x0301, supported = nil },
    { label = "TLS 1.1", version = 0x0302, supported = nil },
    { label = "TLS 1.2", version = 0x0303, supported = nil },
    { label = "TLS 1.3", version = 0x0303, supported = { 0x0304 }, ciphers = { 0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0x009c, 0x0039 } },
  }
  local out = {}
  for _, p in ipairs(probes) do
    local result = tl_probe_version(host, port, p.version, p.supported, p.ciphers)
    local ok, neg = tl_supported_versions(result)
    out[#out + 1] = {
      label = p.label,
      accepted = ok,
      negotiated = neg,
      status = result.status,
      alert = result.alert,
    }
  end
  return out
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

local function rc4_suite_name(id)
  return RC4_SUITE_NAMES[id] or string.format("0x%04x", id or 0)
end

local function run_audit(host, port, args)
  local sections = {}
  local sess, err = rdp_open_session(host, port, args)
  if not sess then
    return rdp_incomplete("no session: " .. tostring(err), sections, "connect", err)
  end
  local neg, neg_err = rdp_negotiate(sess, RDP_T.PROTO_SSL + RDP_T.PROTO_HYBRID, {})
  if neg == nil then
    rdp_close(sess)
    return rdp_incomplete("negotiation failed: " .. tostring(neg_err), sections, "negotiation", neg_err)
  end

  local row = stdnse.output_table()
  row["Negotiation"] = neg.plain_cc and "plain confirm (legacy path; direct TLS attempted)"
    or (neg.failure and ("refused: " .. rdp_failure_name(neg.failure))
      or ("selected: " .. rdp_selected_name(neg.selected)))
  sections[#sections + 1] = { key = "Negotiation", value = row }
  if neg.failure ~= nil then
    rdp_close(sess)
    local out = new_output(RISK_LEVEL, "SECURE - TLS negotiation refused legacy request ("
      .. rdp_failure_name(neg.failure) .. ")")
    add_finding("INFO", "Server refused the probe negotiation", {
      subject = "rc4",
      evidence = rdp_failure_name(neg.failure),
      confidence = "medium",
    })
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end

  local tls, tls_err = rdp_tls_upgrade(sess, { ciphers = RC4_SUITES, version = 0x0301 })
  rdp_close(sess)
  if tls == nil then
    local out = new_output(RISK_LEVEL, "SECURE - RC4-only handshake refused (" .. tostring(tls_err) .. ")")
    add_finding("INFO", "Server did not complete an RC4-restricted handshake", {
      subject = "rc4",
      evidence = tostring(tls_err),
      confidence = "high",
    })
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end

  local tls_row = stdnse.output_table()
  tls_row["Negotiated version"] = tls.version_name or string.format("0x%04x", tls.version or 0)
  tls_row["Negotiated suite"] = tls.cipher_name or rc4_suite_name(tls.cipher)
  sections[#sections + 1] = { key = "RC4-Only Handshake", value = tls_row }

  local chosen = tls.cipher
  local is_rc4 = (chosen == 0x0004 or chosen == 0x0005 or chosen == 0x0013 or chosen == 0x0016)
  local remediation = stdnse.output_table()
  local status_text
  if is_rc4 then
    status_text = "VULNERABLE - server accepted RC4 (" .. (tls.cipher_name or rc4_suite_name(chosen)) .. ")"
    add_finding("HIGH", "RDP TLS layer negotiates RC4 stream cipher", {
      subject = "rc4",
      evidence = "selected " .. (tls.cipher_name or rc4_suite_name(chosen))
        .. " over TLS " .. (tls.version_name or string.format("0x%04x", tls.version or 0)),
      confidence = "high",
      cvss = 7.4,
    })
    remediation["1. Disable RC4"] = "Remove RC4 suites from the Schannel cipher suite order."
    remediation["2. Require AEAD"] = "Prefer TLS 1.2+ with ECDHE and AES-GCM suites."
    remediation["3. Clients"] = "Retire or update clients that still require RC4."
  else
    status_text = "SECURE - RC4 refused; server selected "
      .. (tls.cipher_name or rc4_suite_name(chosen))
    add_finding("INFO", "Server downgraded the RC4-only offer to a stronger suite", {
      subject = "rc4",
      evidence = "selected " .. (tls.cipher_name or rc4_suite_name(chosen)),
      confidence = "medium",
    })
    remediation["1. Maintain"] = "Keep RC4 disabled in the cipher suite order after client updates."
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
