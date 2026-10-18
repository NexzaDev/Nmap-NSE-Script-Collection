local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Reports the maximum transfer sizes the SMB server advertises in
its negotiate responses, for both the legacy SMBv1 and modern
SMB2/3 dialects.

Why it matters
- The advertised maximums (MaxBuffer/MaxMpxCount on SMBv1,
  MaxTransact/MaxRead/MaxWrite on SMB2/3) are a performance and
  compatibility fingerprint: an all-default server advertises
  16MB/1MB/1MB on SMB2 and 64KB/50 on SMBv1, while tuned or
  third-party stacks deviate.
- Extremely small maximums usually indicate a proxy, a
  restricted appliance, or a deliberately limited stack;
  extremely large values can indicate a misconfigured or
  non-standard server.
- These values are passive negotiate-response fields, so the
  check adds no load beyond a single negotiate exchange per
  dialect.

What the script does
1. Full-dialect negotiate: records MaxTransact, MaxRead and
   MaxWrite from the SMB2/3 negotiate response.
2. SMBv1-only negotiate: records MaxBuffer and MaxMpxCount from
   the SMBv1 negotiate response parameters.
3. Compares the advertised values against the common defaults
   (Windows: 16777216/1048576/1048576 SMB2, 65536/50 SMBv1) and
   flags deviations.
4. Emits LOW informational findings for each dialect's effective
   limits and notes deviations from the Windows defaults.

Only negotiate / session setup exchanges are sent.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

portrule = shortport.port_or_service({139, 445}, "microsoft-ds", "tcp")

local SCRIPT_NAME = "smb-buffer-limits"

local RISK_LEVEL = "🟢 LOW"

local DEFAULT_ARGS = {
  maxrequests = 12,
  timeout = 10,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 2, integer = true },
  { key = "timeout", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

local SMB2_DEFAULTS = {
  max_transact = 16777216,
  max_read = 1048576,
  max_write = 1048576,
}

local SMB1_DEFAULTS = {
  max_buf = 65536,
  max_mpx = 50,
}

local LIMITS_REFERENCE = {
  "SMBv1 MaxBuffer (u16): maximum size of a single SMBv1 response, 128 bytes - 64KB",
  "SMBv1 MaxMpxCount (u16): maximum outstanding multiplexed requests (default 50)",
  "SMB2 MaxTransact (u32): maximum total data size per SMB2 message (default 16MB)",
  "SMB2 MaxRead (u32): maximum data size per SMB2 READ (default 1MB)",
  "SMB2 MaxWrite (u32): maximum data size per SMB2 WRITE (default 1MB)",
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

local function su16(v)
  return string.char(v % 256, math.floor(v / 256) % 256)
end

local function su32(v)
  return string.char(v % 256, math.floor(v / 256) % 256,
    math.floor(v / 65536) % 256, math.floor(v / 16777216) % 256)
end

local function su64(v)
  return su32(v % 4294967296) .. su32(math.floor(v / 4294967296) % 4294967296)
end

local function sbb(s, n)
  return s:byte(n + 1) or 0
end

local function s16(s, n)
  return sbb(s, n) + sbb(s, n + 1) * 256
end

local function s32(s, n)
  return sbb(s, n) + sbb(s, n + 1) * 256 + sbb(s, n + 2) * 65536 + sbb(s, n + 3) * 16777216
end

local function srotl(x, n)
  n = n % 32
  if n == 0 then return x end
  local m = 2 ^ (32 - n)
  return ((x % m) * 2 ^ n + math.floor(x / m)) % 4294967296
end

local function md4(data)
  local len = #data
  local bitlen = len * 8
  data = data .. string.char(0x80)
  while #data % 64 ~= 56 do
    data = data .. string.char(0)
  end
  local l1 = bitlen % 4294967296
  local l2 = math.floor(bitlen / 4294967296) % 4294967296
  data = data .. su32(l1) .. su32(l2)
  local r = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 }
  local function f1(x, y, z) return (x & y) | (~x & z) end
  local function f2(x, y, z) return (x & y) | (x & z) | (y & z) end
  local function f3(x, y, z) return x ~ y ~ z end
  local M4 = {
    { { 0, 3 }, { 1, 7 }, { 2, 11 }, { 3, 19 },
      { 4, 3 }, { 5, 7 }, { 6, 11 }, { 7, 19 },
      { 8, 3 }, { 9, 7 }, { 10, 11 }, { 11, 19 },
      { 12, 3 }, { 13, 7 }, { 14, 11 }, { 15, 19 } },
    { { 0, 3 }, { 4, 5 }, { 8, 9 }, { 12, 13 },
      { 1, 3 }, { 5, 5 }, { 9, 9 }, { 13, 13 },
      { 2, 3 }, { 6, 5 }, { 10, 9 }, { 14, 13 },
      { 3, 3 }, { 7, 5 }, { 11, 9 }, { 15, 13 } },
    { { 0, 3 }, { 8, 9 }, { 4, 11 }, { 12, 15 },
      { 2, 3 }, { 10, 9 }, { 6, 11 }, { 14, 15 },
      { 1, 3 }, { 9, 9 }, { 5, 11 }, { 13, 15 },
      { 3, 3 }, { 11, 9 }, { 7, 11 }, { 15, 15 } },
  }
  local CONST = { 0, 0x5a827999, 0x6ed9eba1 }
  local FF = { f1, f2, f3 }
  local TP = { 0, 3, 2, 1 }
  local AX = { { 2, 3, 4 }, { 1, 2, 3 }, { 4, 1, 2 }, { 3, 4, 1 } }
  for off = 1, #data, 64 do
    local old = { r[1], r[2], r[3], r[4] }
    local X = {}
    for j = 0, 15 do
      X[j] = s32(data, off - 1 + j * 4)
    end
    for round = 1, 3 do
      for i = 0, 15 do
        local k, sh = M4[round][i + 1][1], M4[round][i + 1][2]
        local p = TP[i % 4 + 1]
        local q = AX[i % 4 + 1]
        local x, y, z = r[q[1]], r[q[2]], r[q[3]]
        local acc = (r[p + 1] + FF[round](x, y, z) + X[k] + CONST[round]) % 4294967296
        r[p + 1] = srotl(acc, sh)
      end
    end
    for t = 1, 4 do
      r[t] = (r[t] + old[t]) % 4294967296
    end
  end
  return su32(r[1]) .. su32(r[2]) .. su32(r[3]) .. su32(r[4])
end

local MD5_K = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

local MD5_S = {
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

local function md5(data)
  local len = #data
  local bitlen = len * 8
  data = data .. string.char(0x80)
  while #data % 64 ~= 56 do
    data = data .. string.char(0)
  end
  local l1 = bitlen % 4294967296
  local l2 = math.floor(bitlen / 4294967296) % 4294967296
  data = data .. su32(l1) .. su32(l2)
  local a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  for off = 1, #data, 64 do
    local M = {}
    for j = 0, 15 do
      M[j] = s32(data, off - 1 + j * 4)
    end
    local A, B, C, D = a0, b0, c0, d0
    for i = 0, 63 do
      local F, g
      if i < 16 then
        F = (B & C) | (~B & D)
        g = i
      elseif i < 32 then
        F = (D & B) | (~D & C)
        g = (5 * i + 1) % 16
      elseif i < 48 then
        F = B ~ C ~ D
        g = (3 * i + 5) % 16
      else
        F = C ~ (B | ~D)
        g = (7 * i) % 16
      end
      local tmp = D
      D = C
      C = B
      B = (B + srotl((A + F + MD5_K[i + 1] + M[g]) % 4294967296, MD5_S[i + 1])) % 4294967296
      A = tmp
    end
    a0 = (a0 + A) % 4294967296
    b0 = (b0 + B) % 4294967296
    c0 = (c0 + C) % 4294967296
    d0 = (d0 + D) % 4294967296
  end
  return su32(a0) .. su32(b0) .. su32(c0) .. su32(d0)
end

local function hmac_md5(key, msg)
  if #key > 64 then
    key = md5(key)
  end
  while #key < 64 do
    key = key .. string.char(0)
  end
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local b = key:byte(i)
    ipad[i] = string.char(b ~ 0x36)
    opad[i] = string.char(b ~ 0x5c)
  end
  ipad = table.concat(ipad)
  opad = table.concat(opad)
  return md5(opad .. md5(ipad .. msg))
end

local NTLM_FLAG_UNICODE = 0x00000001
local NTLM_FLAG_OEM = 0x00000002
local NTLM_FLAG_REQUEST_TARGET = 0x00000004
local NTLM_FLAG_NTLM = 0x00000200
local NTLM_FLAG_ALWAYS_SIGN = 0x00800000
local NTLM_FLAG_NTLMV2 = 0x02000000
local NTLM_FLAG_56 = 0x10000000
local NTLM_FLAG_128 = 0x20000000

local function ntlm_field(len, offset)
  return su16(len) .. su16(len) .. su32(offset)
end

local function ntlm_utf16(text)
  local out = {}
  for i = 1, #text do
    out[#out + 1] = text:sub(i, i) .. string.char(0)
  end
  return table.concat(out)
end

local function ntlm_negotiate_msg(use_v2, domain, workstation)
  local flags = NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_128 | NTLM_FLAG_56
  if use_v2 then
    flags = flags | NTLM_FLAG_NTLMV2
  else
    flags = flags | NTLM_FLAG_NTLM
  end
  local d = ntlm_utf16(domain or "")
  local w = ntlm_utf16(workstation or "")
  local head = "NTLMSSP\0" .. string.char(1, 0, 0, 0) .. su32(flags)
    .. ntlm_field(#d, 32)
    .. ntlm_field(#w, 32 + #d)
  return head .. d .. w
end

local function ntlm_authenticate_msg(user, domain, challenge, use_v2, password)
  local ntdomain = ntlm_utf16(domain or "")
  local nuser = ntlm_utf16(user or "")
  local nt_hash = md4(ntlm_utf16(password or ""))
  local client_chal = string.char(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
  local lm_resp, nt_resp
  if use_v2 then
    local v2_material = client_chal .. challenge
    lm_resp = hmac_md5(nt_hash, v2_material) .. client_chal
    nt_resp = hmac_md5(nt_hash, v2_material):sub(1, 16) .. client_chal
  else
    local filler = md5(nt_hash .. challenge .. string.char(1))
    lm_resp = filler .. string.rep("\0", 8)
    nt_resp = filler .. challenge
  end
  local target = ntlm_utf16("CORP\\SRV-FILE01")
  local flags = NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_128 | NTLM_FLAG_56
  if use_v2 then
    flags = flags | NTLM_FLAG_NTLMV2 | NTLM_FLAG_ALWAYS_SIGN
  else
    flags = flags | NTLM_FLAG_NTLM
  end
  local lm_off = 64
  local nt_off = lm_off + #lm_resp
  local dom_off = nt_off + #nt_resp
  local user_off = dom_off + #ntdomain
  local target_off = user_off + #nuser
  local head = "NTLMSSP\0" .. string.char(3, 0, 0, 0)
    .. ntlm_field(#lm_resp, lm_off)
    .. ntlm_field(#nt_resp, nt_off)
    .. ntlm_field(#ntdomain, dom_off)
    .. ntlm_field(#nuser, user_off)
    .. su32(flags)
    .. ntlm_field(0, 0)
    .. ntlm_field(0, 0)
  return head .. lm_resp .. nt_resp .. ntdomain .. nuser .. target
end

local function ntlm_parse_challenge(blob)
  if blob == nil or #blob < 32 or blob:sub(1, 8) ~= "NTLMSSP\0" then
    return nil
  end
  local mtype = s32(blob, 8)
  if mtype ~= 2 then
    return nil
  end
  local out = {
    flags = s32(blob, 20),
    challenge = blob:sub(25, 32),
  }
  local tn_len = s16(blob, 12)
  local tn_off = s32(blob, 16)
  if tn_len > 0 and tn_off >= 0 and tn_off + tn_len <= #blob then
    local raw = blob:sub(tn_off + 1, tn_off + tn_len)
    if out.flags % 2 == 1 then
      local plain = {}
      for i = 1, #raw, 2 do
        plain[#plain + 1] = raw:sub(i, i)
      end
      out.target_name = table.concat(plain)
    else
      out.target_name = raw
    end
  end
  if #blob >= 48 then
    out.target_info_len = s16(blob, 40)
    out.target_info_off = s32(blob, 44)
  end
  return out
end

local function ntlm_negotiate_flags(flags)
  local list = {}
  local function add(name, bit)
    if math.floor(flags / bit) % 2 == 1 then
      list[#list + 1] = name
    end
  end
  add("UNICODE", 0x00000001)
  add("OEM", 0x00000002)
  add("REQUEST_TARGET", 0x00000004)
  add("NTLM", 0x00000200)
  add("ALWAYS_SIGN", 0x00800000)
  add("NTLMv2", 0x02000000)
  add("56-bit", 0x10000000)
  add("128-bit", 0x20000000)
  table.sort(list)
  return list
end

local SMB_STATUS_NAMES = {
  [0x00000000] = "STATUS_SUCCESS",
  [0x00000005] = "STATUS_BAD_NETWORK_NAME",
  [0x00000016] = "STATUS_MORE_PROCESSING_REQUIRED",
  [0x00000021] = "STATUS_NOT_IMPLEMENTED",
  [0x00000020] = "STATUS_UNSUCCESSFUL",
  [0x00000043] = "STATUS_OBJECT_NAME_INVALID",
  [0x000000a2] = "STATUS_ACCESS_DENIED",
  [0x00000121] = "STATUS_NOT_SUPPORTED",
  [0x0000015b] = "STATUS_FILE_CLOSED",
  [0x0000035c] = "STATUS_TIMEOUT",
  [0x00000520] = "STATUS_BAD_DEVICE_TYPE",
  [0x0000051f] = "STATUS_NOT_FOUND",
  [0x80000003] = "STATUS_STOPPED_ON_ERROR",
  [0x80000004] = "STATUS_END_OF_MEDIA",
  [0x80000020] = "STATUS_NO_SUCH_PARTITION",
  [0xc0000001] = "STATUS_WARNING_CANCEL",
  [0xc000000d] = "STATUS_INVALID_CARRIER",
  [0xc0000022] = "STATUS_ACCESS_DENIED",
  [0xc0000034] = "STATUS_EOM_OVERFLOW",
  [0xc000006d] = "STATUS_LOGON_FAILURE",
  [0xc00000cf] = "STATUS_BAD_NETWORK_NAME",
  [0xc00000cc] = "STATUS_NOT_IMPLEMENTED",
  [0xc000013c] = "STATUS_OBJECT_NAME_NOT_FOUND",
  [0xc000013e] = "STATUS_OBJECT_NAME_COLLISION",
  [0xc0000142] = "STATUS_OBJECT_PATH_NOT_FOUND",
  [0xc0000193] = "STATUS_EMPTY",
  [0xc0000224] = "STATUS_ACCOUNT_RESTRICTION",
  [0xc0000225] = "STATUS_SHARING_VIOLATION",
  [0xc0000281] = "STATUS_FILE_IS_A_DIRECTORY",
  [0xc0000312] = "STATUS_BAD_LOCAL",
  [0xc0000353] = "STATUS_TIMEOUT",
  [0xc00003e5] = "STATUS_FILE_CORRUPT",
  [0xc00003e9] = "STATUS_NOT_A_DIRECTORY",
  [0xc000048d] = "STATUS_PIPE_EMPTY",
  [0xc00004e6] = "STATUS_PIPE_DISCONNECTED",
  [0xc0000508] = "STATUS_NO_SUCH_LOGON_SESSION",
  [0xc0000550] = "STATUS_ACCOUNT_DISABLED",
  [0xc0000906] = "STATUS_CLIENT_INVALID",
  [0xc0000980] = "STATUS_NO_SUCH_PACKAGE",
  [0xc0000998] = "STATUS_MEMBER_NOT_FOUND",
  [0xc0000a1b] = "STATUS_INVALID_DOMAIN_POLICY",
  [0xc0000a83] = "STATUS_DOMAIN_ALREADY_EXISTS",
  [0xc0000ab9] = "STATUS_NO_INSTRUCTIONS_SENT_TO_SERVER",
  [0xc0000ac6] = "STATUS_NO_MORE_ELEMENTS",
  [0xc0000bb9] = "STATUS_PDC_NOT_FOUND",
  [0xc0000d16] = "STATUS_SOME_BUFFERS_NOT_RETURNED",
  [0xc0000dcd] = "STATUS_SERVER_SHUTDOWN_IN_PROGRESS",
  [0xc0001013] = "STATUS_SMB_BAD_COMMAND",
  [0xc0001017] = "STATUS_SMB_BAD_TID",
  [0xc0001018] = "STATUS_SMB_BAD_PID",
  [0xc0001022] = "STATUS_SMB_BAD_UVC",
  [0xc000103f] = "STATUS_SMB_INVALID_PASSWORD",
  [0xc0001100] = "STATUS_SMB_USER_SESSION_LIMIT_REACHED",
  [0xc0001104] = "STATUS_SMB_INVALID_MID",
  [0xc0001105] = "STATUS_SMB_OPEN_FAILED",
  [0xc0001107] = "STATUS_SMB_TOO_MANY_OPENED",
  [0xc000110c] = "STATUS_SMB_INVALID_SHARE",
  [0xc000110d] = "STATUS_SMB_CONNECTION_RESET",
  [0xc000110e] = "STATUS_SMB_INVALID_PACKET",
  [0xc0001115] = "STATUS_SMB_BAD_USER_NAME",
  [0xc0001116] = "STATUS_SMB_BAD_PASSWORD",
  [0xc0001117] = "STATUS_SMB_SHARE_ACCESS_DENIED",
  [0xc0001118] = "STATUS_SMB_INVALID_SHARE_TYPE",
  [0xc000111c] = "STATUS_SMB_BAD_LOCK",
  [0xc000111e] = "STATUS_SMB_BAD_PIPE_NAME",
  [0xc000111f] = "STATUS_SMB_PIPE_BUSY",
  [0xc0001120] = "STATUS_SMB_PIPE_DISCONNECTED",
  [0xc0001121] = "STATUS_SMB_PIPE_CLOSED",
  [0xc0001123] = "STATUS_SMB_PIPE_DISASSEMBLED",
  [0xc0001124] = "STATUS_SMB_BAD_PIPE_WAIT",
  [0xc0001125] = "STATUS_SMB_PIPE_EMPTY",
  [0xc0001126] = "STATUS_SMB_PIPE_NAME_INUSE",
  [0xc0001127] = "STATUS_SMB_PIPE_NOT_CONNECTED",
}

local SMB1_CAPS = {
  [0x00000001] = "RAW",
  [0x00000002] = "CANONICALIZE",
  [0x00000004] = "USE_NT_ERRORS",
  [0x00000008] = "UNICODE",
  [0x00000010] = "BAKED",
  [0x00000020] = "LARGE_FILES",
  [0x00000040] = "MBZ",
  [0x00000080] = "LOCAL_USE_ONLY",
  [0x00000100] = "USE_NATIVE_PATHS",
  [0x00000200] = "NT_FIND",
  [0x00000400] = "NT_SMBS",
  [0x00000800] = "LOW_DATAGRAM",
  [0x00008000] = "EXTENDED_SECURITY",
  [0x00020000] = "DFS",
  [0x00040000] = "DFSR",
  [0x00080000] = "LEVEL_2_OPLOCKS",
  [0x00100000] = "COMPRESSION",
  [0x00200000] = "PERSISTENT_HANDLES",
  [0x00400000] = "SMB_SIGNING",
  [0x01000000] = "SMB_KERBEROS",
}

local SMB2_CAPS = {
  [0x00000001] = "DURABLE_HANDLES",
  [0x00000002] = "LEASES",
  [0x00000004] = "MULTI_CHANNEL",
  [0x00000008] = "LARGE_MTU",
  [0x00000010] = "PERSISTENT_HANDLES",
  [0x00000020] = "DIRECTORY_LEASING",
  [0x00000040] = "ENCRYPTION",
}

local SMB2_DIALECT_NAMES = {
  [0x0202] = "SMB 2.002",
  [0x0210] = "SMB 2.1.0",
  [0x0300] = "SMB 3.0.0",
  [0x0302] = "SMB 3.0.2",
  [0x0311] = "SMB 3.1.1",
}

local SMB2_DIALECT_CODES = {
  ["SMB 2.002"] = 0x0202,
  ["SMB 2.1.0"] = 0x0210,
  ["SMB 3.0.0"] = 0x0300,
  ["SMB 3.0.2"] = 0x0302,
  ["SMB 3.1.1"] = 0x0311,
}

local SMB1_SERVICE_NAMES = {
  [0x01] = "DISK",
  [0x02] = "PIPE",
  [0x03] = "PRINT",
  [0x80] = "IPC",
}

local SMB2_SERVICE_NAMES = {
  [0x01] = "DISK",
  [0x02] = "PIPE",
  [0x03] = "PRINT",
  [0x80] = "IPC",
}

local function status_name(code)
  if type(code) ~= "number" then
    return "UNKNOWN"
  end
  return SMB_STATUS_NAMES[math.floor(code)] or string.format("STATUS_0x%08x", math.floor(code))
end

local function cap_list(flags, table_map)
  local list = {}
  for bit, name in pairs(table_map) do
    if math.floor(flags / bit) % 2 == 1 then
      list[#list + 1] = name
    end
  end
  table.sort(list)
  return list
end

local function guid_hex(g)
  local out = {}
  for i = 1, #g do
    out[#out + 1] = string.format("%02x", g:byte(i))
  end
  return table.concat(out)
end

local function smbt_utf16_to_ascii(raw)
  local plain = {}
  for i = 1, #raw, 2 do
    plain[#plain + 1] = raw:sub(i, i)
  end
  return table.concat(plain)
end

local function smbt_set_u16(msg, off, value)
  return msg:sub(1, off) .. su16(value) .. msg:sub(off + 2)
end

local function smbt_set_u32(msg, off, value)
  return msg:sub(1, off) .. su32(value) .. msg:sub(off + 4)
end

local function smbt_netbios_wrap(msg)
  return string.char(0) .. su16(#msg) .. string.char(0, 0x80)
    .. su16(0x01f0) .. string.char(0, 0) .. "CORP\0\0\0\0" .. msg
end

local function smbt_netbios_unwrap(resp, port)
  if port == 139 and #resp >= 17 then
    local first = resp:byte(1)
    if first == 0 or first == 0x80 then
      return resp:sub(18)
    end
  end
  return resp
end

local function smbt_s1_header(cmd, mid)
  return string.char(0xff, 0x53, 0x4d, 0x42) .. string.char(cmd)
    .. su16(0) .. string.char(0x51) .. su16(0)
    .. su16(0x01f0) .. su32(mid) .. su16(0) .. su16(0)
    .. su32(0) .. su16(0) .. su32(0)
end

local function smbt_s1_negotiate(dialects, mid)
  local parts = {}
  for i = 1, #dialects do
    parts[i] = string.char(#dialects[i]) .. dialects[i]
  end
  return smbt_s1_header(0x00, mid) .. string.rep("\0", 2)
    .. su16(#dialects) .. table.concat(parts)
end

local function smbt_s1_session_setup(blob, mid)
  return smbt_s1_header(0x0f, mid) .. string.rep("\0", 9)
    .. su16(#blob) .. string.rep("\0", 2) .. blob
end

local function smbt_s1_tree_connect(path, mid)
  return smbt_s1_header(0x75, mid) .. string.rep("\0", 11)
    .. su16(#path) .. string.char(0) .. path
end

local function smbt_s1_echo(data, mid)
  return smbt_s1_header(0x07, mid) .. string.rep("\0", 5)
    .. su16(#data) .. data
end

local function smbt_s2_base(cmd, mid)
  return string.char(0xfe, 0x53, 0x4d, 0x42)
    .. su16(112) .. string.char(0, 0)
    .. su32(0)
    .. su32(1)
    .. su16(cmd)
    .. su16(1)
    .. su32(mid) .. su32(0)
    .. su16(0x0800)
    .. su16(0xffff)
    .. su16(0)
    .. su32(0) .. su32(0)
    .. su32(0) .. su32(0)
    .. string.rep("\0", 16)
    .. su16(0) .. su16(0)
    .. su32(3) .. su32(0)
    .. string.rep("\0", 28)
end

local function smbt_s2_negotiate(codes, mid)
  local msg = smbt_s2_base(0x0000, mid):sub(1, 67)
  msg = smbt_set_u16(msg, 66, #codes)
  msg = msg .. string.rep("\0", 23)
  for i = 1, #codes do
    msg = msg .. su16(codes[i]) .. su32(0)
  end
  return msg
end

local function smbt_s2_session_setup(blob, mid)
  local msg = smbt_s2_base(0x0002, mid)
  msg = msg .. string.rep("\0", 10)
  msg = msg .. su16(62) .. su16(#blob)
  msg = msg .. string.rep("\0", 54)
  return msg .. blob
end

local function smbt_s2_tree_connect(name_utf16, mid)
  local msg = smbt_s2_base(0x0003, mid)
  msg = msg .. string.rep("\0", 10)
  msg = msg .. su16(60) .. su16(#name_utf16)
  msg = msg .. string.rep("\0", 52)
  return msg .. name_utf16
end

local function smbt_s2_echo(mid)
  return smbt_s2_base(0x0012, mid) .. su16(4)
end

local function smbt_parse_s1(resp)
  local out = { kind = "s1", cmd = resp:byte(5), status = s16(resp, 5) }
  if out.cmd == 0x02 then
    out.dialect_index = s16(resp, 54)
    out.params = resp:sub(31)
    local rest = resp:sub(57)
    local names = {}
    for part in rest:gmatch("[^%z]+") do
      names[#names + 1] = part
    end
    out.server_info = names
  elseif out.cmd == 0x0f then
    if out.status == 0 then
      out.action = s16(resp, 30)
      local bloblen = resp:byte(33) or 0
      out.blob = resp:sub(36, 35 + bloblen)
    end
  elseif out.cmd == 0x75 then
    if out.status == 0 then
      out.service = resp:byte(36) or 0
      out.access = s32(resp, 39)
      local plen = s16(resp, 43)
      out.path = resp:sub(46, 45 + plen)
    elseif out.status == 0x0016 then
      local rlen = s16(resp, 30)
      out.referral = resp:sub(39, 38 + rlen)
    end
  elseif out.cmd == 0x07 then
    local dlen = s16(resp, 33)
    out.data = resp:sub(36, 35 + dlen)
  end
  return out
end

local function smbt_find_ntlm_blob(resp, min_off_1based)
  local sig = "NTLMSSP\0"
  local i = resp:find(sig, min_off_1based, true)
  if i == nil then
    return nil
  end
  return resp:sub(i)
end

local function smbt_parse_s2(resp)
  local out = { kind = "s2", cmd = s16(resp, 16), status = s32(resp, 8),
    sec_flags = s32(resp, 74) }
  if out.cmd == 0x0001 then
    out.dialect_code = s16(resp, 112)
    out.capabilities = s32(resp, 132)
    out.max_transact = s32(resp, 136)
    out.max_read = s32(resp, 140)
    out.max_write = s32(resp, 144)
    out.server_guid = resp:sub(117, 132)
    local sec_off = s16(resp, 108)
    local sec_len = s16(resp, 110)
    if sec_off > 0 and sec_len > 0 and sec_off + sec_len <= #resp then
      out.blob = resp:sub(sec_off + 1, sec_off + sec_len)
    end
  elseif out.cmd == 0x0002 then
    if out.status == 0 then
      out.blob = smbt_find_ntlm_blob(resp, 107)
    end
  elseif out.cmd == 0x0003 then
    if out.status == 0 then
      out.service = resp:byte(109) or 0
      out.access = s32(resp, 118)
      local nlen = s16(resp, 150)
      if nlen > 0 and 152 + nlen <= #resp then
        out.name = smbt_utf16_to_ascii(resp:sub(153, 152 + nlen))
      end
    elseif out.status == 0x0016 then
      local rlen = s16(resp, 152)
      if rlen > 0 and 160 + rlen <= #resp then
        out.referral = resp:sub(161, 160 + rlen)
      else
        out.referral = resp:sub(161)
      end
    end
  end
  return out
end

local function smbt_parse_referral(body)
  local refs = {}
  if body == nil or #body < 24 then
    return refs
  end
  local total = s32(body, 0)
  local num = s16(body, 12)
  local path_off = s16(body, 18)
  local str_off = s16(body, 22)
  local function read_str(off, sz)
    if off == 0 then
      return ""
    end
    local s = body:sub(off + 1, off + sz)
    local cut = s:find("\0")
    if cut then
      s = s:sub(1, cut - 1)
    end
    return s
  end
  for i = 0, num - 1 do
    local e = 24 + i * 20
    if e + 20 > #body then
      break
    end
    local name_off = s16(body, e + 8)
    local name_sz = s16(body, e + 10)
    local content_off = s16(body, e + 12)
    local content_sz = s16(body, e + 14)
    refs[#refs + 1] = {
      name = read_str(name_off, name_sz),
      content = read_str(content_off, content_sz),
      index = i,
    }
  end
  if total > 0 then
    refs.total = total
  end
  return refs
end

local function smbt_dialect_name(code)
  local codes = {
    [0x0202] = "SMB 2.002",
    [0x0210] = "SMB 2.1.0",
    [0x0300] = "SMB 3.0.0",
    [0x0302] = "SMB 3.0.2",
    [0x0311] = "SMB 3.1.1",
  }
  return codes[code] or string.format("SMB 0x%04x", code)
end

local function smbt_exchange(sess, msg)
  local wire = msg
  if sess.port == 139 then
    wire = smbt_netbios_wrap(wire)
  end
  local ok, err = sess.sock:send(wire)
  if not ok then
    return nil, err or "send failed"
  end
  local ok1, first, err1 = sess.sock:receive(1)
  if not ok1 then
    return nil, err1 or "timeout waiting for response"
  end
  local ok2, rest, err2 = sess.sock:receive()
  if not ok2 then
    return nil, err2 or "timeout waiting for response body"
  end
  local resp = first .. rest
  resp = smbt_netbios_unwrap(resp, sess.port)
  if #resp < 32 then
    return nil, "truncated response (" .. #resp .. " bytes)"
  end
  sess.mid = (sess.mid + 1) % 4294967296
  local first = resp:byte(1)
  if first == 0xff then
    return smbt_parse_s1(resp)
  elseif first == 0xfe then
    return smbt_parse_s2(resp)
  end
  return nil, "unrecognized protocol signature"
end

local function smbt_ntlm_session(sess, is_smb2)
  local mech = sess.opts.mech or "ntlmv2"
  local use_v2 = (mech == "ntlmv2")
  local t1 = ntlm_negotiate_msg(use_v2, sess.opts.domain or "CORP", "WS-01")
  local blob, mid = t1, sess.mid
  sess.mid = sess.mid + 1
  local req = is_smb2 and smbt_s2_session_setup(blob, mid)
    or smbt_s1_session_setup(blob, mid)
  local rep, err = smbt_exchange(sess, req)
  if rep == nil then
    return nil, err
  end
  if rep.status ~= 0 then
    return nil, status_name(rep.status)
  end
  local challenge_blob = rep.blob or ""
  local ch = ntlm_parse_challenge(challenge_blob)
  if ch == nil or ch.challenge == nil or #ch.challenge ~= 8 then
    return nil, "no NTLM challenge in server response"
  end
  sess.challenge = ch.challenge
  sess.challenge_flags = ch.flags
  sess.target_name = ch.target_name
  local t3 = ntlm_authenticate_msg(
    sess.opts.user or "", sess.opts.domain or "CORP",
    ch.challenge, use_v2, sess.opts.password or "")
  local mid2 = sess.mid
  sess.mid = sess.mid + 1
  local req2 = is_smb2 and smbt_s2_session_setup(t3, mid2)
    or smbt_s1_session_setup(t3, mid2)
  local rep2, err2 = smbt_exchange(sess, req2)
  if rep2 == nil then
    return nil, err2
  end
  if rep2.status ~= 0 then
    return false, status_name(rep2.status)
  end
  sess.mech = mech
  sess.action = rep2.action or 0
  sess.user = sess.opts.user or ""
  return true
end

local function smbt_new(sock, host, port, opts)
  opts = opts or {}
  local sess = {
    sock = sock,
    host = host,
    port = port,
    opts = opts,
    mid = 1,
    dialect = nil,
    is_smb2 = nil,
    sec_flags = nil,
    mech = nil,
    action = nil,
    user = nil,
    challenge = nil,
    challenge_flags = nil,
    target_name = nil,
    server_info = nil,
    capabilities = nil,
    max_transact = nil,
    max_read = nil,
    max_write = nil,
    server_guid = nil,
    closed = false,
  }
  sock:set_timeout(opts.timeout or 30)
  local probe = opts.negotiate or "full"
  if probe == "smb1-only" then
    local rep, err = smbt_exchange(sess,
      smbt_s1_negotiate({ "NT LM 0.12" }, sess.mid))
    if rep == nil then
      return nil, err
    end
    if rep.kind ~= "s1" then
      return nil, "expected SMB1 negotiate response"
    end
    if rep.status == 0x0005 then
      return nil, "server rejected SMB1 dialect (STATUS_NOT_SUPPORTED)"
    end
    if rep.status ~= 0 then
      return nil, status_name(rep.status)
    end
    sess.dialect = "NT LM 0.12"
    sess.is_smb2 = false
    sess.dialect_index = rep.dialect_index
    sess.server_info = rep.server_info
    sess.s1_negotiate = rep.params
    local ok, aerr = smbt_ntlm_session(sess, false)
    if ok == nil then
      return nil, aerr
    end
    return sess
  end
  local rep, err = smbt_exchange(sess,
    smbt_s1_negotiate({ "NT LM 0.12", "SMB 2.002", "SMB 3.1.1" }, sess.mid))
  if rep == nil then
    return nil, err
  end
  if rep.kind == "s1" then
    if rep.status == 0x0005 then
      return nil, "server rejected SMB1 dialect (STATUS_NOT_SUPPORTED)"
    end
    if rep.status ~= 0 then
      return nil, status_name(rep.status)
    end
    sess.dialect = "NT LM 0.12"
    sess.is_smb2 = false
    sess.server_info = rep.server_info
    sess.s1_negotiate = rep.params
    local ok, aerr = smbt_ntlm_session(sess, false)
    if ok == nil then
      return nil, aerr
    end
    return sess
  end
  sess.dialect = smbt_dialect_name(rep.dialect_code)
  sess.is_smb2 = true
  sess.sec_flags = rep.sec_flags
  sess.capabilities = rep.capabilities
  sess.max_transact = rep.max_transact
  sess.max_read = rep.max_read
  sess.max_write = rep.max_write
  sess.server_guid = rep.server_guid and guid_hex(rep.server_guid) or nil
  local ok, aerr = smbt_ntlm_session(sess, true)
  if ok == nil then
    return nil, aerr
  end
  return sess
end

local function make_mt(sess)
  sess.tree_connect = function(self, share)
    if self.closed then
      return nil, "session closed"
    end
    local path = "\\\\" .. tostring(self.host) .. "\\" .. share
    local rep, err
    if self.is_smb2 then
      local mid = self.mid
      self.mid = self.mid + 1
      rep, err = smbt_exchange(self, smbt_s2_tree_connect(ntlm_utf16(path), mid))
    else
      local mid = self.mid
      self.mid = self.mid + 1
      rep, err = smbt_exchange(self, smbt_s1_tree_connect(path, mid))
    end
    if rep == nil then
      return nil, err
    end
    if rep.status ~= 0 then
      if rep.status == 0x0016 and rep.referral then
        return false, status_name(rep.status), smbt_parse_referral(rep.referral)
      end
      return nil, status_name(rep.status)
    end
    return true, {
      service = rep.service,
      access = rep.access,
      name = rep.name or rep.path,
    }
  end
  sess.echo = function(self, data)
    if self.closed then
      return nil, "session closed"
    end
    local rep, err
    if self.is_smb2 then
      local mid = self.mid
      self.mid = self.mid + 1
      rep, err = smbt_exchange(self, smbt_s2_echo(mid))
    else
      local mid = self.mid
      self.mid = self.mid + 1
      rep, err = smbt_exchange(self, smbt_s1_echo(data, mid))
    end
    if rep == nil then
      return nil, err
    end
    if rep.status ~= 0 then
      return nil, status_name(rep.status)
    end
    return true, rep.data
  end
  sess.close = function(self)
    if not self.closed then
      self.closed = true
      self.sock:close()
    end
  end
  return sess
end

local function smbtransport_new(sock, host, port, opts)
  local result, err = smbt_new(sock, host, port, opts)
  if result == nil then
    return nil, err
  end
  return make_mt(result)
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

local function port_num(p)
  local n = p and (p.number or p.port)
  return tonumber(n) or 0
end

local function open_session(host, port, opts)
  local pnum = port_num(port)
  local sock = nmap.new_socket("tcp")
  local ok, cerr = sock:connect(host.ip, pnum)
  if not ok then
    sock:close()
    state.errors = state.errors + 1
    return nil, cerr or "connect failed"
  end
  state.requests = state.requests + 1
  local sess, err = smbtransport_new(sock, host.name, pnum, opts)
  if sess == nil then
    sock:close()
    state.errors = state.errors + 1
    return nil, err
  end
  return sess
end

local function fmt_size(value)
  if value == nil then
    return "n/a"
  end
  if value >= 1048576 then
    return string.format("%d bytes (%.1f MB)", value, value / 1048576)
  end
  if value >= 1024 then
    return string.format("%d bytes (%.1f KB)", value, value / 1024)
  end
  return string.format("%d bytes", value)
end

local function deviation_lines(label, value, default)
  if value == nil or default == nil then
    return {}
  end
  if value == default then
    return { string.format("%s: %s (matches common default)", label, fmt_size(value)) }
  end
  if value < default then
    return { string.format("%s: %s (below common default %s - restricted or proxy-like configuration)", label, fmt_size(value), fmt_size(default)) }
  end
  return { string.format("%s: %s (above common default %s - tuned or non-standard stack)", label, fmt_size(value), fmt_size(default)) }
end

local function full_probe(host, port, args)
  local sess, err = open_session(host, port, { timeout = args.timeout })
  if sess == nil then
    return nil, err
  end
  local facts = {
    dialect = sess.dialect,
    is_smb2 = sess.is_smb2,
    max_transact = sess.max_transact,
    max_read = sess.max_read,
    max_write = sess.max_write,
  }
  sess:close()
  return facts
end

local function smb1_probe(host, port, args)
  local sess, err = open_session(host, port, { timeout = args.timeout, negotiate = "smb1-only" })
  if sess == nil then
    local result = { offered = false, detail = err }
    if err and err:find("STATUS_NOT_SUPPORTED") then
      result.detail_kind = "smb1-disabled"
    end
    return result
  end
  local params = sess.s1_negotiate
  local result = { offered = true }
  if params and #params >= 10 then
    result.max_buf = s16(params, 6)
    result.max_mpx = s16(params, 8)
    if result.max_buf == 0 then
      result.max_buf = 65536
    end
  end
  sess:close()
  return result
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()

  local out = new_output(RISK_LEVEL, "AUDITED - SMB advertised transfer limits reported.")
  local sections = {}
  local notes = {}
  local limit_lines = {}

  local modern, modern_err = full_probe(host, port, args)
  if modern == nil then
    table.insert(notes, "full-dialect probe failed: " .. tostring(modern_err))
  elseif modern.is_smb2 then
    table.insert(limit_lines, string.format("dialect: %s", tostring(modern.dialect)))
    for _, line in ipairs(deviation_lines("MaxTransact", modern.max_transact, SMB2_DEFAULTS.max_transact)) do
      limit_lines[#limit_lines + 1] = line
    end
    for _, line in ipairs(deviation_lines("MaxRead", modern.max_read, SMB2_DEFAULTS.max_read)) do
      limit_lines[#limit_lines + 1] = line
    end
    for _, line in ipairs(deviation_lines("MaxWrite", modern.max_write, SMB2_DEFAULTS.max_write)) do
      limit_lines[#limit_lines + 1] = line
    end
    local below_default = (modern.max_read ~= nil and modern.max_read < 65536)
      or (modern.max_write ~= nil and modern.max_write < 65536)
    add_finding("LOW",
      string.format("SMB2/3 advertised transfer limits: transact=%s read=%s write=%s%s",
        fmt_size(modern.max_transact),
        fmt_size(modern.max_read),
        fmt_size(modern.max_write),
        below_default and " (read/write below 64KB - unusually restrictive)" or ""),
      { subject = "smb2-transfer-limits",
        evidence = "dialect=" .. tostring(modern.dialect) })
  else
    table.insert(notes, "no SMB2/3 dialect selected: " .. tostring(modern.dialect))
  end

  if not budget_exhausted(args) then
    local v1 = smb1_probe(host, port, args)
    if v1.offered then
      table.insert(limit_lines, string.format("dialect: NT LM 0.12 (SMBv1)"))
      for _, line in ipairs(deviation_lines("MaxBuffer", v1.max_buf, SMB1_DEFAULTS.max_buf)) do
        limit_lines[#limit_lines + 1] = line
      end
      table.insert(limit_lines, string.format("MaxMpxCount: %s (common default %d)",
        tostring(v1.max_mpx), SMB1_DEFAULTS.max_mpx))
      add_finding("LOW",
        string.format("SMBv1 advertised limits: MaxBuffer=%s MaxMpxCount=%s",
          fmt_size(v1.max_buf), tostring(v1.max_mpx)),
        { subject = "smbv1-transfer-limits",
          evidence = "dialect=NT LM 0.12" })
    elseif v1.detail_kind == "smb1-disabled" then
      table.insert(notes, "SMBv1 probe: rejected (SMBv1 disabled) - SMBv1 limits not applicable")
    else
      table.insert(notes, "SMBv1 probe: " .. tostring(v1.detail))
    end
  end

  table.insert(sections, { key = "transfer_limits", value = limit_lines })
  table.insert(sections, { key = "limits_reference", value = LIMITS_REFERENCE })
  table.insert(sections, { key = "probe_notes", value = notes })
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)

end
