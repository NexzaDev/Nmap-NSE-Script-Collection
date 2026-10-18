local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Fingerprints the RFB ProtocolVersion banner the VNC server announces before
any authentication and maps it to a stack generation with known exposure
history.

Why it matters
- The banner fixes the maximum feature set of the session (security-type
  negotiation, VeNCrypt/TLS paths, result codes).
- Very old banners (3.3/3.7) correlate with unpatched builds that expose
  the MS12-020 and RealVNC 4.1 era flaws.

What the script does
1. Connects and reads the 12-byte ProtocolVersion greeting.
2. Completes one offer-only handshake to learn the negotiated version.
3. Maps the banner to a stack generation table and reports legacy flags.

Safe operation: one TCP session, banner read and security-type offer
only; no authentication is attempted.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  5900,
  "vnc",
  "tcp"
)

local SCRIPT_NAME = "vnc-rfb-version-fingerprint"

local RISK_LEVEL = "🟢 LOW"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 32,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}

local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, integer = true },
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

VNC_T = {}

VNC_T.RFB_3_3 = "RFB 003.003\n"
VNC_T.RFB_3_7 = "RFB 003.007\n"
VNC_T.RFB_3_8 = "RFB 003.008\n"
VNC_T.RFB_4_1 = "RFB 004.001\n"
VNC_T.RFB_REPEATER = "RFB 000.000.000\n"

VNC_T.SEC_INVALID = 0
VNC_T.SEC_NONE = 1
VNC_T.SEC_VNC = 2
VNC_T.SEC_RA2 = 5
VNC_T.SEC_RA2NE = 6
VNC_T.SEC_RA2_1WAY = 7
VNC_T.SEC_RA2NE_1WAY = 8
VNC_T.SEC_ULTRA = 15
VNC_T.SEC_TIGHT = 16
VNC_T.SEC_TLS = 17
VNC_T.SEC_VENCRYPT = 18
VNC_T.SEC_XVP = 19
VNC_T.SEC_SASL = 23
VNC_T.SEC_APPLE = 30
VNC_T.SEC_RSA_AES = 128
VNC_T.SEC_RSA_AES_256 = 129

VNC_T.SEC_NAMES = {
  [0] = "Invalid",
  [1] = "None (unauthenticated)",
  [2] = "VNC challenge-response (DES-56)",
  [5] = "RealVNC RA2 (AES)",
  [6] = "RealVNC RA2ne (AES, session ephemeral)",
  [7] = "RealVNC RA2 one-way",
  [8] = "RealVNC RA2ne one-way",
  [15] = "UltraVNC ultra",
  [16] = "Tight",
  [17] = "TLS-encrypted RFB",
  [18] = "VeNCrypt",
  [19] = "xvp",
  [23] = "SASL",
  [30] = "Apple Remote Desktop",
  [128] = "RSA/AES",
  [129] = "RSA/AES 256-bit",
}

VNC_T.SEC_FAMILY = {
  [1] = "plaintext",
  [2] = "legacy-des",
  [5] = "strong",
  [6] = "strong",
  [7] = "strong",
  [8] = "strong",
  [16] = "wrapper",
  [17] = "encrypted-transport",
  [18] = "encrypted-transport",
  [19] = "encrypted-transport",
  [23] = "strong",
  [30] = "vendor",
  [128] = "strong",
  [129] = "strong",
}

VNC_T.MSG_CLIENT_SETPIXELFORMAT = 0
VNC_T.MSG_CLIENT_SETENCODINGS = 2
VNC_T.MSG_CLIENT_FBUPDATE_REQ = 3
VNC_T.MSG_CLIENT_KEYEVENT = 4
VNC_T.MSG_CLIENT_POINTEREVENT = 5
VNC_T.MSG_CLIENT_CUTTEXT = 6

VNC_T.MSG_SERVER_FBUPDATE = 0
VNC_T.MSG_SERVER_COLOURMAP = 1
VNC_T.MSG_SERVER_BELL = 2
VNC_T.MSG_SERVER_CUTTEXT = 3

VNC_T.LEGACY_VERSIONS = {
  ["3.3"] = "RFB 3.3 (1995 era): fixed server-chosen security, no TLS path",
  ["3.7"] = "RFB 3.7: minimal negotiation, no mandatory SecurityResult",
  ["3.8"] = "RFB 3.8: SecurityResult mandatory for None",
}

VNC_T.REPEATER_PROBE_ID = "ID:0000000000:AUDIT"

VNC_T.DES_PC1 = {
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
  59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
  31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
  29, 21, 13, 5, 28, 20, 12, 4,
}

VNC_T.DES_SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }

VNC_T.DES_PC2 = {
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
}

VNC_T.DES_IP = {
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
}

VNC_T.DES_E = {
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
}

VNC_T.DES_P = {
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
}

VNC_T.DES_IPINV = {
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
}

VNC_T.DES_SBOX = {
  {
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  },
  {
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  },
  {
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  },
  {
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  },
  {
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  },
  {
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  },
  {
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  },
  {
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  },
}

VNC_T.DES_SELFTEST = {
  { key = "\x13\x34\x57\x79\x9B\xBC\xDF\xF1", plain = "\x01\x23\x45\x67\x89\xAB\xCD\xEF", cipher = "\x85\xE8\x13\x54\x0F\x0A\xB4\x05" },
  { key = "\x0E\x32\x92\x32\xEA\x6D\x0D\x73", plain = "\x87\x87\x87\x87\x87\x87\x87\x87", cipher = "\x00\x00\x00\x00\x00\x00\x00\x00" },
}

VNC_B = {}

VNC_B.u8 = function(v)
  return string.char(v % 256)
end

VNC_B.u16be = function(v)
  return string.char(math.floor(v / 256) % 256, v % 256)
end

VNC_B.u32be = function(v)
  return string.char(
    math.floor(v / 16777216) % 256,
    math.floor(v / 65536) % 256,
    math.floor(v / 256) % 256,
    v % 256)
end

VNC_B.protocol_version = function(major, minor)
  return string.format("RFB %03d.%03d\n", major, minor)
end

VNC_B.security_choice = function(sec_type)
  return VNC_B.u8(sec_type)
end

VNC_B.client_init = function(share_desktop)
  if share_desktop then
    return "\x01"
  end
  return "\x00"
end

VNC_B.set_pixel_format = function(fmt)
  local pad = "\x00\x00\x00"
  return "\x00" .. pad .. (fmt or VNC_B.default_pixel_format())
end

VNC_B.default_pixel_format = function()
  return VNC_B.pixel_format(32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
end

VNC_B.pixel_format = function(bpp, depth, big_endian, true_colour, rmax, gmax, bmax, rshift, gshift, bshift)
  return string.char(bpp, depth, big_endian, true_colour)
    .. VNC_B.u16be(rmax) .. VNC_B.u16be(gmax) .. VNC_B.u16be(bmax)
    .. string.char(rshift, gshift, bshift) .. "\x00\x00\x00"
end

VNC_B.set_encodings = function(encodings)
  local body = {}
  body[#body + 1] = "\x02\x00"
  body[#body + 1] = VNC_B.u16be(#encodings)
  for i = 1, #encodings do
    body[#body + 1] = VNC_B.u32be(encodings[i])
  end
  return table.concat(body, "")
end

VNC_B.fb_update_request = function(incremental, x, y, w, h)
  return string.char(3, incremental and 1 or 0) .. VNC_B.u16be(x or 0) .. VNC_B.u16be(y or 0)
    .. VNC_B.u16be(w or 0) .. VNC_B.u16be(h or 0)
end

VNC_B.client_cut_text = function(text)
  return "\x06\x00\x00\x00" .. VNC_B.u32be(#tostring(text or "")) .. tostring(text or "")
end

VNC_B.repeater_id_string = function(id)
  local raw = tostring(id or "")
  if #raw > 250 then
    raw = raw:sub(1, 250)
  end
  return raw .. string.rep("\x00", 250 - #raw)
end

VNC_B.http_request = function(host_header, path, opts)
  opts = opts or {}
  local lines = {}
  lines[#lines + 1] = (opts.method or "GET") .. " " .. (path or "/") .. " HTTP/1.1"
  lines[#lines + 1] = "Host: " .. tostring(host_header or "target.example.com")
  lines[#lines + 1] = "User-Agent: Mozilla/5.0 (audit; NSE collection)"
  lines[#lines + 1] = "Accept: text/html,application/xhtml+xml"
  lines[#lines + 1] = "Connection: close"
  if opts.upgrade_websocket then
    lines[#lines + 1] = "Upgrade: websocket"
    lines[#lines + 1] = "Connection: Upgrade"
    lines[#lines + 1] = "Sec-WebSocket-Key: " .. (opts.ws_key or "dGhlIHNhbXBsZSBub25jZQ==")
    lines[#lines + 1] = "Sec-WebSocket-Version: 13"
  end
  return table.concat(lines, "\r\n") .. "\r\n\r\n"
end

VNC_B.base64_encode = function(data)
  local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local out = {}
  local i = 1
  while i <= #data do
    local a = data:byte(i)
    local b = data:byte(i + 1)
    local c = data:byte(i + 2)
    local n = a * 65536 + (b or 0) * 256 + (c or 0)
    local c1 = math.floor(n / 262144) % 64
    local c2 = math.floor(n / 4096) % 64
    local c3 = math.floor(n / 64) % 64
    local c4 = n % 64
    out[#out + 1] = chars:sub(c1 + 1, c1 + 1)
    out[#out + 1] = chars:sub(c2 + 1, c2 + 1)
    if b == nil then
      out[#out + 1] = "=="
    else
      out[#out + 1] = chars:sub(c3 + 1, c3 + 1)
      if c == nil then
        out[#out + 1] = "="
      else
        out[#out + 1] = chars:sub(c4 + 1, c4 + 1)
      end
    end
    i = i + 3
  end
  return table.concat(out, "")
end

VNC_B.ws_key_nonce = function(rand_u8)
  local raw = {}
  for i = 1, 16 do
    raw[#raw + 1] = string.char(rand_u8(i))
  end
  return VNC_B.base64_encode(table.concat(raw, ""))
end

VNC_X = {}

VNC_X.hex = function(data)
  local out = {}
  for i = 1, #data do
    out[#out + 1] = string.format("%02x", data:byte(i))
  end
  return table.concat(out, "")
end

VNC_X.parse_protocol_version = function(data)
  local out = { valid = false, major = 0, minor = 0, text = "unknown", raw = "" }
  if data == nil or #data < 12 then
    return out
  end
  out.raw = data:sub(1, 12)
  local major = tonumber(out.raw:sub(5, 8))
  local minor = tonumber(out.raw:sub(9, 12))
  if major == nil or minor == nil then
    return out
  end
  out.major = major
  out.minor = minor
  out.valid = true
  out.text = string.format("%d.%d", major, minor)
  out.is_repeater = (out.raw:sub(1, 3) == "RFB" and major == 0 and minor == 0)
  return out
end

VNC_X.version_key = function(major, minor)
  return string.format("%d.%d", major, minor)
end

VNC_X.parse_security_offer = function(data, rfb_major, rfb_minor)
  local out = { mode = nil, types = {}, valid = false }
  if data == nil or #data < 1 then
    return out
  end
  if rfb_major ~= nil and rfb_major <= 3 and rfb_minor ~= nil and rfb_minor <= 3 then
    if #data < 4 then
      return out
    end
    local t = data:byte(1) * 16777216 + data:byte(2) * 65536 + data:byte(3) * 256 + data:byte(4)
    out.mode = "3.3"
    out.types[1] = t
    out.valid = true
    return out
  end
  local count = data:byte(1)
  if count == 0 then
    out.mode = "failure"
    out.valid = true
    return out
  end
  if #data < 1 + count then
    return out
  end
  out.mode = (rfb_major ~= nil and rfb_minor ~= nil and rfb_minor == 7) and "3.7" or "3.8"
  for i = 1, count do
    out.types[#out.types + 1] = data:byte(1 + i)
  end
  out.valid = true
  return out
end

VNC_X.security_label = function(sec_type)
  return VNC_T.SEC_NAMES[sec_type] or ("Vendor/unknown security type " .. tostring(sec_type))
end

VNC_X.security_family = function(sec_type)
  return VNC_T.SEC_FAMILY[sec_type] or "unknown"
end

VNC_X.security_offers_none = function(types)
  for i = 1, #types do
    if types[i] == VNC_T.SEC_NONE then
      return true
    end
  end
  return false
end

VNC_X.security_offers_vnc = function(types)
  for i = 1, #types do
    if types[i] == VNC_T.SEC_VNC then
      return true
    end
  end
  return false
end

VNC_X.security_offers_tls_family = function(types)
  for i = 1, #types do
    local f = VNC_X.security_family(types[i])
    if f == "encrypted-transport" then
      return true, types[i]
    end
  end
  return false, nil
end

VNC_X.security_strongest_family = function(types)
  local rank = { unknown = 0, vendor = 1, plaintext = 4, ["legacy-des"] = 3, wrapper = 2, strong = 1, ["encrypted-transport"] = 0 }
  local worst = "unknown"
  local worst_rank = 0
  for i = 1, #types do
    local f = VNC_X.security_family(types[i])
    local r = rank[f] or 0
    if r > worst_rank then
      worst_rank = r
      worst = f
    end
  end
  return worst
end

VNC_X.types_to_strings = function(types)
  local out = {}
  for i = 1, #types do
    out[#out + 1] = tostring(types[i]) .. ":" .. VNC_X.security_label(types[i])
  end
  return out
end

VNC_X.parse_security_result = function(data)
  local out = { valid = false, code = nil, ok = false }
  if data == nil or #data < 4 then
    return out
  end
  out.code = data:byte(1) * 16777216 + data:byte(2) * 65536 + data:byte(3) * 256 + data:byte(4)
  out.valid = true
  out.ok = (out.code == 0)
  return out
end

VNC_X.parse_pixel_format = function(data)
  local out = { valid = false }
  if data == nil or #data < 16 then
    return out
  end
  out.bpp = data:byte(1)
  out.depth = data:byte(2)
  out.big_endian = data:byte(3)
  out.true_colour = data:byte(4)
  out.red_max = data:byte(5) * 256 + data:byte(6)
  out.green_max = data:byte(7) * 256 + data:byte(8)
  out.blue_max = data:byte(9) * 256 + data:byte(10)
  out.red_shift = data:byte(11)
  out.green_shift = data:byte(12)
  out.blue_shift = data:byte(13)
  out.valid = true
  out.depth_label = out.depth .. "-bit colour depth (" .. out.bpp .. "bpp wire format)"
  return out
end

VNC_X.parse_server_init = function(data)
  local out = { valid = false }
  if data == nil or #data < 24 then
    return out
  end
  out.width = data:byte(1) * 256 + data:byte(2)
  out.height = data:byte(3) * 256 + data:byte(4)
  out.pixel_format = VNC_X.parse_pixel_format(data:sub(5, 20))
  local name_len = data:byte(21) * 16777216 + data:byte(22) * 65536 + data:byte(23) * 256 + data:byte(24)
  if name_len > 4096 then
    return out
  end
  if #data < 24 + name_len then
    return out
  end
  out.name_len = name_len
  out.name = data:sub(25, 24 + name_len)
  out.valid = true
  return out
end

VNC_X.parse_server_messages = function(data)
  local out = { messages = {}, cut_text = nil, bell = false, incomplete = false }
  local off = 1
  while off <= #data do
    local mtype = data:byte(off)
    if mtype == VNC_T.MSG_SERVER_FBUPDATE then
      if #data < off + 4 then
        out.incomplete = true
        break
      end
      local nrect = data:byte(off + 3) * 256 + data:byte(off + 4)
      out.messages[#out.messages + 1] = { type = mtype, label = "framebuffer-update", rects = nrect }
      break
    elseif mtype == VNC_T.MSG_SERVER_COLOURMAP then
      if #data < off + 6 then
        out.incomplete = true
        break
      end
      out.messages[#out.messages + 1] = { type = mtype, label = "set-colour-map-entries" }
      break
    elseif mtype == VNC_T.MSG_SERVER_BELL then
      out.bell = true
      out.messages[#out.messages + 1] = { type = mtype, label = "bell" }
      off = off + 1
    elseif mtype == VNC_T.MSG_SERVER_CUTTEXT then
      if #data < off + 8 then
        out.incomplete = true
        break
      end
      local len = data:byte(off + 4) * 16777216 + data:byte(off + 5) * 65536
        + data:byte(off + 6) * 256 + data:byte(off + 7)
      if len > 8192 or #data < off + 7 + len then
        out.incomplete = true
        break
      end
      local text = data:sub(off + 8, off + 7 + len)
      out.messages[#out.messages + 1] = { type = mtype, label = "server-cut-text", text = text }
      if out.cut_text == nil then
        out.cut_text = text
      end
      off = off + 7 + len
    else
      out.messages[#out.messages + 1] = { type = mtype, label = "unknown-" .. tostring(mtype) }
      break
    end
  end
  return out
end

VNC_X.parse_http_response = function(data)
  local out = { valid = false, code = nil, status_line = "", headers = {}, header_count = 0, body = "" }
  if data == nil or #data < 12 then
    return out
  end
  local head_end = data:find("\r\n\r\n", 1, true)
  local sep_len = 4
  if head_end == nil then
    head_end = data:find("\n\n", 1, true)
    sep_len = 2
  end
  if head_end == nil then
    out.status_line = data:sub(1, 32)
    return out
  end
  local head = data:sub(1, head_end - 1)
  out.body = data:sub(head_end + sep_len)
  local lines = {}
  for line in (head .. "\n"):gmatch("(.-)\n") do
    lines[#lines + 1] = line:gsub("\r$", "")
  end
  out.status_line = lines[1] or ""
  local code = tonumber(out.status_line:match("HTTP/%d%.%d%s+(%d%d%d)"))
  out.code = code
  for i = 2, #lines do
    local k, v = lines[i]:match("^([^:]+):%s*(.*)$")
    if k then
      out.headers[k:lower()] = v
      out.header_count = out.header_count + 1
    end
  end
  out.valid = code ~= nil
  out.server = out.headers["server"]
  out.content_type = out.headers["content-type"]
  return out
end

VNC_X.secret_patterns = {
  { label = "password assignment", re = "[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]%s*[:=]%s*%S+" },
  { label = "credential pair", re = "%S+[:/]%S+@[A-Za-z0-9%.%-]+" },
  { label = "private key marker", re = "BEGIN [A-Z]+ PRIVATE KEY" },
  { label = "windows domain path", re = "%\\\\\\\\[A-Za-z0-9%.%-]+\\\\[^%s]+" },
  { label = "token-like string", re = "(?)" },
}

VNC_X.scan_secrets = function(text)
  local hits = {}
  if text == nil or #text == 0 then
    return hits
  end
  if text:find("password", 1, true) or text:find("Password", 1, true) then
    hits[#hits + 1] = "password assignment"
  end
  if text:find("@", 1, true) and text:find(":", 1, true) then
    hits[#hits + 1] = "credential pair"
  end
  if text:find("PRIVATE KEY", 1, true) then
    hits[#hits + 1] = "private key marker"
  end
  if text:find("\\\\", 1, true) then
    hits[#hits + 1] = "UNC share path"
  end
  if text:find("token", 1, true) or text:find("TOKEN", 1, true) then
    hits[#hits + 1] = "token string"
  end
  return hits
end

VNC_X.byte_hex_rate = function(data)
  local zeros = 0
  for i = 1, #data do
    if data:byte(i) == 0 then
      zeros = zeros + 1
    end
  end
  if #data == 0 then
    return 0
  end
  return zeros / #data
end

VNC_A = {}

VNC_A.des_tables = function()
  return VNC_T
end

VNC_A.bits_from_bytes = function(data)
  local bits = {}
  for i = 1, #data do
    local b = data:byte(i)
    for j = 7, 0, -1 do
      bits[#bits + 1] = math.floor(b / 2 ^ j) % 2
    end
  end
  return bits
end

VNC_A.bits_to_bytes = function(bits)
  local out = {}
  for i = 1, #bits, 8 do
    local v = 0
    for j = 0, 7 do
      v = v * 2 + (bits[i + j] or 0)
    end
    out[#out + 1] = string.char(v % 256)
  end
  return table.concat(out, "")
end

VNC_A.permute = function(bits, table, out_len)
  local out = {}
  for i = 1, out_len do
    out[i] = bits[table[i]] or 0
  end
  return out
end

VNC_A.rot_left_28 = function(bits, n)
  local out = {}
  for i = 1, 28 do
    out[i] = bits[((i - 1 + n) % 28) + 1]
  end
  return out
end

VNC_A.subkeys = function(key8)
  local pc1 = VNC_A.permute(VNC_A.bits_from_bytes(key8), VNC_T.DES_PC1, 56)
  local c = {}
  local d = {}
  for i = 1, 28 do
    c[i] = pc1[i]
    d[i] = pc1[i + 28]
  end
  local subs = {}
  for round = 1, 16 do
    local shift = VNC_T.DES_SHIFTS[round]
    c = VNC_A.rot_left_28(c, shift)
    d = VNC_A.rot_left_28(d, shift)
    local cd = {}
    for i = 1, 28 do
      cd[i] = c[i]
      cd[i + 28] = d[i]
    end
    subs[round] = VNC_A.permute(cd, VNC_T.DES_PC2, 48)
  end
  return subs
end

VNC_A.feistel = function(r32, k48)
  local expanded = VNC_A.permute(r32, VNC_T.DES_E, 48)
  for i = 1, 48 do
    expanded[i] = (expanded[i] + k48[i]) % 2
  end
  local s_out = {}
  for box = 1, 8 do
    local o = (box - 1) * 6
    local row = expanded[o + 1] * 2 + expanded[o + 6]
    local col = expanded[o + 2] * 8 + expanded[o + 3] * 4 + expanded[o + 4] * 2 + expanded[o + 5]
    local v = VNC_T.DES_SBOX[box][row * 16 + col + 1]
    s_out[#s_out + 1] = math.floor(v / 8) % 2
    s_out[#s_out + 1] = math.floor(v / 4) % 2
    s_out[#s_out + 1] = math.floor(v / 2) % 2
    s_out[#s_out + 1] = v % 2
  end
  return VNC_A.permute(s_out, VNC_T.DES_P, 32)
end

VNC_A.block_encrypt = function(subkeys, block8)
  local bits = VNC_A.bits_from_bytes(block8)
  local p = VNC_A.permute(bits, VNC_T.DES_IP, 64)
  local l = {}
  local r = {}
  for i = 1, 32 do
    l[i] = p[i]
    r[i] = p[i + 32]
  end
  for round = 1, 16 do
    local f = VNC_A.feistel(r, subkeys[round])
    local nr = {}
    for i = 1, 32 do
      nr[i] = (l[i] + f[i]) % 2
    end
    l = r
    r = nr
  end
  local pre = {}
  for i = 1, 32 do
    pre[i] = r[i]
    pre[i + 32] = l[i]
  end
  return VNC_A.bits_to_bytes(VNC_A.permute(pre, VNC_T.DES_IPINV, 64))
end

VNC_A.ecb_encrypt = function(key8, data)
  local subs = VNC_A.subkeys(key8)
  local out = {}
  local pos = 1
  while pos + 8 <= #data + 1 and pos <= #data do
    local block = data:sub(pos, pos + 7)
    if #block < 8 then
      block = block .. string.rep("\x00", 8 - #block)
    end
    out[#out + 1] = VNC_A.block_encrypt(subs, block)
    pos = pos + 8
  end
  return table.concat(out, "")
end

VNC_A.vnc_auth_key = function(password)
  local base = tostring(password or "")
  if #base > 8 then
    base = base:sub(1, 8)
  end
  base = base .. string.rep("\x00", 8 - #base)
  local out = {}
  for i = 1, 8 do
    local b = base:byte(i)
    local r = 0
    for _ = 1, 8 do
      r = r * 2 + b % 2
      b = math.floor(b / 2)
    end
    out[i] = string.char(r % 256)
  end
  return table.concat(out, "")
end

VNC_A.vnc_challenge_response = function(challenge16, password)
  if challenge16 == nil or #challenge16 < 16 then
    return nil, "challenge too short"
  end
  local key = VNC_A.vnc_auth_key(password)
  local part1 = VNC_A.block_encrypt(VNC_A.subkeys(key), challenge16:sub(1, 8))
  local part2 = VNC_A.block_encrypt(VNC_A.subkeys(key), challenge16:sub(9, 16))
  return part1 .. part2
end

VNC_A.des_selftest = function()
  for i = 1, #VNC_T.DES_SELFTEST do
    local vec = VNC_T.DES_SELFTEST[i]
    local got = VNC_A.ecb_encrypt(vec.key, vec.plain)
    if got ~= vec.cipher then
      return false, "vector " .. tostring(i) .. " mismatch: " .. VNC_X.hex(got)
    end
  end
  return true, "all FIPS-46-3 known-answer vectors passed"
end

VNC_A.vnc_key_selftest = function()
  local key = VNC_A.vnc_auth_key("pass")
  local expected_key = VNC_A.bits_to_bytes({})
  expected_key = nil
  for i = 1, 8 do
    local b = key:byte(i)
    if b == nil then
      return false, "short key"
    end
  end
  local r1 = VNC_A.vnc_challenge_response(string.rep("\xAB", 16), "vncpass")
  local r2 = VNC_A.vnc_challenge_response(string.rep("\xAB", 16), "vncpass")
  if r1 ~= r2 then
    return false, "response not deterministic"
  end
  return true, "VNCAuth key derivation and response deterministic"
end

local function vnc_session_new(host, port, args)
  return {
    host = host,
    port = port or 5900,
    args = args,
    sock = nil,
    connected = false,
    closed = false,
    rfb_version = nil,
    sec_mode = nil,
    sec_types = {},
    chosen_type = nil,
    auth_state = "not-started",
    security_result = nil,
    authenticated = false,
    vnc_challenge = nil,
    server_init = nil,
    premature_choice_rejected = false,
    repeater_banner = false,
    bridge_status = nil,
    connects = 0,
    sends = 0,
    recvs = 0,
    timeouts = 0,
    errors = 0,
    audit = {},
  }
end

local function vnc_audit(sess, kind, detail)
  sess.audit[#sess.audit + 1] = kind .. ":" .. tostring(detail)
end

local function vnc_connect(sess)
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
  vnc_audit(sess, "connect", sess.port)
  return 1
end

local function vnc_close(sess)
  if sess and sess.sock and not sess.closed then
    sess.sock:close()
  end
  if sess then
    sess.closed = true
    sess.connected = false
  end
end

local function vnc_send_raw(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  sess.sends = sess.sends + 1
  vnc_audit(sess, "send", #data)
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function vnc_recv_bytes(sess, want)
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
    local ok, chunk = sess.sock:receive(chunk_size)
    if ok then
      buf = buf .. chunk
      sess.recvs = sess.recvs + 1
    else
      local err = chunk
      if err == "TIMEOUT" or err == "EOF" then
        sess.timeouts = sess.timeouts + 1
        if #buf > 0 then
          return buf
        end
        return nil, "timeout"
      end
      sess.errors = sess.errors + 1
      return nil, "receive failed: " .. tostring(err or "unknown")
    end
  end
  return buf
end

local function vnc_recv_available(sess, want, wait_seconds)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  local deadline = os.time() + math.max(1, wait_seconds or 1)
  local buf = ""
  while #buf < want do
    if budget_exhausted(sess.args) then
      break
    end
    local remaining = deadline - os.time()
    if remaining <= 0 then
      break
    end
    sess.sock:set_timeout(math.min(remaining, 2) * 1000)
    local ok, chunk = sess.sock:receive(want - #buf)
    if ok then
      buf = buf .. chunk
      sess.recvs = sess.recvs + 1
    else
      local err = chunk
      if err ~= "TIMEOUT" and err ~= "EOF" then
        break
      end
      sess.timeouts = sess.timeouts + 1
      if #buf > 0 then
        break
      end
      return nil, err or "timeout"
    end
  end
  if #buf > 0 then
    return buf
  end
  return nil, "timeout"
end

local function vnc_handle_none_auth(sess, sec_mode)
  if sec_mode == "3.8" then
    local data, err = vnc_recv_bytes(sess, 4)
    if not data then
      sess.auth_state = "failed"
      return nil, "no SecurityResult: " .. tostring(err)
    end
    local result = VNC_X.parse_security_result(data)
    sess.security_result = result.code
    if result.ok then
      sess.auth_state = "authenticated"
      sess.authenticated = true
      return 1
    end
    sess.auth_state = "rejected"
    return nil, "None rejected with code " .. tostring(result.code)
  end
  sess.auth_state = "authenticated"
  sess.authenticated = true
  return 1
end

local function vnc_handle_vnc_auth(sess, opts, sec_mode, challenge)
  if opts.password == nil then
    sess.auth_state = "challenge"
    sess.vnc_challenge = challenge
    return 1
  end
  local resp, rerr = VNC_A.vnc_challenge_response(challenge, opts.password)
  if not resp then
    sess.auth_state = "failed"
    return nil, "response computation failed: " .. tostring(rerr)
  end
  local ok, serr = vnc_send_raw(sess, resp)
  if not ok then
    sess.auth_state = "failed"
    return nil, serr
  end
  local data, err = vnc_recv_bytes(sess, 4)
  if not data then
    sess.auth_state = "unknown"
    return nil, "no auth result: " .. tostring(err)
  end
  local result = VNC_X.parse_security_result(data)
  sess.security_result = result.code
  if result.ok then
    sess.auth_state = "authenticated"
    sess.authenticated = true
    return 1
  end
  sess.auth_state = "failed"
  return 1
end

local function vnc_read_server_init(sess)
  local head, err = vnc_recv_bytes(sess, 24)
  if not head then
    return nil, "no ServerInit: " .. tostring(err)
  end
  local name_len = head:byte(21) * 16777216 + head:byte(22) * 65536 + head:byte(23) * 256 + head:byte(24)
  if name_len > 4096 then
    return nil, "implausible ServerInit name length"
  end
  local name = ""
  if name_len > 0 then
    name = vnc_recv_bytes(sess, name_len)
    if not name then
      return nil, "truncated ServerInit name"
    end
  end
  local parsed = VNC_X.parse_server_init(head .. name)
  if not parsed.valid then
    return nil, "unparseable ServerInit"
  end
  return parsed
end

local function vnc_handshake(sess, opts)
  opts = opts or {}
  local ver_bytes, verr = vnc_recv_bytes(sess, 12)
  if not ver_bytes or #ver_bytes < 12 then
    return nil, "no RFB banner: " .. tostring(verr or (#ver_bytes or 0) .. " bytes")
  end
  local sv = VNC_X.parse_protocol_version(ver_bytes)
  if not sv.valid then
    return nil, "unparseable RFB banner"
  end
  sess.rfb_version = sv
  vnc_audit(sess, "server-version", sv.text)
  if sv.major == 0 and sv.minor == 0 then
    sess.repeater_banner = true
    sess.auth_state = "repeater"
    return 1
  end
  local cmajor = tonumber(opts.client_major) or 3
  local cminor = tonumber(opts.client_minor) or 8
  local client_ver = VNC_B.protocol_version(cmajor, cminor)
  local emajor = sv.major
  local eminor = sv.minor
  if cmajor < emajor or (cmajor == emajor and cminor < eminor) then
    emajor = cmajor
    eminor = cminor
  end
  sess.negotiated_version = VNC_X.version_key(emajor, eminor)
  local choice = tonumber(opts.choose)
  local first_send = client_ver
  if opts.premature_choice and choice then
    first_send = client_ver .. VNC_B.security_choice(choice)
  end
  local ok, serr = vnc_send_raw(sess, first_send)
  if not ok then
    return nil, serr
  end
  if opts.premature_choice and choice then
    local result_bytes = vnc_recv_bytes(sess, 4)
    if result_bytes and #result_bytes >= 4 and result_bytes:byte(1) == 0 and result_bytes:byte(2) == 0
      and result_bytes:byte(3) == 0 and result_bytes:byte(4) == 0 then
      sess.security_result = 0
      sess.auth_state = "authenticated"
      sess.authenticated = true
      sess.sec_mode = "bypass"
      if opts.complete_init ~= false then
        local iok, ierr = vnc_send_raw(sess, VNC_B.client_init(opts.share_desktop ~= false))
        if iok then
          local init, perr = vnc_read_server_init(sess)
          if init then
            sess.server_init = init
            vnc_audit(sess, "server-init", init.width .. "x" .. init.height)
          end
        end
      end
      return 1
    end
    sess.premature_choice_rejected = true
    sess.auth_state = "rejected"
    return 1
  end
  local offer
  if emajor == 3 and eminor <= 3 then
    local sec_bytes, secerr = vnc_recv_bytes(sess, 4)
    if not sec_bytes or #sec_bytes < 4 then
      return nil, "no 3.3 security type: " .. tostring(secerr)
    end
    offer = VNC_X.parse_security_offer(sec_bytes, emajor, eminor)
  else
    local count_bytes, cerr = vnc_recv_bytes(sess, 1)
    if not count_bytes or #count_bytes < 1 then
      return nil, "no security type count: " .. tostring(cerr)
    end
    local count = count_bytes:byte(1)
    if count == 0 then
      sess.sec_mode = "failure"
      return nil, "server advertised zero security types"
    end
    local type_bytes, terr = vnc_recv_bytes(sess, count)
    if not type_bytes or #type_bytes < count then
      return nil, "truncated security type list: " .. tostring(terr)
    end
    offer = VNC_X.parse_security_offer(count_bytes .. type_bytes, emajor, eminor)
  end
  if not offer.valid then
    return nil, "unparseable security offer"
  end
  sess.sec_mode = offer.mode
  sess.sec_types = offer.types
  vnc_audit(sess, "sec-types", table.concat(VNC_X.types_to_strings(offer.types), ","))
  if choice == nil then
    sess.auth_state = "enumerated"
    return 1
  end
  local found = false
  for i = 1, #offer.types do
    if offer.types[i] == choice then
      found = true
      break
    end
  end
  if not found then
    sess.chosen_type = choice
    sess.auth_state = "unsupported-type"
    return 1
  end
  sess.chosen_type = choice
  local cok, cerr = vnc_send_raw(sess, VNC_B.security_choice(choice))
  if not cok then
    return nil, cerr
  end
  if choice == VNC_T.SEC_NONE then
    local nok, nerr = vnc_handle_none_auth(sess, offer.mode)
    if not nok then
      return nil, nerr
    end
  elseif choice == VNC_T.SEC_VNC then
    local challenge
    if offer.mode == "3.3" then
      local chal_bytes, cherr = vnc_recv_bytes(sess, 16)
      if not chal_bytes or #chal_bytes < 16 then
        return nil, "no 3.3 VNC challenge: " .. tostring(cherr)
      end
      challenge = chal_bytes
    else
      local chal_bytes, cherr = vnc_recv_bytes(sess, 16)
      if not chal_bytes or #chal_bytes < 16 then
        return nil, "no VNC challenge: " .. tostring(cherr)
      end
      challenge = chal_bytes
    end
    sess.vnc_challenge = challenge
    local aok, aerr = vnc_handle_vnc_auth(sess, opts, offer.mode, challenge)
    if not aok then
      return nil, aerr
    end
  else
    sess.auth_state = "unsupported-type"
    return 1
  end
  if not sess.authenticated or opts.complete_init == false then
    return 1
  end
  local iok, ierr = vnc_send_raw(sess, VNC_B.client_init(opts.share_desktop ~= false))
  if not iok then
    return nil, ierr
  end
  local init, perr = vnc_read_server_init(sess)
  if not init then
    return nil, perr
  end
  sess.server_init = init
  vnc_audit(sess, "server-init", init.width .. "x" .. init.height)
  return 1
end

local function vnc_offer_scan(host, port, args, opts)
  local sess = vnc_session_new(host, port, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    return nil, err, sess
  end
  ok, err = vnc_handshake(sess, opts or {})
  if not ok then
    vnc_close(sess)
    return nil, err, sess
  end
  return sess, nil
end

local function vnc_auth_attempt(host, port, password, args)
  local sess = vnc_session_new(host, port, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    vnc_close(sess)
    return "connect-error", err, sess
  end
  ok, err = vnc_handshake(sess, { choose = VNC_T.SEC_VNC, password = password })
  if not ok then
    vnc_close(sess)
    if sess.timeouts > 0 and sess.sends <= 1 then
      return "dropped", err, sess
    end
    return "protocol-error", err, sess
  end
  vnc_close(sess)
  if sess.auth_state == "authenticated" then
    return "success", nil, sess
  end
  if sess.auth_state == "failed" then
    return "auth-failed", nil, sess
  end
  if sess.auth_state == "unsupported-type" then
    return "no-vnc-auth", nil, sess
  end
  return "unknown", nil, sess
end

local function vnc_none_attempt(host, port, args, opts)
  local sess = vnc_session_new(host, port, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    vnc_close(sess)
    return "connect-error", err, sess
  end
  ok, err = vnc_handshake(sess, opts or { choose = VNC_T.SEC_NONE })
  if not ok then
    vnc_close(sess)
    return "protocol-error", err, sess
  end
  return "ok", nil, sess
end

local function vnc_http_probe(host, port, args, opts)
  opts = opts or {}
  local sess = vnc_session_new(host, port, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    vnc_close(sess)
    return nil, err, sess
  end
  local req = VNC_B.http_request(opts.host_header or host.targetname or host.name or host.ip, opts.path or "/", opts)
  ok, err = vnc_send_raw(sess, req)
  if not ok then
    vnc_close(sess)
    return nil, err, sess
  end
  local data = vnc_recv_available(sess, 65536, opts.wait or 1)
  vnc_close(sess)
  if not data then
    return nil, "no HTTP response", sess
  end
  return VNC_X.parse_http_response(data), nil, sess
end

local function vnc_websocket_probe(host, port, args, opts)
  opts = opts or {}
  opts.upgrade_websocket = true
  opts.ws_key = opts.ws_key or VNC_B.base64_encode("audit-nonce-0001")
  local parsed, err, sess = vnc_http_probe(host, port, args, opts)
  if not parsed then
    return nil, err, sess
  end
  parsed.upgrade_ok = (parsed.code == 101)
    and ((parsed.headers["upgrade"] or ""):lower() == "websocket")
  parsed.accept_present = (parsed.headers["sec-websocket-accept"] ~= nil)
  return parsed, nil, sess
end

local function vnc_repeater_probe(host, port, args, opts)
  opts = opts or {}
  local sess = vnc_session_new(host, port, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    vnc_close(sess)
    return nil, err, sess
  end
  local banner = vnc_recv_available(sess, 64, opts.wait or 1)
  if not banner then
    vnc_close(sess)
    sess.bridge_status = "silent"
    return sess, nil
  end
  local parsed = VNC_X.parse_protocol_version(banner)
  sess.rfb_version = parsed
  if not parsed.valid then
    vnc_close(sess)
    sess.bridge_status = "not-rfb"
    return sess, nil
  end
  if parsed.major ~= 0 or parsed.minor ~= 0 then
    vnc_close(sess)
    sess.bridge_status = "vnc-server"
    return sess, nil
  end
  sess.repeater_banner = true
  local idok, iderr = vnc_send_raw(sess, VNC_B.repeater_id_string(opts.id or VNC_T.REPEATER_PROBE_ID))
  if not idok then
    vnc_close(sess)
    sess.bridge_status = "send-failed"
    return sess, nil
  end
  local reply = vnc_recv_available(sess, 64, opts.wait or 1)
  vnc_close(sess)
  if not reply then
    sess.bridge_status = "no-target"
    return sess, nil
  end
  local target = VNC_X.parse_protocol_version(reply)
  if target.valid and not (target.major == 0 and target.minor == 0) then
    sess.bridge_status = "bridge-accepted"
  else
    sess.bridge_status = "repeater-ack"
  end
  return sess, nil
end

local function vnc_clipboard_probe(sess, opts)
  opts = opts or {}
  if not sess.authenticated or sess.server_init == nil then
    return nil, "session not established"
  end
  local enc_ok, enc_err = vnc_send_raw(sess, VNC_B.set_encodings({ 0 }))
  if not enc_ok then
    return nil, enc_err
  end
  local req_ok, req_err = vnc_send_raw(sess, VNC_B.fb_update_request(true, 0, 0,
    sess.server_init.width, sess.server_init.height))
  if not req_ok then
    return nil, req_err
  end
  local data = vnc_recv_available(sess, 8192, opts.wait or 1)
  if not data then
    return nil, "no server messages"
  end
  local parsed = VNC_X.parse_server_messages(data)
  return parsed.cut_text, nil, parsed
end

local function vnc_drain_messages(sess, wait_seconds)
  local data = vnc_recv_available(sess, 1, wait_seconds or 1)
  if not data then
    return nil
  end
  return VNC_X.parse_server_messages(data)
end

local function vnc_stage_summary(sess)
  return {
    banner = sess.rfb_version and sess.rfb_version.text or "unknown",
    sec_mode = sess.sec_mode or "unknown",
    sec_types = table.concat(VNC_X.types_to_strings(sess.sec_types), ", "),
    chosen = sess.chosen_type and VNC_X.security_label(sess.chosen_type) or "none",
    auth_state = sess.auth_state,
    result = sess.security_result,
    geometry = sess.server_init and (sess.server_init.width .. "x" .. sess.server_init.height) or "not disclosed",
    server_name = sess.server_init and sess.server_init.name or "",
  }
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

local function vnc_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - VNC audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The VNC audit did not complete against this target", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function vnc_open_session(host, port, args)
  local sess = vnc_session_new(host, port.number, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    return nil, err
  end
  return sess
end

local function vnc_scan_offer(host, port, args)
  local sess = vnc_session_new(host, port.number, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    return nil, "TCP connect failed: " .. tostring(err)
  end
  ok, err = vnc_handshake(sess, { complete_init = false })
  if not ok then
    vnc_close(sess)
    return nil, err
  end
  return sess
end

local function vnc_probe_none(host, port, args)
  local sess = vnc_session_new(host, port.number, args)
  local ok, err = vnc_connect(sess)
  if not ok then
    return nil, "TCP connect failed: " .. tostring(err)
  end
  ok, err = vnc_handshake(sess, { choose = VNC_T.SEC_NONE, share_desktop = true })
  if not ok then
    vnc_close(sess)
    return nil, err
  end
  return sess
end

local RFB_GENERATIONS = {
  ["3.3"] = "RFB 3.3 (1998-era, server-chosen security, no TLS path)",
  ["3.7"] = "RFB 3.7 (2003-era, no mandatory SecurityResult)",
  ["3.8"] = "RFB 3.8 (modern base protocol, SecurityResult mandatory)",
  ["4.0"] = "RFB 4.0 vendor extension banner",
  ["4.1"] = "RFB 4.1 (RealVNC 4.x enterprise banner family)",
  ["4.2"] = "RFB 4.2 vendor extension banner",
  ["5.0"] = "RFB 5.0 (current draft extension family)",
}

local function rfb_generation_name(version_text)
  if version_text == nil then
    return "unknown"
  end
  return RFB_GENERATIONS[version_text] or ("vendor banner " .. version_text)
end

local function run_audit(host, port, args)
  local sections = {}
  local sess, err = vnc_scan_offer(host, port, args)
  if sess == nil then
    return vnc_incomplete(err, sections, "handshake", err)
  end
  vnc_close(sess)
  local banner = sess.rfb_version
  local negotiated = sess.negotiated_version or banner.text
  local fingerprint = {
    banner = string.format("RFB %03d.%03d", banner.major, banner.minor),
    negotiated = negotiated,
    generation = rfb_generation_name(banner.text),
    repeater_banner = tostring(banner.is_repeater),
    security_offer_mode = sess.sec_mode or "unknown",
  }
  if sess.repeater_banner then
    fingerprint.note = "target answered with the repeater null banner"
  end
  sections[#sections + 1] = { key = "Fingerprint", value = fingerprint }

  local type_lines = {}
  for i = 1, #sess.sec_types do
    type_lines[#type_lines + 1] = string.format("%d. %s", sess.sec_types[i], VNC_X.security_label(sess.sec_types[i]))
  end
  if #type_lines == 0 then
    type_lines[#type_lines + 1] = "none readable (offer missing or refused)"
  end
  sections[#sections + 1] = { key = "Advertised Security Types", value = type_lines }

  local legacy_notes = {}
  local legacy_hit = false
  local LEGACY_BANNERS = { ["3.3"] = true, ["3.7"] = true }
  for key, note in pairs(VNC_T.LEGACY_VERSIONS) do
    legacy_notes[#legacy_notes + 1] = key .. ": " .. note
  end
  table.sort(legacy_notes)
  if LEGACY_BANNERS[banner.text] then
    legacy_hit = true
  end
  sections[#sections + 1] = { key = "Legacy Banner Reference", value = legacy_notes }

  local remediation = {}
  local status_text
  if legacy_hit then
    status_text = "VULNERABLE - legacy " .. banner.text .. " banner negotiated (" .. fingerprint.generation .. ")"
    add_finding("HIGH", "Server announces a legacy RFB banner with known exposure history", {
      subject = "rfb-banner",
      evidence = fingerprint.banner .. " (" .. fingerprint.generation .. ")",
      confidence = "high",
      cvss = 7.5,
    })
    remediation["1. Upgrade"] = "Move the deployment to a build negotiating RFB 3.8 with TLS-capable security types."
  else
    status_text = "INFORMATIONAL - RFB " .. banner.text .. " banner negotiated (" .. fingerprint.generation .. ")"
    add_finding("INFO", "RFB banner recorded for inventory", {
      subject = "rfb-banner",
      evidence = fingerprint.banner .. " advertised " .. tostring(#sess.sec_types) .. " security type(s)",
      confidence = "high",
    })
    remediation["1. Baseline"] = "Keep the banner inventory current; re-audit after VNC server upgrades."
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
