local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Fingerprints the PBX engine behind the SIP service from Server and
User-Agent headers (Asterisk, FreePBX, Cisco CUCM, 3CX, Kamailio,
OpenSIPS and others) and records the capability profile.

Why it matters
- The engine identity drives every other SIP audit: version-specific
  advisories, default dial-plan behaviour and vendor hardening guides.
- The Allow/Supported profile shows which extensions and methods the
  platform runs.

What the script does
1. Sends one OPTIONS request and captures the response headers.
2. Classifies the engine and version from Server/User-Agent.
3. Records Allow, Supported and Accept capabilities.

Safe operation: a single read-only OPTIONS exchange; no registration
state is touched.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  5060,
  "sip",
  {"udp", "tcp"}
)

local SCRIPT_NAME = "sip-server-fingerprint"

local RISK_LEVEL = "🟢 LOW"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 48,
  retries = 1,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}

local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "retries", minimum = 0, maximum = 3, integer = true },
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

SIP_T = {
  VERSION = "SIP/2.0",
  METHODS = { "REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "INFO", "UPDATE", "PRACK", "REFER", "NOTIFY", "SUBSCRIBE", "PUBLISH", "MESSAGE" },
  REASONS = {
    [100] = "Trying", [180] = "Ringing", [183] = "Session Progress", [200] = "OK",
    [202] = "Accepted", [301] = "Moved Permanently", [302] = "Moved Temporarily",
    [400] = "Bad Request", [401] = "Unauthorized", [403] = "Forbidden", [404] = "Not Found",
    [405] = "Method Not Allowed", [407] = "Proxy Authentication Required", [408] = "Request Timeout",
    [413] = "Request Entity Too Large", [420] = "Bad Extension", [423] = "Interval Too Brief",
    [480] = "Temporarily Unavailable", [481] = "Call/Transaction Does Not Exist", [486] = "Busy Here",
    [487] = "Request Terminated", [488] = "Not Acceptable Here", [491] = "Request Pending",
    [500] = "Server Internal Error", [501] = "Not Implemented", [502] = "Bad Gateway",
    [503] = "Service Unavailable", [504] = "Server Time-out", [600] = "Busy Everywhere",
    [603] = "Decline", [604] = "Does Not Exist Anywhere", [606] = "Not Acceptable",
  },
  EVENT_PACKAGES = { "presence", "dialog", "message-summary", "reg", "refer", "conference", "kpml" },
  STATIC_PAYLOADS = {
    [0] = "PCMU", [1] = "1016", [2] = "G721", [3] = "GSM", [4] = "G723", [5] = "GSM-HR",
    [6] = "DVI4", [7] = "LPC", [8] = "PCMA", [9] = "G722", [10] = "L16", [11] = "L16",
    [12] = "QCELP", [13] = "CN", [14] = "MPA", [15] = "G728", [16] = "DVI4", [17] = "DVI4",
    [18] = "G729", [25] = "CELB", [26] = "JPEG", [28] = "NV", [31] = "H261", [32] = "MPV",
    [33] = "MP2T", [34] = "H263",
  },
  ENGINES = {
    { engine = "Asterisk", patterns = { "Asterisk" } },
    { engine = "FreePBX", patterns = { "FreePBX", "FPBX" } },
    { engine = "Cisco CUCM", patterns = { "CUCM", "Cisco%-SIPGateway", "Cisco%-CP", "CCM" } },
    { engine = "3CX", patterns = { "3CX" } },
    { engine = "Kamailio", patterns = { "kamailio", "Kamailio", "sr " } },
    { engine = "OpenSIPS", patterns = { "OpenSIPS", "opensips" } },
    { engine = "Twilio", patterns = { "Twilio" } },
    { engine = "Avaya", patterns = { "Avaya", "S8300", "Communication Manager" } },
    { engine = "Grandstream", patterns = { "Grandstream", "GrandStream", "UGW" } },
    { engine = "Yeastar", patterns = { "Yeastar", "MyPBX" } },
  },
  AUDIT_UA = "nse-sip-audit/1.0",
}

local SIP_PRNG_STATE = nil

local function sip_prng()
  if SIP_PRNG_STATE == nil then
    SIP_PRNG_STATE = (os.time() * 1103515245 + 12345) % 2147483648
    if SIP_PRNG_STATE == 0 then
      SIP_PRNG_STATE = 2147483647
    end
  end
  local x = SIP_PRNG_STATE
  x = (x * 1103515245 + 12345) % 2147483648
  SIP_PRNG_STATE = x
  return x
end

local MD5_S = {
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

local MD5_K = {}
for i = 0, 63 do
  MD5_K[i] = math.floor(math.abs(math.sin(i + 1)) * 4294967296) % 4294967296
end

local function md5_rotl(x, s)
  x = x % 4294967296
  return ((x << s) | (x >> (32 - s))) % 4294967296
end

local function md5_add(a, b)
  return (a + b) % 4294967296
end

local function md5_word(s, off)
  local b1, b2, b3, b4 = string.byte(s, off, off + 3)
  return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

local function md5_hexword(w)
  return string.format("%02x%02x%02x%02x", w % 256, math.floor(w / 256) % 256,
    math.floor(w / 65536) % 256, math.floor(w / 16777216) % 256)
end

local function md5(msg)
  local h0, h1, h2, h3 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  local padded = msg .. "\128"
  while #padded % 64 ~= 56 do
    padded = padded .. "\0"
  end
  local bits = #msg * 8
  padded = padded .. string.char(bits % 256, math.floor(bits / 256) % 256,
    math.floor(bits / 65536) % 256, math.floor(bits / 16777216) % 256, 0, 0, 0, 0)
  for off = 1, #padded, 64 do
    local m = {}
    for i = 0, 15 do
      m[i] = md5_word(padded, off + i * 4)
    end
    local a, b, c, d = h0, h1, h2, h3
    for i = 0, 63 do
      local f, g
      if i < 16 then
        f = (b & c) | (~b & d)
        g = i
      elseif i < 32 then
        f = (d & b) | (~d & c)
        g = (5 * i + 1) % 16
      elseif i < 48 then
        f = b ~ c ~ d
        g = (3 * i + 5) % 16
      else
        f = c ~ (b | (d ~ 0xFFFFFFFF))
        g = (7 * i) % 16
      end
      f = md5_add(md5_add(f, a), md5_add(MD5_K[i], m[g]))
      a, d, c = d, c, b
      b = md5_add(b, md5_rotl(f, MD5_S[i + 1]))
    end
    h0 = md5_add(h0, a)
    h1 = md5_add(h1, b)
    h2 = md5_add(h2, c)
    h3 = md5_add(h3, d)
  end
  return md5_hexword(h0) .. md5_hexword(h1) .. md5_hexword(h2) .. md5_hexword(h3)
end

SIP_B = {}

function SIP_B.hex(len)
  local out = {}
  for _ = 1, len do
    out[#out + 1] = string.format("%02x", sip_prng() % 256)
  end
  return table.concat(out)
end

function SIP_B.branch()
  return "z9hG4bK" .. SIP_B.hex(8)
end

function SIP_B.tag()
  return SIP_B.hex(6)
end

function SIP_B.call_id(host)
  return SIP_B.hex(10) .. "@" .. (host or "nse-audit.invalid")
end

function SIP_B.cseq_start()
  return 100 + (sip_prng() % 900)
end

function SIP_B.request(method, uri, headers, body)
  local lines = { method .. " " .. uri .. " SIP/2.0" }
  for _, h in ipairs(headers) do
    lines[#lines + 1] = h.name .. ": " .. h.value
  end
  if body and #body > 0 then
    lines[#lines + 1] = "Content-Length: " .. tostring(#body)
    lines[#lines + 1] = ""
    lines[#lines + 1] = body
  else
    lines[#lines + 1] = "Content-Length: 0"
    lines[#lines + 1] = ""
    lines[#lines + 1] = ""
  end
  return table.concat(lines, "\r\n")
end

function SIP_B.base_headers(host, from_user, to_user, callid, cseq, method, branch, tag, contact_port)
  local contact_user = from_user or "nse-audit"
  return {
    { name = "Via", value = "SIP/2.0/UDP 192.0.2.10:" .. tostring(contact_port or 5060) .. ";branch=" .. branch .. ";rport" },
    { name = "From", value = "<sip:" .. contact_user .. "@nse-audit.invalid>;tag=" .. tag },
    { name = "To", value = "<sip:" .. (to_user or contact_user) .. "@" .. host .. ">" },
    { name = "Call-ID", value = callid },
    { name = "CSeq", value = tostring(cseq) .. " " .. method },
    { name = "Contact", value = "<sip:" .. contact_user .. "@192.0.2.10:" .. tostring(contact_port or 5060) .. ">" },
    { name = "Max-Forwards", value = "70" },
    { name = "User-Agent", value = SIP_T.AUDIT_UA },
  }
end

function SIP_B.build_options(host, args, extras)
  local branch = SIP_B.branch()
  local callid = SIP_B.call_id(host)
  local headers = SIP_B.base_headers(host, "nse-audit", nil, callid, 1, "OPTIONS", branch, SIP_B.tag(), 5060)
  headers[#headers + 1] = { name = "Accept", value = "application/sdp" }
  if extras then
    for _, h in ipairs(extras) do
      headers[#headers + 1] = h
    end
  end
  return SIP_B.request("OPTIONS", "sip:" .. host, headers, nil), { callid = callid, branch = branch, cseq = 1, method = "OPTIONS" }
end

function SIP_B.build_register(host, user, args, opts)
  opts = opts or {}
  local expires = tostring(opts.expires or 300)
  local branch = SIP_B.branch()
  local callid = SIP_B.call_id(host)
  local headers = SIP_B.base_headers(host, user, user, callid, opts.cseq or 1, "REGISTER", branch, SIP_B.tag(), 5060)
  headers[#headers + 1] = { name = "Expires", value = expires }
  if opts.authorization then
    headers[#headers + 1] = { name = "Authorization", value = opts.authorization }
  end
  return SIP_B.request("REGISTER", "sip:" .. host, headers, nil),
    { callid = callid, branch = branch, cseq = opts.cseq or 1, method = "REGISTER" }
end

function SIP_B.build_invite(host, from_user, to_user, args, opts)
  opts = opts or {}
  local branch = SIP_B.branch()
  local callid = SIP_B.call_id(host)
  local headers = SIP_B.base_headers(host, from_user, to_user, callid, opts.cseq or 1, "INVITE", branch, SIP_B.tag(), 5060)
  headers[#headers + 1] = { name = "Allow", value = "INVITE, ACK, CANCEL, BYE" }
  headers[#headers + 1] = { name = "Supported", value = "replaces, timer" }
  if opts.authorization then
    headers[#headers + 1] = { name = "Authorization", value = opts.authorization }
  end
  if opts.extra_headers then
    for _, h in ipairs(opts.extra_headers) do
      headers[#headers + 1] = h
    end
  end
  local body = nil
  if opts.sdp then
    headers[#headers + 1] = { name = "Content-Type", value = "application/sdp" }
    body = opts.sdp
  end
  return SIP_B.request("INVITE", "sip:" .. to_user .. "@" .. host, headers, body),
    { callid = callid, branch = branch, cseq = opts.cseq or 1, method = "INVITE", to_tag_target = "<sip:" .. to_user .. "@" .. host .. ">" }
end

function SIP_B.build_message(host, from_user, to_user, text, args, opts)
  opts = opts or {}
  local branch = SIP_B.branch()
  local callid = SIP_B.call_id(host)
  local headers = SIP_B.base_headers(host, from_user, to_user, callid, opts.cseq or 1, "MESSAGE", branch, SIP_B.tag(), 5060)
  if opts.authorization then
    headers[#headers + 1] = { name = "Authorization", value = opts.authorization }
  end
  return SIP_B.request("MESSAGE", "sip:" .. to_user .. "@" .. host, headers, text),
    { callid = callid, branch = branch, cseq = opts.cseq or 1, method = "MESSAGE" }
end

function SIP_B.build_subscribe(host, user, event, args, opts)
  opts = opts or {}
  local branch = SIP_B.branch()
  local callid = SIP_B.call_id(host)
  local headers = SIP_B.base_headers(host, user, user, callid, opts.cseq or 1, "SUBSCRIBE", branch, SIP_B.tag(), 5060)
  headers[#headers + 1] = { name = "Event", value = event or "presence" }
  headers[#headers + 1] = { name = "Expires", value = tostring(opts.expires or 300) }
  headers[#headers + 1] = { name = "Accept", value = "application/pidf+xml, application/dialog-info+xml" }
  if opts.authorization then
    headers[#headers + 1] = { name = "Authorization", value = opts.authorization }
  end
  return SIP_B.request("SUBSCRIBE", "sip:" .. user .. "@" .. host, headers, nil),
    { callid = callid, branch = branch, cseq = opts.cseq or 1, method = "SUBSCRIBE" }
end

function SIP_B.build_bye(host, callid, from_user, to_user, from_tag, to_tag, cseq, args)
  local branch = SIP_B.branch()
  local headers = SIP_B.base_headers(host, from_user, to_user, callid, cseq or 2, "BYE", branch, from_tag or SIP_B.tag(), 5060)
  local to_value = "<sip:" .. to_user .. "@" .. host .. ">"
  if to_tag then
    to_value = to_value .. ";tag=" .. to_tag
  end
  headers[3] = { name = "To", value = to_value }
  return SIP_B.request("BYE", "sip:" .. to_user .. "@" .. host, headers, nil),
    { callid = callid, branch = branch, cseq = cseq or 2, method = "BYE" }
end

function SIP_B.build_cancel(host, invite_meta, from_user, to_user, to_tag, args)
  local branch = SIP_B.branch()
  local headers = SIP_B.base_headers(host, from_user, to_user, invite_meta.callid, invite_meta.cseq, "CANCEL", branch, SIP_B.tag(), 5060)
  return SIP_B.request("CANCEL", "sip:" .. to_user .. "@" .. host, headers, nil),
    { callid = invite_meta.callid, branch = branch, cseq = invite_meta.cseq, method = "CANCEL" }
end

function SIP_B.build_ack(host, invite_meta, from_user, to_user, args)
  local branch = SIP_B.branch()
  local headers = SIP_B.base_headers(host, from_user, to_user, invite_meta.callid, invite_meta.cseq, "ACK", branch, SIP_B.tag(), 5060)
  return SIP_B.request("ACK", "sip:" .. to_user .. "@" .. host, headers, nil),
    { callid = invite_meta.callid, branch = branch, cseq = invite_meta.cseq, method = "ACK" }
end

function SIP_B.build_sdp(owner_ip, media_port, codecs)
  local lines = {
    "v=0",
    "o=nse-audit " .. tostring(sip_prng() % 1000000) .. " " .. tostring(sip_prng() % 1000000) .. " IN IP4 " .. owner_ip,
    "s=nse-sip-audit",
    "c=IN IP4 " .. owner_ip,
    "t=0 0",
    "m=audio " .. tostring(media_port or 40000) .. " RTP/AVP " .. table.concat(codecs, " "),
  }
  for _, pt in ipairs(codecs) do
    local name = SIP_T.STATIC_PAYLOADS[tonumber(pt)]
    if name then
      lines[#lines + 1] = "a=rtpmap:" .. pt .. " " .. name .. "/8000"
    end
  end
  lines[#lines + 1] = "a=sendrecv"
  return table.concat(lines, "\r\n")
end

function SIP_B.digest_response(p)
  local algorithm = string.upper(p.algorithm or "MD5")
  if algorithm == "MD5-SESS" then
    local ha1_sess = md5(md5(p.username .. ":" .. p.realm .. ":" .. p.password) .. ":" .. (p.nonce or "") .. ":" .. (p.cnonce or ""))
    local ha2 = md5(p.method .. ":" .. p.uri)
    if p.qop == "auth" then
      return md5(ha1_sess .. ":" .. (p.nonce or "") .. ":" .. (p.nc or "00000001") .. ":" .. (p.cnonce or "") .. ":auth:" .. ha2)
    end
    return md5(ha1_sess .. ":" .. (p.nonce or "") .. ":" .. ha2)
  end
  local ha1 = md5(p.username .. ":" .. p.realm .. ":" .. p.password)
  local ha2 = md5(p.method .. ":" .. p.uri)
  if p.qop == "auth" or p.qop == "auth-int" then
    return md5(ha1 .. ":" .. (p.nonce or "") .. ":" .. (p.nc or "00000001") .. ":" .. (p.cnonce or "") .. ":" .. (p.qop or "auth") .. ":" .. ha2)
  end
  return md5(ha1 .. ":" .. (p.nonce or "") .. ":" .. ha2)
end

function SIP_B.authorization_header(challenge, creds, method, uri, opts)
  opts = opts or {}
  local cnonce = SIP_B.hex(8)
  local nc = string.format("%08d", opts.nc or 1)
  local qop = challenge.qop == "auth-int" and "auth-int" or (challenge.qop == "auth" and "auth" or nil)
  local response = SIP_B.digest_response({
    username = creds.username, realm = challenge.realm or "", password = creds.password or "",
    method = method, uri = uri, nonce = challenge.nonce or "", cnonce = cnonce, nc = nc,
    qop = qop, algorithm = challenge.algorithm or "MD5",
  })
  local parts = {
    'Digest username="' .. creds.username .. '"',
    'realm="' .. (challenge.realm or "") .. '"',
    'nonce="' .. (challenge.nonce or "") .. '"',
    'uri="' .. uri .. '"',
    'response="' .. response .. '"',
    'algorithm=' .. (challenge.algorithm or "MD5"),
  }
  if challenge.opaque then
    parts[#parts + 1] = 'opaque="' .. challenge.opaque .. '"'
  end
  if qop then
    parts[#parts + 1] = "qop=" .. qop
    parts[#parts + 1] = "nc=" .. nc
    parts[#parts + 1] = 'cnonce="' .. cnonce .. '"'
  end
  return table.concat(parts, ", ")
end

SIP_X = {}

local function sip_split_lines(text)
  local lines = {}
  local pos = 1
  while pos <= #text do
    local nl = string.find(text, "\r\n", pos, true)
    local nlen = 2
    if nl == nil then
      nl = string.find(text, "\n", pos, true)
      nlen = 1
    end
    if nl == nil then
      lines[#lines + 1] = string.sub(text, pos)
      break
    end
    lines[#lines + 1] = string.sub(text, pos, nl - 1)
    pos = nl + nlen
  end
  return lines
end

function SIP_X.parse_message(text)
  local msg = { headers = {}, hmap = {}, header_count = 0 }
  local lines = sip_split_lines(text)
  msg.first_line = lines[1] or ""
  local status = string.match(msg.first_line, "^SIP/2%.0%s+(%d%d%d)%s*(.*)$")
  if status then
    msg.kind = "response"
    msg.status = tonumber(status)
    msg.reason = string.match(msg.first_line, "%d%d%d%s*(.*)$") or ""
  else
    local method, uri = string.match(msg.first_line, "^([%a]+)%s+(%S+)%s+SIP/2%.0$")
    if method then
      msg.kind = "request"
      msg.method = method
      msg.uri = uri
    else
      msg.kind = "unknown"
    end
  end
  local in_body = false
  local body_lines = {}
  for i = 2, #lines do
    local line = lines[i]
    if in_body then
      body_lines[#body_lines + 1] = line
    elseif line == "" then
      in_body = true
    else
      local name, value = string.match(line, "^([^:]+):%s*(.*)$")
      if name then
        local entry = { name = name, value = value }
        msg.headers[#msg.headers + 1] = entry
        local key = string.lower(name)
        if msg.hmap[key] == nil then
          msg.hmap[key] = entry.value
        end
        if msg.hmap["#" .. key] == nil then
          msg.hmap["#" .. key] = {}
        end
        table.insert(msg.hmap["#" .. key], entry.value)
        msg.header_count = msg.header_count + 1
      end
    end
  end
  msg.body = table.concat(body_lines, "\r\n")
  local cl = tonumber(msg.hmap["content-length"] or "0") or 0
  if cl > 0 and #msg.body > cl then
    msg.body = string.sub(msg.body, 1, cl)
  end
  msg.cseq_method = string.match(msg.hmap["cseq"] or "", "%d+%s+([%a]+)")
  msg.cseq_number = tonumber(string.match(msg.hmap["cseq"] or "", "(%d+)"))
  return msg
end

function SIP_X.reason_for(status)
  return SIP_T.REASONS[status] or "Unknown"
end

function SIP_X.header(msg, name)
  return msg.hmap[string.lower(name)]
end

function SIP_X.header_list(msg, name)
  return msg.hmap["#" .. string.lower(name)] or {}
end

function SIP_X.parse_via(value)
  local proto, hostport, params = string.match(value, "^SIP/2%.0/(%u+)%s+([^;]+)(.*)$")
  if proto == nil then
    return nil
  end
  local host, port = string.match(hostport, "^([^:]+):?(%d*)$")
  local out = { proto = proto, host = host, port = port ~= "" and tonumber(port) or 5060, params = {} }
  for k, v in string.gmatch(params or "", ";([^=;]+)=?([^;]*)") do
    out.params[k] = v
  end
  out.branch = out.params.branch
  out.received = out.params.received
  out.rport = tonumber(out.params.rport) or nil
  return out
end

function SIP_X.parse_uri(value)
  local user, rest = string.match(value, "^sips?:([^@]*)@(.*)$")
  if rest == nil then
    rest = string.match(value, "^sips?:(.*)$") or value
    user = nil
  end
  local hostport, params = string.match(rest, "^([^;]*)(.*)$")
  local host, port = string.match(hostport, "^(%d+%.%d+%.%d+%.%d+):(%d+)$")
  if host == nil then
    local host2, port2 = string.match(hostport, "^([%w%-%._]+):(%d+)$")
    if host2 then
      host, port = host2, port2
    else
      host, port = hostport, ""
    end
  end
  local out = { user = user, host = host or hostport, port = (port and port ~= "") and tonumber(port) or 5060, params = {} }
  for k, v in string.gmatch(params or "", ";([^=;]+)=?([^;]*)") do
    out.params[k] = v
  end
  out.transport = out.params.transport or "udp"
  return out
end

function SIP_X.parse_contact(value)
  local contacts = {}
  for entry in string.gmatch(value, "<([^>]*)>") do
    contacts[#contacts + 1] = SIP_X.parse_uri(entry)
  end
  if #contacts == 0 then
    contacts[#contacts + 1] = SIP_X.parse_uri(value)
  end
  return contacts
end

function SIP_X.parse_auth_challenge(value)
  local scheme = string.match(value, "^(%a+)")
  local out = { scheme = scheme or "Digest", params = {} }
  for k, v in string.gmatch(value, '([%w%-]+)%s*=%s*"?([^",]+)"?') do
    out.params[string.lower(k)] = v
  end
  out.realm = out.params.realm
  out.nonce = out.params.nonce
  out.opaque = out.params.opaque
  out.algorithm = out.params.algorithm
  out.qop = out.params.qop
  out.stale = out.params.stale ~= nil and string.lower(out.params.stale) == "true"
  return out
end

function SIP_X.parse_allow(msg)
  local methods = {}
  for _, value in ipairs(SIP_X.header_list(msg, "Allow")) do
    for m in string.gmatch(value, "[%a]+") do
      methods[#methods + 1] = m
    end
  end
  return methods
end

function SIP_X.parse_supported(msg)
  local exts = {}
  for _, value in ipairs(SIP_X.header_list(msg, "Supported")) do
    for e in string.gmatch(value, "[^,%s]+") do
      exts[#exts + 1] = e
    end
  end
  return exts
end

function SIP_X.parse_sdp(body)
  local sdp = { media = {}, rtpmaps = {}, attrs = {}, lines = 0 }
  if body == nil or body == "" then
    return nil
  end
  local current = nil
  for line in string.gmatch(body .. "\r\n", "([^\r\n]+)\r\n") do
    sdp.lines = sdp.lines + 1
    local kind, value = string.match(line, "^([%a])=(.*)$")
    if kind == "v" then
      sdp.version = value
    elseif kind == "o" then
      local user, sid, ver, net, addr = string.match(value, "^(%S*)%s+(%d*)%s+(%d*)%s+(%S*)%s+(%S*)")
      sdp.owner = { user = user, session_id = sid, version = ver, address = addr }
    elseif kind == "s" then
      sdp.subject = value
    elseif kind == "c" then
      local addr = string.match(value, "IN IP4 (%S*)")
      sdp.connection = addr
    elseif kind == "m" then
      local media, port, proto, fmts = string.match(value, "^(%a+)%s+(%d+)%s+(%S+)%s+(.*)$")
      current = { media = media, port = tonumber(port), proto = proto, formats = {}, attrs = {} }
      sdp.media[#sdp.media + 1] = current
      for f in string.gmatch(fmts or "", "%d+") do
        current.formats[#current.formats + 1] = tonumber(f)
      end
    elseif kind == "a" then
      local name, parm = string.match(value, "^([%w%-]+):?(.*)$")
      sdp.attrs[#sdp.attrs + 1] = { name = name, value = parm }
      if current then
        current.attrs[#current.attrs + 1] = { name = name, value = parm }
      end
      local pt, map = string.match(value, "^rtpmap:(%d+)%s+(.+)$")
      if pt then
        sdp.rtpmaps[tonumber(pt)] = map
      end
    end
  end
  return sdp
end

function SIP_X.sdp_codecs(sdp)
  local codecs = {}
  if sdp == nil then
    return codecs
  end
  for _, media in ipairs(sdp.media) do
    for _, pt in ipairs(media.formats) do
      local name = sdp.rtpmaps[pt] or SIP_T.STATIC_PAYLOADS[pt] or ("dynamic-" .. tostring(pt))
      codecs[#codecs + 1] = { payload = pt, name = name, media = media.media, proto = media.proto }
    end
  end
  return codecs
end

function SIP_X.sdp_security(sdp)
  if sdp == nil then
    return "no-sdp"
  end
  for _, media in ipairs(sdp.media) do
    if string.find(media.proto, "SAVP", 1, true) then
      return "srtp"
    end
  end
  for _, attr in ipairs(sdp.attrs) do
    if attr.name == "crypto" then
      return "srtp"
    end
  end
  return "plain-rtp"
end

function SIP_X.classify_server(value)
  local out = { engine = "Unknown", version = nil, raw = value }
  if value == nil or value == "" then
    return out
  end
  for _, sig in ipairs(SIP_T.ENGINES) do
    for _, pat in ipairs(sig.patterns) do
      local s, e = string.find(value, pat)
      if s then
        out.engine = sig.engine
        local after = string.sub(value, e + 1)
        local ver = string.match(after, "%s*[vV]?([0-9]+%.[0-9]+[0-9a-zA-Z%.%-%_]*)") or string.match(value, "([0-9]+%.[0-9]+[0-9a-zA-Z%.%-%_]*)")
        out.version = ver
        return out
      end
    end
  end
  local ver = string.match(value, "([0-9]+%.[0-9]+[0-9a-zA-Z%.%-%_]*)")
  out.version = ver
  return out
end

function SIP_X.is_internal_ip(ip)
  if ip == nil then
    return false
  end
  local a, b = string.match(ip, "^(%d+)%.(%d+)%.")
  if a == nil then
    return string.find(ip, ":", 1, true) ~= nil and string.find(ip, "fd", 1, true) ~= nil
  end
  a, b = tonumber(a), tonumber(b)
  if a == 10 or a == 127 then
    return true
  end
  if a == 172 and b >= 16 and b <= 31 then
    return true
  end
  if a == 192 and b == 168 then
    return true
  end
  if a == 169 and b == 254 then
    return true
  end
  return false
end

function SIP_X.address_disclosures(msg)
  local leaks = {}
  for _, via_value in ipairs(SIP_X.header_list(msg, "Via")) do
    local via = SIP_X.parse_via(via_value)
    if via then
      local ip = via.received or via.host
      if SIP_X.is_internal_ip(ip) then
        leaks[#leaks + 1] = { source = "Via", value = ip, detail = "proto=" .. via.proto .. " port=" .. tostring(via.port) }
      end
    end
  end
  for _, contact_value in ipairs(SIP_X.header_list(msg, "Contact")) do
    for _, contact in ipairs(SIP_X.parse_contact(contact_value)) do
      if SIP_X.is_internal_ip(contact.host) then
        leaks[#leaks + 1] = { source = "Contact", value = contact.host, detail = "port=" .. tostring(contact.port) .. " user=" .. tostring(contact.user) }
      end
    end
  end
  for _, hdr in ipairs({ "Record-Route", "Path", "P-Asserted-Identity", "Diversion", "Alert-Info" }) do
    for _, value in ipairs(SIP_X.header_list(msg, hdr)) do
      for ip in string.gmatch(value, "(%d+%.%d+%.%d+%.%d+)") do
        if SIP_X.is_internal_ip(ip) then
          leaks[#leaks + 1] = { source = hdr, value = ip, detail = "header address" }
        end
      end
    end
  end
  return leaks
end

function SIP_X.response_class(status)
  if status == nil then
    return "timeout"
  end
  if status >= 200 and status < 300 then
    return "success"
  elseif status == 401 or status == 407 then
    return "auth-required"
  elseif status == 403 then
    return "forbidden"
  elseif status == 404 then
    return "not-found"
  elseif status >= 400 and status < 500 then
    return "client-error"
  elseif status >= 500 then
    return "server-error"
  elseif status >= 100 and status < 200 then
    return "provisional"
  end
  return "unknown"
end

SIP_A = {}

function SIP_A.selftest()
  if md5("") ~= "d41d8cd98f00b204e9800998ecf8427e" then
    return false, "md5 empty vector failed"
  end
  if md5("abc") ~= "900150983cd24fb0d6963f7d28e17f72" then
    return false, "md5 abc vector failed"
  end
  if md5("The quick brown fox jumps over the lazy dog") ~= "9e107d9d372bb6826bd81d3542a419d6" then
    return false, "md5 fox vector failed"
  end
  local resp = SIP_X.parse_message("SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1;received=10.0.0.5\r\nFrom: <sip:100@pbx>;tag=a1\r\nTo: <sip:100@pbx>\r\nCall-ID: c1\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm=\"asterisk\", nonce=\"4321\", algorithm=MD5, qop=\"auth\"\r\nContact: <sip:100@192.168.1.2:5060>\r\nContent-Length: 0\r\n\r\n")
  if resp.kind ~= "response" or resp.status ~= 401 then
    return false, "response parse failed"
  end
  local ch = SIP_X.parse_auth_challenge(SIP_X.header(resp, "WWW-Authenticate") or "")
  if ch.realm ~= "asterisk" or ch.nonce ~= "4321" or ch.qop ~= "auth" then
    return false, "challenge parse failed"
  end
  local leaks = SIP_X.address_disclosures(resp)
  if #leaks ~= 2 then
    return false, "address disclosure expected 2, got " .. tostring(#leaks)
  end
  local req = SIP_X.parse_message("OPTIONS sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKx\r\nAllow: INVITE, ACK, CANCEL, OPTIONS\r\nSupported: replaces, timer\r\nContent-Length: 0\r\n\r\n")
  if req.kind ~= "request" or req.method ~= "OPTIONS" then
    return false, "request parse failed"
  end
  local allow = SIP_X.parse_allow(req)
  if #allow ~= 4 or allow[2] ~= "ACK" then
    return false, "allow parse failed"
  end
  local supported = SIP_X.parse_supported(req)
  if #supported ~= 2 or supported[1] ~= "replaces" then
    return false, "supported parse failed"
  end
  local via = SIP_X.parse_via(SIP_X.header(req, "Via"))
  if via == nil or via.proto ~= "UDP" or via.branch ~= "z9hG4bKx" then
    return false, "via parse failed"
  end
  local sdp_text = "v=0\r\no=nse 1 2 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0 8 18 96\r\na=rtpmap:96 opus/48000/2\r\n"
  local sdp = SIP_X.parse_sdp(sdp_text)
  if sdp == nil or #sdp.media ~= 1 or sdp.media[1].port ~= 40000 then
    return false, "sdp parse failed"
  end
  local codecs = SIP_X.sdp_codecs(sdp)
  if #codecs ~= 4 or codecs[1].name ~= "PCMU" or codecs[4].name ~= "opus/48000/2" then
    return false, "sdp codec extraction failed"
  end
  if SIP_X.sdp_security(sdp) ~= "plain-rtp" then
    return false, "sdp security classify failed"
  end
  local uri = SIP_X.parse_uri("sip:100@10.1.2.3:5060;transport=udp")
  if uri.user ~= "100" or uri.host ~= "10.1.2.3" or uri.port ~= 5060 then
    return false, "uri parse failed"
  end
  local srv = SIP_X.classify_server("Asterisk PBX 18.10.0")
  if srv.engine ~= "Asterisk" or srv.version ~= "18.10.0" then
    return false, "server classify failed: " .. tostring(srv.engine) .. "/" .. tostring(srv.version)
  end
  local digest = SIP_B.digest_response({ username = "100", realm = "asterisk", password = "100", method = "REGISTER", uri = "sip:pbx", nonce = "abc123", qop = "auth", nc = "00000001", cnonce = "0a4f113b" })
  if #digest ~= 32 then
    return false, "digest response format failed"
  end
  local hdr = SIP_B.authorization_header(ch, { username = "100", password = "100" }, "REGISTER", "sip:pbx", {})
  if not string.find(hdr, "response=\"", 1, true) or not string.find(hdr, "realm=\"asterisk\"", 1, true) then
    return false, "authorization header build failed"
  end
  return true, "SIP codec, digest and parsers verified"
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

local function sip_session_new(host, port, args)
  local hname = host
  if type(host) == "table" then
    hname = host.ip or host.name or host.targetname or "192.0.2.10"
  end
  local pnum = port
  if type(port) == "table" then
    pnum = port.number or 5060
  end
  return {
    host = hname or "192.0.2.10",
    host_table = host,
    port = pnum or 5060,
    proto = (args and args.proto) or "udp",
    args = args or {},
    sock = nil,
    connected = false,
    closed = false,
    connects = 0,
    sends = 0,
    recvs = 0,
    timeouts = 0,
    errors = 0,
    transactions = 0,
    audit = {},
  }
end

local function sip_audit(sess, kind, detail)
  sess.audit[#sess.audit + 1] = kind .. ":" .. tostring(detail)
end

local function sip_connect(sess)
  if sess.connected then
    return 1
  end
  local sock = nmap.new_socket(sess.proto)
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, sess.proto)
  if not ok then
    sock:close()
    return nil, string.upper(sess.proto) .. " connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  sess.connects = sess.connects + 1
  sip_audit(sess, "connect", sess.port .. "/" .. sess.proto)
  return 1
end

local function sip_close(sess)
  if sess and sess.sock and not sess.closed then
    sess.sock:close()
  end
  if sess then
    sess.closed = true
    sess.connected = false
  end
end

local function sip_send_raw(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  sess.sends = sess.sends + 1
  sip_audit(sess, "send", #data)
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function sip_recv_chunk(sess, wait_seconds)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  local remaining = math.max(1, wait_seconds or 2)
  sess.sock:set_timeout(remaining * 1000)
  local ok, dat = sess.sock:receive(65535)
  if ok then
    sess.recvs = sess.recvs + 1
    sip_audit(sess, "recv", #dat)
    return dat
  end
  local err = dat
  if err == "TIMEOUT" or err == "EOF" then
    sess.timeouts = sess.timeouts + 1
    return nil, "timeout"
  end
  sess.errors = sess.errors + 1
  return nil, "receive failed: " .. tostring(err or "unknown")
end

local function sip_message_complete(buf)
  if buf == nil or buf == "" then
    return false
  end
  local head_end = string.find(buf, "\r\n\r\n", 1, true)
  if head_end == nil then
    if string.find(buf, "\n\n", 1, true) then
      return true
    end
    return false
  end
  local cl = tonumber(string.match(buf, "[Cc]ontent%-[Ll]ength:%s*(%d+)") or "0") or 0
  local body_len = #buf - (head_end + 3)
  return body_len >= cl
end

local function sip_recv_message(sess, deadline_seconds)
  local deadline = os.time() + math.max(1, deadline_seconds or 4)
  local buf = ""
  while os.time() < deadline do
    if budget_exhausted(sess.args) then
      break
    end
    local chunk, err = sip_recv_chunk(sess, 1)
    if chunk then
      buf = buf .. chunk
      if sip_message_complete(buf) then
        return buf
      end
    end
    if err == "timeout" and #buf > 0 then
      break
    end
    if err ~= nil and err ~= "timeout" then
      break
    end
  end
  if buf ~= "" then
    return buf
  end
  return nil, "no response before deadline"
end

local function sip_transaction(sess, request_text, args)
  args = args or {}
  local retries = args.retries or 2
  local last_err = nil
  for attempt = 1, retries + 1 do
    if attempt > 1 then
      sip_audit(sess, "retransmit", attempt)
    end
    local ok, serr = sip_send_raw(sess, request_text)
    if not ok then
      return nil, serr
    end
    local resp, rerr = sip_recv_message(sess, args.recv_window or 4)
    if resp then
      sess.transactions = sess.transactions + 1
      return resp
    end
    last_err = rerr
  end
  return nil, last_err or "no response"
end

local function sip_options_request(host, args, extras)
  return SIP_B.build_options(host, args, extras)
end

local function sip_options_probe(host, port, args)
  local sess = sip_session_new(host, port, args)
  local sections_audit = {}
  local ok, err = sip_connect(sess)
  if not ok then
    sip_close(sess)
    return nil, err, sess
  end
  local req_text, meta = sip_options_request(sess.host, args)
  local resp_text, terr = sip_transaction(sess, req_text, args)
  if resp_text == nil then
    sip_close(sess)
    return nil, terr, sess
  end
  local msg = SIP_X.parse_message(resp_text)
  local probe = {
    status = msg.status,
    reason = msg.reason or SIP_X.reason_for(msg.status or 0),
    class = SIP_X.response_class(msg.status),
    server = SIP_X.header(msg, "Server"),
    user_agent = SIP_X.header(msg, "User-Agent"),
    allow = SIP_X.parse_allow(msg),
    supported = SIP_X.parse_supported(msg),
    accept = SIP_X.header(msg, "Accept"),
    challenge = nil,
    cseq_method = msg.cseq_method,
    disclosure_leaks = SIP_X.address_disclosures(msg),
  }
  local auth_hdr = SIP_X.header(msg, "WWW-Authenticate") or SIP_X.header(msg, "Proxy-Authenticate")
  if auth_hdr then
    probe.challenge = SIP_X.parse_auth_challenge(auth_hdr)
  end
  sip_close(sess)
  for _, a in ipairs(sess.audit) do
    sections_audit[#sections_audit + 1] = a
  end
  probe.audit = sections_audit
  return probe, nil, sess
end

local function sip_register_probe(host, port, args, creds)
  local sess = sip_session_new(host, port, args)
  local ok, err = sip_connect(sess)
  if not ok then
    sip_close(sess)
    return nil, err
  end
  local stages = {}
  local req_text, meta = SIP_B.build_register(sess.host, creds.username, args, {})
  local resp_text, terr = sip_transaction(sess, req_text, args)
  if resp_text == nil then
    sip_close(sess)
    return nil, terr
  end
  local msg = SIP_X.parse_message(resp_text)
  stages[#stages + 1] = "register:" .. tostring(msg.status)
  local outcome = {
    stages = stages,
    initial_status = msg.status,
    authenticated = false,
    challenge = nil,
    realm = nil,
    response_status = nil,
    algo = nil,
  }
  local class = SIP_X.response_class(msg.status)
  if class == "auth-required" then
    local auth_hdr = SIP_X.header(msg, "WWW-Authenticate") or SIP_X.header(msg, "Proxy-Authenticate")
    local challenge = SIP_X.parse_auth_challenge(auth_hdr or "")
    outcome.challenge = challenge
    outcome.realm = challenge.realm
    outcome.algo = challenge.algorithm or "MD5"
    if creds.password then
      local auth_value = SIP_B.authorization_header(challenge, creds, "REGISTER", "sip:" .. sess.host, { nc = 1 })
      local req2_text = SIP_B.build_register(sess.host, creds.username, args, { cseq = 2, authorization = auth_value })
      local resp2_text, terr2 = sip_transaction(sess, req2_text, args)
      if resp2_text == nil then
        stages[#stages + 1] = "auth-retry:no-answer"
        outcome.response_status = nil
      else
        local msg2 = SIP_X.parse_message(resp2_text)
        stages[#stages + 1] = "auth:" .. tostring(msg2.status)
        outcome.response_status = msg2.status
        if msg2.status == 200 then
          outcome.authenticated = true
        end
      end
    end
  end
  sip_close(sess)
  outcome.stages = stages
  return outcome, nil
end

local function sip_invite_probe(host, port, args, from_user, to_user)
  local sess = sip_session_new(host, port, args)
  local ok, err = sip_connect(sess)
  if not ok then
    sip_close(sess)
    return nil, err
  end
  local stages = {}
  local sdp = SIP_B.build_sdp("192.0.2.10", 40000, { 0, 8, 18 })
  local req_text, meta = SIP_B.build_invite(sess.host, from_user, to_user, args, { sdp = sdp })
  local resp_text, terr = sip_transaction(sess, req_text, args)
  if resp_text == nil then
    sip_close(sess)
    return nil, terr
  end
  local msg = SIP_X.parse_message(resp_text)
  stages[#stages + 1] = "invite:" .. tostring(msg.status)
  local outcome = {
    stages = stages,
    status = msg.status,
    class = SIP_X.response_class(msg.status),
    reason = msg.reason,
    auth_required = false,
    challenge = nil,
    to_tag = nil,
    cleaned_up = false,
    sdp = nil,
    sdp_security = nil,
  }
  if msg.body and msg.body ~= "" then
    local sdp = SIP_X.parse_sdp(msg.body)
    if sdp then
      outcome.sdp = sdp
      outcome.sdp_security = SIP_X.sdp_security(sdp)
    end
  end
  local to_value = SIP_X.header(msg, "To") or ""
  outcome.to_tag = string.match(to_value, "tag=([^;>]+)")
  if msg.status == 401 or msg.status == 407 then
    outcome.auth_required = true
    local auth_hdr = SIP_X.header(msg, "WWW-Authenticate") or SIP_X.header(msg, "Proxy-Authenticate")
    outcome.challenge = SIP_X.parse_auth_challenge(auth_hdr or "")
  end
  if msg.status >= 200 then
    local ack_text = SIP_B.build_ack(sess.host, meta, from_user, to_user, args)
    sip_send_raw(sess, ack_text)
    stages[#stages + 1] = "ack:sent"
    if msg.status and msg.status < 300 then
      local bye_text = SIP_B.build_bye(sess.host, meta.callid, from_user, to_user, nil, outcome.to_tag, meta.cseq + 1, args)
      local bye_resp = sip_transaction(sess, bye_text, args)
      stages[#stages + 1] = "bye:" .. (bye_resp and SIP_X.parse_message(bye_resp).status or "timeout")
    end
    outcome.cleaned_up = true
  end
  sip_close(sess)
  return outcome, nil
end

local function sip_subscribe_probe(host, port, args, user, event)
  local sess = sip_session_new(host, port, args)
  local ok, err = sip_connect(sess)
  if not ok then
    sip_close(sess)
    return nil, err
  end
  local req_text, meta = SIP_B.build_subscribe(sess.host, user or "nse-audit", event or "presence", args, {})
  local resp_text, terr = sip_transaction(sess, req_text, args)
  if resp_text == nil then
    sip_close(sess)
    return nil, terr
  end
  local msg = SIP_X.parse_message(resp_text)
  local outcome = {
    status = msg.status,
    class = SIP_X.response_class(msg.status),
    reason = msg.reason,
    event = event or "presence",
    expires = tonumber(SIP_X.header(msg, "Expires")),
    content_type = SIP_X.header(msg, "Content-Type"),
    body_bytes = #msg.body,
  }
  sip_close(sess)
  return outcome, nil
end

local function sip_message_probe(host, port, args, from_user, to_user, text)
  local sess = sip_session_new(host, port, args)
  local ok, err = sip_connect(sess)
  if not ok then
    sip_close(sess)
    return nil, err
  end
  local req_text, meta = SIP_B.build_message(sess.host, from_user, to_user, text, args, {})
  local resp_text, terr = sip_transaction(sess, req_text, args)
  if resp_text == nil then
    sip_close(sess)
    return nil, terr
  end
  local msg = SIP_X.parse_message(resp_text)
  local outcome = {
    status = msg.status,
    class = SIP_X.response_class(msg.status),
    reason = msg.reason,
    auth_required = msg.status == 401 or msg.status == 407,
  }
  sip_close(sess)
  return outcome, nil
end

local function sip_bye_probe(host, port, args, from_user, to_user)
  local sess = sip_session_new(host, port, args)
  local ok, err = sip_connect(sess)
  if not ok then
    sip_close(sess)
    return nil, err
  end
  local callid = SIP_B.call_id(sess.host)
  local req_text, meta = SIP_B.build_bye(sess.host, callid, from_user or "nse-audit", to_user or "100", nil, nil, 2, args)
  local resp_text, terr = sip_transaction(sess, req_text, args)
  if resp_text == nil then
    sip_close(sess)
    return { status = nil, class = "timeout", validated = nil }, nil
  end
  local msg = SIP_X.parse_message(resp_text)
  local outcome = {
    status = msg.status,
    class = SIP_X.response_class(msg.status),
    reason = msg.reason,
    validated = nil,
  }
  if msg.status == 200 then
    outcome.validated = "teardown-accepted"
  elseif msg.status == 481 or msg.status == 403 or msg.status == 404 then
    outcome.validated = "rejected"
  else
    outcome.validated = "unclear"
  end
  sip_close(sess)
  return outcome, nil
end

local function sip_capacity_probe(host, port, args, limit)
  limit = math.min(limit or 5, 8)
  local accepted = 0
  local attempts = 0
  local statuses = {}
  for _ = 1, limit do
    attempts = attempts + 1
    local probe, err = sip_options_probe(host, port, args)
    if probe then
      statuses[#statuses + 1] = probe.status
      if probe.class == "success" then
        accepted = accepted + 1
      end
    else
      statuses[#statuses + 1] = nil
    end
  end
  return { attempts = attempts, accepted = accepted, bound = limit, statuses = statuses }
end

local function sip_rate_probe(host, port, args, count)
  count = math.min(count or 8, 12)
  local sess = sip_session_new(host, port, args)
  local ok, err = sip_connect(sess)
  if not ok then
    sip_close(sess)
    return nil, err
  end
  local sent = 0
  local start_t = os.time()
  local statuses = {}
  for i = 1, count do
    if budget_exhausted(sess.args) then
      break
    end
    local req_text = SIP_B.build_options(sess.host, args, { { name = "X-Audit-Seq", value = tostring(i) } })
    local ok2 = sip_send_raw(sess, req_text)
    if ok2 then
      sent = sent + 1
    else
      break
    end
  end
  local replies = 0
  local buf = ""
  local deadline = os.time() + (args.timeout or 8)
  while os.time() <= deadline and replies < sent do
    if budget_exhausted(sess.args) then
      break
    end
    local chunk, rerr = sip_recv_chunk(sess, 1)
    if chunk then
      buf = buf .. chunk
      while true do
        while string.sub(buf, 1, 2) == "\r\n" do
          buf = string.sub(buf, 3)
        end
        while string.sub(buf, 1, 1) == "\n" do
          buf = string.sub(buf, 2)
        end
        if buf == "" then
          break
        end
        local head_end = string.find(buf, "\r\n\r\n", 1, true)
        if head_end == nil then
          break
        end
        local cl = tonumber(string.match(buf, "[Cc]ontent%-[Ll]ength:%s*(%d+)") or "0") or 0
        local total = head_end + 3 + cl
        if #buf < total then
          break
        end
        local one = string.sub(buf, 1, total)
        buf = string.sub(buf, total + 1)
        local msg = SIP_X.parse_message(one)
        if msg.kind == "response" then
          replies = replies + 1
          statuses[#statuses + 1] = msg.status
        end
      end
    end
    if rerr == "timeout" and replies == 0 and os.time() >= deadline - 1 then
      break
    end
  end
  local window_ms = (os.time() - start_t) * 1000
  sip_close(sess)
  return { sent = sent, replies = replies, window_ms = window_ms, statuses = statuses }, nil
end

SIP_TP = {
  session_new = sip_session_new,
  audit = sip_audit,
  connect = sip_connect,
  close = sip_close,
  send_raw = sip_send_raw,
  recv_chunk = sip_recv_chunk,
  recv_message = sip_recv_message,
  message_complete = sip_message_complete,
  transaction = sip_transaction,
  options_probe = sip_options_probe,
  register_probe = sip_register_probe,
  invite_probe = sip_invite_probe,
  subscribe_probe = sip_subscribe_probe,
  message_probe = sip_message_probe,
  bye_probe = sip_bye_probe,
  capacity_probe = sip_capacity_probe,
  rate_probe = sip_rate_probe,
}

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

local function sip_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - SIP audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The SIP audit did not complete against this target", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function sip_target(host, port)
  return type(host) == "table" and (host.ip or host.name or host.targetname) or (host or "192.0.2.10"),
    (type(port) == "table" and (port.number or 5060) or (port or 5060))
end

local function sip_probe_args(args)
  return {
    timeout = args.timeout or 8,
    maxrequests = args.maxrequests or 48,
    retries = args.retries or 1,
  }
end

local function sip_invite_session(host, port, args, from_user, to_user, extra_headers)
  local hname, pnum = sip_target(host, port)
  local sess = SIP_TP.session_new(hname, pnum, sip_probe_args(args))
  local ok = SIP_TP.connect(sess)
  if not ok then
    return nil, "connect failed"
  end
  local sdp = SIP_B.build_sdp("192.0.2.10", 40000, { 0, 8, 18 })
  local req_text, meta = SIP_B.build_invite(sess.host, from_user, to_user, sip_probe_args(args),
    { sdp = sdp, extra_headers = extra_headers })
  local resp_text, err = SIP_TP.transaction(sess, req_text, sip_probe_args(args))
  if resp_text == nil then
    SIP_TP.close(sess)
    return nil, tostring(err or "no answer")
  end
  local msg = SIP_X.parse_message(resp_text)
  return sess, msg, meta
end

local function run_audit(host, port, args)
  local sections = {}
  local probe, err = SIP_TP.options_probe(host, port, sip_probe_args(args))
  if probe == nil then
    return sip_incomplete("OPTIONS probe failed: " .. tostring(err), sections, "session", err)
  end
  local server_value = probe.server or probe.user_agent or ""
  local engine = SIP_X.classify_server(server_value)
  sections[#sections + 1] = { key = "SIP Capabilities", value = {
    status = tostring(probe.status) .. " " .. tostring(probe.reason),
    server = probe.server or "absent",
    user_agent = probe.user_agent or "absent",
    engine = engine.engine,
    version = engine.version or "unknown",
    allow_count = #probe.allow,
    supported = #probe.supported > 0 and table.concat(probe.supported, ", ") or "none",
    accept = probe.accept or "n/a",
  } }
  local allow_rows = {}
  for _, m in ipairs(probe.allow) do
    allow_rows[#allow_rows + 1] = { method = m }
  end
  sections[#sections + 1] = { key = "Allowed Methods", value = allow_rows }

  local remediation = {}
  local status_text
  if engine.engine ~= "Unknown" then
    status_text = "INFORMATIONAL - PBX identified: " .. engine.engine .. (engine.version and (" " .. engine.version) or "")
    add_finding("INFO", "SIP server fingerprint identified", {
      subject = "fingerprint",
      evidence = "engine=" .. engine.engine .. " version=" .. tostring(engine.version) .. " raw=" .. server_value,
      confidence = "high",
    })
    remediation["1. Version"] = "Check the vendor advisory feed for " .. engine.engine .. " " .. tostring(engine.version or "releases") .. "."
  else
    status_text = "INFORMATIONAL - SIP service answered but the engine is not identifiable (" .. server_value .. ")"
    add_finding("INFO", "SIP service alive without a recognisable engine signature", {
      subject = "fingerprint",
      evidence = "status=" .. tostring(probe.status) .. " server=" .. server_value,
      confidence = "medium",
    })
    remediation["1. Identify"] = "Record the platform manually for the asset inventory."
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
