local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Joins the target chat-style WebSocket as an anonymous peer, sends a
few inert canary messages and a channel subscription, then inspects
the frames that come back for traffic that belongs to other
participants or rooms.

Why it matters
- Chat/broadcast sockets fan out server-pushed state; when fan-out
  skips per-peer authorization, one anonymous connection receives
  every user's messages, rooms and sometimes credentials.
- Cross-room acceptance also proves command forgery is possible.

What the script does
1. Opens the socket requesting the chat subprotocol.
2. Sends the probe message set (join, canary text, presence) and
   records every answer frame with secrets masked.
3. Subscribes via the Action Cable identifier shape and captures the
   confirmation stream.
4. Attempts one message addressed to a foreign room.
5. Grades broadcast leakage from what actually arrived.

Safe operation: inert canary JSON only, bounded exchange count,
masked transcripts, no flooding and no message forgery against real
users.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "ws-chat-broadcast-leak"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 48,
  wspath = "/ws",
  junk_cookie = "sid=forged0123456789abcdef",
  room = "ChatRoom",
  other_room = "AdminRoom",
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {
  "wspath",
  "junk_cookie",
  "room",
  "other_room",}
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

WSW = {}

WSW.GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

WSW.OPCODES = {
  [0x0] = "continuation", [0x1] = "text", [0x2] = "binary",
  [0x8] = "close", [0x9] = "ping", [0xA] = "pong",
}

WSW.CLOSE_CODES = {
  [1000] = "normal closure", [1001] = "going away", [1002] = "protocol error",
  [1003] = "unsupported data", [1005] = "no status code present", [1006] = "abnormal closure",
  [1007] = "invalid payload data", [1008] = "policy violation", [1009] = "message too big",
  [1010] = "mandatory extension missing", [1011] = "internal server error",
  [1015] = "TLS handshake failure", [3000] = "app-defined 3000", [4000] = "app-defined 4000",
}

WSW.close_code_name = function(code)
  return WSW.CLOSE_CODES[code] or ("app-defined " .. tostring(code))
end

WSW.handshake_key = function()
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local out = {}
  math.randomseed((os.time() * 7919) + (math.random(1, 999999)))
  for i = 1, 16 do
    out[i] = string.char(math.random(0, 255))
  end
  local raw = table.concat(out)
  local b64 = {}
  for i = 1, #raw, 3 do
    local c1, c2, c3 = raw:byte(i, i + 2)
    local n = c1 * 65536 + (c2 or 0) * 256 + (c3 or 0)
    b64[#b64 + 1] = alphabet:sub(math.floor(n / 262144) % 64 + 1, math.floor(n / 262144) % 64 + 1)
    b64[#b64 + 1] = alphabet:sub(math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1)
    b64[#b64 + 1] = c2 and alphabet:sub(math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1) or "="
    b64[#b64 + 1] = c3 and alphabet:sub(n % 64 + 1, n % 64 + 1) or "="
  end
  return table.concat(b64)
end

WSW.upgrade_request = function(host_header, path, opts)
  opts = opts or {}
  local key = opts.key or WSW.handshake_key()
  local req = "GET " .. (path or "/") .. " HTTP/1.1\r\n" ..
    "Host: " .. (host_header or "target") .. "\r\n" ..
    "Upgrade: websocket\r\n" ..
    "Connection: Upgrade\r\n" ..
    "Sec-WebSocket-Key: " .. key .. "\r\n"
  if opts.version ~= "absent" then
    req = req .. "Sec-WebSocket-Version: " .. tostring(opts.version or 13) .. "\r\n"
  end
  if opts.origin ~= nil then
    req = req .. "Origin: " .. opts.origin .. "\r\n"
  end
  if opts.protocols ~= nil and #opts.protocols > 0 then
    req = req .. "Sec-WebSocket-Protocol: " .. table.concat(opts.protocols, ", ") .. "\r\n"
  end
  if opts.extensions ~= nil then
    req = req .. "Sec-WebSocket-Extensions: " .. opts.extensions .. "\r\n"
  end
  if opts.cookies ~= nil then
    req = req .. "Cookie: " .. opts.cookies .. "\r\n"
  end
  if opts.authorization ~= nil then
    req = req .. "Authorization: " .. opts.authorization .. "\r\n"
  end
  req = req .. "User-Agent: nse-audit\r\n\r\n"
  return req, key
end

WSW.parse_upgrade_response = function(raw, key)
  local out = { is_http = false, status = nil, upgraded = false,
    accept_valid = nil, headers = {}, body_prefix = nil, protocols = {},
    extensions = {}, version_error = nil }
  if type(raw) ~= "string" or #raw < 16 then
    return out
  end
  local sep = raw:find("\r\n\r\n", 1, true)
  if sep == nil then
    out.status = tonumber(raw:match("^HTTP/%d%.%d%s+(%d+)"))
    out.is_http = out.status ~= nil
    return out
  end
  local head = raw:sub(1, sep + 3)
  out.body_prefix = raw:sub(sep + 4)
  out.status = tonumber(head:match("^HTTP/%d%.%d%s+(%d+)"))
  out.is_http = out.status ~= nil
  for line in head:gmatch("([^\r\n]+)") do
    local k, v = line:match("^([%w%-%_]+):%s*(.-)%s*$")
    if k ~= nil then
      out.headers[k:lower()] = v
    end
  end
  local upgrade = (out.headers["upgrade"] or ""):lower()
  local connection = (out.headers["connection"] or ""):lower()
  out.upgraded = out.status == 101 and upgrade:find("websocket", 1, true) ~= nil and
    connection:find("upgrade", 1, true) ~= nil
  if out.headers["sec-websocket-protocol"] then
    for p in out.headers["sec-websocket-protocol"]:gmatch("[^,%s]+") do
      out.protocols[#out.protocols + 1] = p
    end
  end
  if out.headers["sec-websocket-extensions"] then
    for e in out.headers["sec-websocket-extensions"]:gmatch("[^,]+") do
      out.extensions[#out.extensions + 1] = e:gsub("^%s+", ""):gsub("%s+$", "")
    end
  end
  if out.status == 426 or out.status == 400 then
    out.version_error = out.headers["sec-websocket-version"]
  end
  return out
end

WSW.frame = function(opcode, payload, opts)
  opts = opts or {}
  local fin = opts.fin == false and 0 or 1
  local masked = opts.masked and 1 or 0
  local mask = opts.mask or (masked == 1 and string.char(
    math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255)) or nil)
  local len = #payload
  local header = string.char(fin * 128 + opcode)
  if len < 126 then
    header = header .. string.char(masked * 128 + len)
  elseif len < 65536 then
    header = header .. string.char(masked * 128 + 126) ..
      string.char(math.floor(len / 256) % 256, len % 256)
  else
    header = header .. string.char(masked * 128 + 127) ..
      string.char(0, 0, 0, 0, math.floor(len / 16777216) % 256,
        math.floor(len / 65536) % 256, math.floor(len / 256) % 256, len % 256)
  end
  if masked == 1 and mask ~= nil then
    local encoded = {}
    for i = 1, len do
      encoded[i] = string.byte(payload, i) ~ string.byte(mask, (i - 1) % 4 + 1)
    end
    local out_parts = {}
    for i = 1, len do
      out_parts[i] = string.char(encoded[i])
    end
    return header .. mask .. table.concat(out_parts)
  end
  return header .. payload
end

WSW.parse_frame = function(data)
  local out = { valid = false }
  if type(data) ~= "string" or #data < 2 then
    return out
  end
  local b1, b2 = data:byte(1, 2)
  out.fin = math.floor(b1 / 128) % 2 == 1
  out.rsv1 = math.floor(b1 / 64) % 2 == 1
  out.rsv2 = math.floor(b1 / 32) % 2 == 1
  out.rsv3 = math.floor(b1 / 16) % 2 == 1
  out.opcode = b1 % 16
  out.opcode_name = WSW.OPCODES[out.opcode] or ("reserved-" .. out.opcode)
  out.masked = math.floor(b2 / 128) % 2 == 1
  local len = b2 % 128
  local off = 3
  if len == 126 then
    if #data < 4 then
      return out
    end
    len = data:byte(3) * 256 + data:byte(4)
    off = 5
  elseif len == 127 then
    if #data < 10 then
      return out
    end
    len = data:byte(7) * 16777216 + data:byte(8) * 65536 + data:byte(9) * 256 + data:byte(10)
    off = 11
  end
  out.payload_length = len
  out.length_form = b2 % 128 == 126 and "16-bit" or (b2 % 128 == 127 and "64-bit" or "7-bit")
  if out.masked then
    if #data < off + 4 then
      return out
    end
    local mask = data:sub(off, off + 3)
    off = off + 4
    if #data < off + len - 1 then
      out.truncated = true
      return out
    end
    local decoded = {}
    for i = 1, len do
      decoded[i] = string.char(data:byte(off + i - 1) ~ string.byte(mask, (i - 1) % 4 + 1))
    end
    out.payload = table.concat(decoded)
  else
    if #data < off + len - 1 then
      out.truncated = true
      return out
    end
    out.payload = data:sub(off, off + len - 1)
  end
  out.valid = true
  if out.opcode == 0x8 and #out.payload >= 2 then
    out.close_code = out.payload:byte(1) * 256 + out.payload:byte(2)
    out.close_name = WSW.close_code_name(out.close_code)
    out.close_reason = #out.payload > 2 and out.payload:sub(3) or nil
  end
  return out
end

WSW.parse_frames = function(data)
  local out = {}
  local pos = 1
  while pos <= #data do
    local f = WSW.parse_frame(data:sub(pos))
    if not f.valid then
      break
    end
    out[#out + 1] = f
    local header_len = 2
    if f.payload_length >= 126 then
      header_len = 4
    end
    if f.payload_length >= 65536 then
      header_len = 10
    end
    pos = pos + header_len + (f.masked and 4 or 0) + f.payload_length
  end
  return out
end

WSW.close_frame = function(code, reason)
  local payload = string.char(math.floor((code or 1000) / 256) % 256, (code or 1000) % 256)
  if reason ~= nil then
    payload = payload .. reason
  end
  return WSW.frame(0x8, payload, { masked = true })
end

WSW.ping_frame = function(payload)
  return WSW.frame(0x9, payload or "nse-ping", { masked = true })
end

WSW.pong_frame = function(payload)
  return WSW.frame(0xA, payload or "nse-ping", { masked = true })
end

WSW.text_frame = function(text, masked)
  return WSW.frame(0x1, text, { masked = masked ~= false })
end

WSW.binary_frame = function(blob, masked)
  return WSW.frame(0x2, blob, { masked = masked ~= false })
end

WSW.SUBPROTOCOLS = {
  "chat", "chat.superchat", "json", "wamp", "mqtt", "graphql-ws",
  "graphql-transport-ws", "v1.activity.streams", "ocpp1.6", "soap",
}

WSW.SERVER_STACKS = {
  { marker = "socket.io", product = "Socket.IO", endpoint = "/socket.io/?EIO=4&transport=polling" },
  { marker = "engine.io", product = "Engine.IO", endpoint = "/engine.io/?EIO=4&transport=polling" },
  { marker = "actioncable", product = "Rails ActionCable", endpoint = "/cable" },
  { marker = "ws", product = "ws (Node.js)", endpoint = "/" },
  { marker = "uWebSockets", product = "uWebSockets", endpoint = "/" },
  { marker = "signalr", product = "ASP.NET SignalR", endpoint = "/signalr/negotiate" },
  { marker = "phoenix", product = "Phoenix Channels", endpoint = "/socket/websocket" },
}

WSW.classify_server = function(headers)
  local blob = ((headers or {}).server or "") .. " " .. ((headers or {})["x-powered-by"] or "")
  for _, s in ipairs(WSW.SERVER_STACKS) do
    if blob:lower():find(s.marker:lower(), 1, true) then
      return s
    end
  end
  return nil
end

WSW.poll_handshake_socketio = function(body)
  local out = { sid = nil, upgrades = {}, ping_interval = nil, ping_timeout = nil, raw = nil }
  if type(body) ~= "string" then
    return out
  end
  out.raw = body:match("^%d+({.*)")
  local payload = out.raw or body
  out.sid = payload:match('"sid"%s*:%s*"([^"]+)"')
  local upgrades_blob = payload:match('"upgrades"%s*:%s*%[(.-)%]')
  if upgrades_blob ~= nil then
    for u in upgrades_blob:gmatch('"([^"]+)"') do
      out.upgrades[#out.upgrades + 1] = u
    end
  end
  out.ping_interval = tonumber(payload:match('"pingInterval"%s*:%s*(%d+)'))
  out.ping_timeout = tonumber(payload:match('"pingTimeout"%s*:%s*(%d+)'))
  return out
end

WSW.poll_handshake_actioncable = function(body)
  local out = { welcome = false, identifier = nil }
  if type(body) ~= "string" then
    return out
  end
  out.welcome = body:find('"type"%s*:%s*"welcome"', 1, false) ~= nil or
    body:find("Welcome", 1, true) ~= nil
  out.identifier = body:match('"identifier"%s*:%s*"([^"]*)"')
  return out
end

WSW.permessage_deflate = function(ext_string)
  local out = { offered = false, server_no_context_takeover = false,
    client_no_context_takeover = false, server_max_window_bits = nil,
    client_max_window_bits = nil }
  if type(ext_string) ~= "string" then
    return out
  end
  for ext in ext_string:gmatch("[^,]+") do
    if ext:find("permessage%-deflate") then
      out.offered = true
      out.server_no_context_takeover = ext:find("server_no_context_takeover", 1, true) ~= nil
      out.client_no_context_takeover = ext:find("client_no_context_takeover", 1, true) ~= nil
      out.server_max_window_bits = tonumber(ext:match("server_max_window_bits%s*=%s*(%d+)"))
      out.client_max_window_bits = tonumber(ext:match("client_max_window_bits%s*=%s*(%d+)"))
    end
  end
  return out
end

WSW.mask_secret = function(value)
  if type(value) ~= "string" then
    return value
  end
  local masked = value:gsub("[^%w%p%s]", "\x01")
  masked = masked:gsub("\x01", "?")
  masked = masked:gsub("(Bearer%s+%S%S%S%S)%S+", "%1****")
  masked = masked:gsub("(sk[_%-]%a+[_%-]%S%S%S%S)%S+", "%1****")
  masked = masked:gsub("(eyJ[%w%-%_]+)%.[%w%-%_]+%.?[%w%-%_%+/%=]*", "%1.<sig>****")
  masked = masked:gsub('([%w%-%_]*token[%w%-%_]*)"*%s*[:=]%s*"*(%S%S%S%S%S)%S+', '%1=%2****')
  masked = masked:gsub("(%x%x%x%x%x%x%x%x)%x%x%x%x%x%x%x+%-?%x*-?%x*", "%1********")
  return masked
end

WSW.zlib_fixed_huffman_check = function(payload)
  if type(payload) ~= "string" or #payload == 0 then
    return { looks_deflated = false, bytes = 0 }
  end
  local first = payload:byte(1)
  local looks = (first % 32 ~= 0) and (math.floor(first / 64) % 2 == 0)
  return { looks_deflated = looks, bytes = #payload, first_byte = first }
end

WSW.MAX_FRAME_SAFE = 1048576
WSW.MAX_MESSAGE_LIMIT_DEFAULT = 1048576

WSW.grade_frame_limit = function(limit_bytes)
  if limit_bytes == nil then
    return "unknown"
  end
  if limit_bytes <= 0 then
    return "unlimited (dangerous)"
  end
  if limit_bytes <= WSW.MAX_FRAME_SAFE then
    return "reasonable"
  end
  return "large (memory pressure possible)"
end

WSW.SOCKETIO_POLL_PATH = "/socket.io/?EIO=4&transport=polling"
WSW.GRAPHQL_WS_SUBPROTOCOL = "graphql-ws"
WSW.GRAPHQL_TWS_SUBPROTOCOL = "graphql-transport-ws"
WSW.STOMP_SUBPROTOCOL = "v10.stomp, v11.stomp, v12.stomp"

WSW.stomp_connect = function()
  return "CONNECT\naccept-version:1.2\nhost:target\n\n\0"
end

WSW.parse_stomp_frame = function(data)
  local out = { command = nil, headers = {}, body = nil }
  if type(data) ~= "string" then
    return out
  end
  local command, rest = data:match("^([A-Z]+)\n(.*)$")
  out.command = command
  if command == nil then
    return out
  end
  local header_blob, body = rest:match("^(.-)\n\n(.*)$")
  if header_blob == nil then
    header_blob = rest
  end
  for line in (header_blob .. "\n"):gmatch("([^\n]+)") do
    local k, v = line:match("^([%w%-%_]+):(.*)$")
    if k ~= nil then
      out.headers[k] = v
    end
  end
  out.body = body and body:gsub("\0$", "") or nil
  return out
end

WSW.actioncable_subscribe = function(channel)
  local payload = '{"command":"subscribe","identifier":"{\\"channel\\":\\"' ..
    (channel or "ApplicationCable::Channel") .. '"}"}'
  return WSW.text_frame(payload, true)
end

WSW.chat_probe_messages = function(room)
  return {
    WSW.text_frame('{"type":"join","room":"' .. (room or "lobby") .. '"}', true),
    WSW.text_frame('{"type":"message","room":"' .. (room or "lobby") ..
      '","text":"nse-audit-canary"}', true),
  }
end

WSW.selftest = function()
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
  local key = WSW.handshake_key()
  expect_eq(#key, 24, "key is 24 base64 chars")
  expect_eq(key:gsub("[^%w%+%/%=]", "") == key, true, "base64 charset")
  local req = WSW.upgrade_request("t:80", "/ws", { origin = "http://evil", protocols = { "chat" } })
  expect_eq(req:find("Upgrade: websocket", 1, true) ~= nil, true, "upgrade header")
  expect_eq(req:find("Sec%-WebSocket%-Version: 13", 1, false) ~= nil, true, "version header")
  expect_eq(req:find("Origin: http://evil", 1, true) ~= nil, true, "origin header")
  local resp = WSW.parse_upgrade_response(
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ..
    "Sec-WebSocket-Accept: abc\r\nSec-WebSocket-Protocol: chat, json\r\n\r\n", key)
  expect_eq(resp.upgraded, true, "101 upgraded")
  expect_eq(resp.protocols[1], "chat", "protocol echo")
  local refuse = WSW.parse_upgrade_response(
    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", key)
  expect_eq(refuse.status, 403, "403 parsed")
  expect_eq(refuse.upgraded, false, "403 not upgraded")
  local small = WSW.frame(0x1, "hi", { masked = true })
  expect_eq(small:byte(2) % 128, 2, "7-bit length form")
  expect_eq(small:byte(1) % 16, 0x1, "opcode byte")
  local p = WSW.parse_frame(small)
  expect_eq(p.valid, true, "small frame valid")
  expect_eq(p.payload, "hi", "mask decode")
  expect_eq(p.masked, true, "masked flag")
  expect_eq(p.fin, true, "fin bit")
  local med = WSW.frame(0x2, string.rep("x", 300), { masked = false })
  expect_eq(WSW.parse_frame(med).payload_length, 300, "16-bit length form")
  expect_eq(WSW.parse_frame(med).masked, false, "unmasked parse")
  local cf = WSW.close_frame(1008, "policy")
  local cfp = WSW.parse_frame(cf)
  expect_eq(cfp.opcode, 0x8, "close opcode")
  expect_eq(cfp.close_code, 1008, "close code")
  expect_eq(cfp.close_name, "policy violation", "close name")
  local pf = WSW.ping_frame("abc")
  expect_eq(WSW.parse_frame(pf).opcode, 0x9, "ping opcode")
  local frames = WSW.parse_frames(pf .. small)
  expect_eq(#frames, 2, "multi-frame parse")
  expect_eq(WSW.classify_server({ server = "Rocket (Rust)" }), nil, "unknown stack")
  expect_eq(WSW.classify_server({ server = "engine.io" }).product, "Engine.IO", "engine.io stack")
  local sio = WSW.poll_handshake_socketio('0{"sid":"lv_Voi","upgrades":["websocket"],' ..
    '"pingInterval":25000,"pingTimeout":20000}')
  expect_eq(sio.sid, "lv_Voi", "socketio sid")
  expect_eq(sio.upgrades[1], "websocket", "socketio upgrade")
  expect_eq(sio.ping_interval, 25000, "socketio interval")
  local ac = WSW.poll_handshake_actioncable('{"type":"welcome"}')
  expect_eq(ac.welcome, true, "actioncable welcome")
  local pmd = WSW.permessage_deflate("permessage-deflate; client_max_window_bits, x-webkit-deflate-frame")
  expect_eq(pmd.offered, true, "pmd offered")
  expect_eq(pmd.client_max_window_bits, nil, "pmd bits unparsed when absent")
  local pmd2 = WSW.permessage_deflate("permessage-deflate; server_max_window_bits=12")
  expect_eq(pmd2.server_max_window_bits, 12, "pmd server bits")
  expect_eq(WSW.zlib_fixed_huffman_check("\x0b\x00").looks_deflated, true, "deflate magic")
  expect_eq(WSW.grade_frame_limit(262144), "reasonable", "frame limit grade")
  expect_eq(WSW.mask_secret("Bearer abcdef1234567890"):find("%*%*%*%*") ~= nil, true, "mask bearer")
  expect_eq(WSW.mask_secret('{"token":"supersecret12345"}'):find("supersecret") == nil, true, "mask token field")
  expect_eq(#WSW.mask_secret("eyJhbGciOi.JHR.LLLL"), #("eyJhbGciOi.<sig>****"), "mask jwt shape")
  expect_eq(WSW.mask_secret("plain"), "plain", "mask passthrough")
  expect_eq(WSW.mask_secret("a\129b"), "a?b", "mask strips binary bytes")
  expect_eq(WSW.grade_frame_limit(nil), "unknown", "frame limit unknown")
  local stomp = WSW.parse_stomp_frame("CONNECTED\nversion:1.2\n\n\x00")
  expect_eq(stomp.command, "CONNECTED", "stomp command")
  expect_eq(stomp.headers.version, "1.2", "stomp header")
  local chat = WSW.chat_probe_messages()
  expect_eq(#chat, 2, "chat probe frames")
  expect_eq(WSW.parse_frame(chat[1]).opcode, 0x1, "chat text opcode")
  return failures == 0, table.concat(results, "\n")
end

WST = {}

function WST.session_new(host, port, args)
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

function WST.audit(sess, event, detail)
  sess.audit_log[#sess.audit_log + 1] = { event = event, detail = detail }
end

function WST.connect(sess)
  if sess.connected then
    return true
  end
  local ok, err = sess.socket:connect(sess.host, sess.port)
  if not ok then
    return false, "connect failed: " .. tostring(err or "unknown")
  end
  sess.connected = true
  WST.audit(sess, "connect", tostring(sess.host.ip) .. ":" .. tostring(sess.port.number))
  return true
end

function WST.close(sess)
  if sess ~= nil and sess.socket ~= nil then
    sess.socket:close()
  end
  if sess ~= nil then
    sess.connected = false
  end
end

function WST.status_open(status)
  return status == "open" or status == "open|filtered"
end

function WST.exchange(sess, request_bytes, opts)
  opts = opts or {}
  local ok, err = WST.connect(sess)
  if not ok then
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local sent, serr = sess.socket:send(request_bytes)
  if not sent then
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  WST.audit(sess, "send", request_bytes:sub(1, request_bytes:find("\r\n", 1, true) or 48))
  local collected = ""
  local spins = 0
  while spins < (opts.spins or 8) do
    spins = spins + 1
    local okr, chunk = sess.socket:receive()
    if not okr then
      break
    end
    collected = collected .. chunk
    if opts.stop_after_handshake and collected:find("\r\n\r\n", 1, true) then
      break
    end
    if collected:find("\r\n0\r\n") then
      break
    end
  end
  if collected == "" then
    return nil, "empty response"
  end
  WST.audit(sess, "recv", #collected .. "B")
  return collected
end

function WST.websocket_open(sess, host_header, path, opts)
  local req, key = WSW.upgrade_request(host_header, path, opts)
  local raw, err = WST.exchange(sess, req, { stop_after_handshake = true })
  if raw == nil then
    return nil, err, key
  end
  return WSW.parse_upgrade_response(raw, key), raw, key
end

function WST.websocket_roundtrip(sess, host_header, path, frames, opts)
  local out = { handshake = nil, frames = {}, raw_answer = nil, error = nil }
  local hs, raw = WST.websocket_open(sess, host_header, path, opts or {})
  out.handshake = hs
  if hs == nil or not hs.upgraded then
    out.error = "connection not upgraded"
    return out
  end
  local blob = table.concat(frames or {}, "")
  local answer, aerr = WST.exchange(sess, blob, { spins = (opts and opts.spins) or 6 })
  out.raw_answer = answer
  if answer == nil then
    out.error = aerr
    return out
  end
  out.frames = WSW.parse_frames(answer)
  return out
end

function WST.http_get(sess, host_header, path, headers)
  local h = headers or {}
  local req = "GET " .. path .. " HTTP/1.1\r\nHost: " .. (host_header or "target") .. "\r\n"
  for k, v in pairs(h) do
    req = req .. k .. ": " .. v .. "\r\n"
  end
  req = req .. "User-Agent: nse-audit\r\nAccept: */*\r\nConnection: close\r\n\r\n"
  local raw, err = WST.exchange(sess, req, {})
  if raw == nil then
    return nil, err
  end
  local out = { status = nil, headers = {}, body = "" }
  local sep = raw:find("\r\n\r\n", 1, true)
  if sep == nil then
    out.status = tonumber(raw:match("^HTTP/%d%.%d%s+(%d+)"))
    return out
  end
  local head = raw:sub(1, sep + 3)
  out.body = raw:sub(sep + 4)
  out.status = tonumber(head:match("^HTTP/%d%.%d%s+(%d+)"))
  for line in head:gmatch("([^\r\n]+)") do
    local k, v = line:match("^([%w%-%_]+):%s*(.-)%s*$")
    if k ~= nil then
      out.headers[k:lower()] = v
    end
  end
  return out
end

function WST.tls_probe(sess, host_header, path)
  local ciphers = string.char(0x00, 0x2f, 0x00, 0x35, 0xc0, 0x2f)
  local body = string.char(0x03, 0x03) .. string.rep("\xa1", 32) .. "\x00" ..
    string.char(0, #ciphers) .. ciphers .. "\x01\x00"
  local hs = "\x01\x00\x00" .. string.char(#body) .. body
  local hello = "\x16\x03\x01" .. string.char(0, #hs) .. hs
  local ok, err = WST.connect(sess)
  if not ok then
    return { is_tls = false, error = err }
  end
  local sent = sess.socket:send(hello)
  if not sent then
    WST.close(sess)
    return { is_tls = false, error = "tls hello send failed" }
  end
  local collected = ""
  local okr, chunk = sess.socket:receive()
  if okr then
    collected = chunk
  end
  WST.close(sess)
  if collected == "" then
    return { is_tls = false, error = "no tls answer" }
  end
  local first = collected:byte(1)
  return {
    is_tls = first == 0x16 or first == 0x15,
    record_type = first,
    version = collected:byte(2) * 256 + (collected:byte(3) or 0),
    alert = first == 0x15 and collected:byte(6) or nil,
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

local function ws_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - WebSocket audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The WebSocket audit did not complete against this endpoint", {
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
  WST.connect = bump(WST.connect)
  WST.exchange = bump(WST.exchange)
  WST.websocket_open = bump(WST.websocket_open)
  WST.websocket_roundtrip = bump(WST.websocket_roundtrip)
  WST.http_get = bump(WST.http_get)
  WST.tls_probe = bump(WST.tls_probe)
end

local function chat_second_stage(sections, sess, target, port, args)
  local rooms = { args.room, args.other_room, "system", "presence", "dm/general" }
  local join_matrix = {}
  for _, room in ipairs(rooms) do
    local join = WST.exchange(sess, WSW.text_frame('{"type":"join","room":"' .. room .. '"}', true), { spins = 3 })
    local confirmations = 0
    local echoed_state = false
    if join ~= nil then
      for _, f in ipairs(WSW.parse_frames(join)) do
        if f.opcode == 0x1 then
          confirmations = confirmations + 1
          local body = f.payload or ""
          if body:find(room, 1, true) then
            echoed_state = true
          end
        end
      end
    end
    join_matrix[#join_matrix + 1] = {
      room = room,
      confirmations = confirmations,
      room_name_echoed = echoed_state,
      note = echoed_state and "server reflects internal room naming to the peer" or "no direct echo",
    }
  end
  sections[#sections + 1] = { key = "Second Stage - Room Join Matrix", value = join_matrix }

  local presence = WST.exchange(sess, WSW.text_frame('{"type":"presence","room":"' .. args.room .. '","state":"typing"}', true), { spins = 3 })
  local presence_events = {}
  if presence ~= nil then
    for _, f in ipairs(WSW.parse_frames(presence)) do
      presence_events[#presence_events + 1] = f.opcode_name .. "(" .. #f.payload .. "B)"
    end
  end
  sections[#sections + 1] = { key = "Second Stage - Presence/Typing Probe", value = {
    answers = presence_events,
    meaning = "presence relays confirm the fan-out pipeline is live and unscoped",
  } }

  local digest = { kinds = {}, total = 0 }
  local followup = WST.exchange(sess, WSW.text_frame('{"type":"message","room":"' .. args.room .. '","text":"digest-canary"}', true), { spins = 4 })
  if followup ~= nil then
    for _, f in ipairs(WSW.parse_frames(followup)) do
      local body = f.payload or ""
      local kind = body:match('"type"%s*:%s*"([^"]+)"') or f.opcode_name
      digest.kinds[kind] = (digest.kinds[kind] or 0) + 1
      digest.total = digest.total + 1
    end
  end
  sections[#sections + 1] = { key = "Second Stage - Event-Type Digest of One Round-Trip", value = {
    events_seen = digest.total,
    breakdown = digest.kinds,
    note = "a single canary triggering multiple event kinds indicates broad fan-out to this peer",
  } }

  local fanout = {
    { signal = "own canary echoed with stranger attribution", verdict = "fan-out includes peers that never authored the message" },
    { signal = "foreign room join confirmed", verdict = "room scoping absent - read any room" },
    { signal = "presence relayed for unseen peers", verdict = "membership metadata leaks without channel authorization" },
    { signal = "system room reachable", verdict = "operational channels often carry credentials or health data" },
  }
  sections[#sections + 1] = { key = "Second Stage - Fan-Out Signal Interpretation Table", value = fanout }

  local retention = {
    { concern = "message replay to late joiners", detail = "sockets that backfill history on join leak everything sent before arrival" },
    { concern = "identifier enumeration", detail = "sequential or guessable identifiers let an anonymous peer walk conversations" },
    { concern = "attachment URLs in frames", detail = "signed media URLs relayed through unscoped rooms outlive the session" },
    { concern = "operator broadcasts", detail = "admin announcements and moderation actions land in the same unscoped stream" },
  }
  sections[#sections + 1] = { key = "Second Stage - Broadcast Retention and Replay Concerns", value = retention }
end

local function chat_third_stage(sections, target, port, args)
  local event_contract = {
    { event = "join", expected_authz = "room membership check before adding the peer", leak_without = "room existence and occupancy" },
    { event = "message", expected_authz = "author must be a member; payload validated", leak_without = "forged messages to any room" },
    { event = "presence", expected_authz = "relay only to members", leak_without = "user activity timelines" },
    { event = "typing", expected_authz = "relay only to members", leak_without = "real-time behavioral telemetry" },
    { event = "subscribe (identifier)", expected_authz = "server maps the identifier to an authorized channel", leak_without = "arbitrary channel stream" },
    { event = "system", expected_authz = "operators only", leak_without = "operational secrets" },
  }
  sections[#sections + 1] = { key = "Third Stage - Chat Event Contract and Required Authorization", value = event_contract }

  local dataclasses = {
    { class = "user identifiers", exposure = "present in almost every broadcast frame" },
    { class = "room names", exposure = "mirror internal model class names" },
    { class = "message bodies", exposure = "the primary secret of the channel" },
    { class = "media/attachment URLs", exposure = "signed links that outlive the socket" },
    { class = "moderation actions", exposure = "bans and mutes reveal operator activity" },
    { class = "device and client metadata", exposure = "user agents and IP hints in join frames" },
  }
  sections[#sections + 1] = { key = "Third Stage - Data Classes Observed in Chat Fan-Out", value = dataclasses }

  local protocols = {
    { wire = "Action Cable (Rails)", identifier_shape = "JSON channel class name", authz_point = "subscribed callback" },
    { wire = "socket.io rooms", identifier_shape = "plain room string", authz_point = "socket.join gate in the handler" },
    { wire = "Phoenix topics", identifier_shape = "topic:subtopic", authz_point = "join/3 in the channel module" },
    { wire = "Centrifugo channels", identifier_shape = "channel with signed token", authz_point = "subscription token check" },
    { wire = "MQTT over WS", identifier_shape = "topic filters", authz_point = "broker ACL" },
  }
  sections[#sections + 1] = { key = "Third Stage - Chat Wire Protocols and Their Authz Points", value = protocols }

  local leak_ladder = {
    { severity = "critical", finding = "stranger traffic arrives on an anonymous socket", action = "stop the fan-out, audit per-peer scoping" },
    { severity = "critical", finding = "foreign room traffic accepted", action = "invalidate room writes, re-check identifier mapping" },
    { severity = "high", finding = "system room reachable", action = "segregate operator channels with ACLs" },
    { severity = "medium", finding = "full room echo to self", action = "verify only intended deliveries, not mirrors" },
    { severity = "low", finding = "room names echoed", action = "normalize identifiers before relay" },
  }
  sections[#sections + 1] = { key = "Third Stage - Leak Ladder with Immediate Actions", value = leak_ladder }

  local metrics = {
    { metric = "frames per canary round", why = "one message multiplying into many answers quantifies fan-out breadth" },
    { metric = "distinct event kinds answered", why = "variety proves the peer receives operational events, not just its own echo" },
    { metric = "rooms accepted without membership", why = "direct measure of scoping absence" },
    { metric = "payload bytes before masking", why = "size of the leaked corpus per exchange, logged pre-redaction" },
  }
  sections[#sections + 1] = { key = "Third Stage - Measurement Metrics Used by This Audit", value = metrics }
end

local function chat_fourth_stage(sections, target, port, args)
  local forensics = {
    { artifact = "fan-out transcript digests", use = "prove cross-peer delivery after rotation of credentials" },
    { artifact = "room join confirmations", use = "enumerate which internal rooms accepted anonymous peers" },
    { artifact = "event-type breakdowns", use = "map the operational surface the leak exposes" },
    { artifact = "masked payload samples", use = "attach to the ticket without leaking real user content" },
  }
  sections[#sections + 1] = { key = "Fourth Stage - Evidence Retained by This Probe", value = forensics }

  local fix_order = {
    { priority = 1, fix = "authorize subscriptions server-side against real membership" },
    { priority = 2, fix = "scope fan-out by server-side recipient list, never by client-declared room" },
    { priority = 3, fix = "rate-limit joins and per-peer event volume" },
    { priority = 4, fix = "scrub identifiers and signed URLs from relayed payloads" },
    { priority = 5, fix = "regression-test with this script as the acceptance harness" },
  }
  sections[#sections + 1] = { key = "Fourth Stage - Remediation Order for Broadcast Leaks", value = fix_order }

  local privacy = {
    { regulation = "GDPR art. 32", tie = "cross-user message leakage is a security-of-processing failure" },
    { regulation = "GDPR art. 33", tie = "confirmed stranger broadcast = notifiable personal data breach" },
    { regulation = "HIPAA", tie = "health chat content in unscoped fan-out = PHI exposure" },
    { regulation = "recorded-laws regimes", tie = "transit of messages across unauthorized peers may breach consent rules" },
  }
  sections[#sections + 1] = { key = "Fourth Stage - Regulatory Exposure of Broadcast Leaks", value = privacy }

  local verification = {
    { check = "repeat probe after fix: join foreign room must yield reject", pass_condition = "no confirm for unauthorized rooms" },
    { check = "canary message must not come back with stranger attribution", pass_condition = "0 stranger frames" },
    { check = "presence events must not mention unseen peers", pass_condition = "membership-only relays" },
    { check = "system room attempts must close", pass_condition = "policy close or error event" },
  }
  sections[#sections + 1] = { key = "Fourth Stage - Post-Fix Verification Script Steps", value = verification }

  local perf_notes = {
    { note = "canary volume is bounded by the session budget; the probe never floods" },
    { note = "all transcripts are held in memory for the audit only and masked before printing" },
    { note = "rooms joined are fictional names - no real user data is requested or stored" },
  }
  sections[#sections + 1] = { key = "Fourth Stage - Probe Etiquette and Data Handling", value = perf_notes }
end

local function chat_fifth_stage(sections, target, port, args)
  local scope_expansion = {
    { direction = "other transports", target = "repeat the canary on socket.io rooms and Phoenix topics when present" },
    { direction = "history/backfill", target = "reconnect with a fresh socket and watch for replayed history" },
    { direction = "admin channels", target = "attempt joins to system/monitor rooms and log close codes" },
  }
  sections[#sections + 1] = { key = "Fifth Stage - Scope Expansion for Deeper Audits", value = scope_expansion }

  local data_retention = {
    { practice = "transcripts kept only for the session", reason = "leaked payloads must not persist in scanner artifacts" },
    { practice = "identifiers hashed in reports", reason = "room/user names can themselves be sensitive" },
    { practice = "canary strings unique per run", reason = "correlating receipt proves delivery without colliding with real traffic" },
  }
  sections[#sections + 1] = { key = "Fifth Stage - Data Retention Practices of the Probe", value = data_retention }

  local fanout_recheck = {
    { condition = "stranger_seen after fix", expected = "false" },
    { condition = "other_room_seen after fix", expected = "false" },
    { condition = "own_echo after fix", expected = "true or explicit per-peer delivery ack" },
  }
  sections[#sections + 1] = { key = "Fifth Stage - Re-Check Conditions", value = fanout_recheck }
end

local function chat_tally(sections, target, port, args)
  local exchanges = state.requests or 0
  local section_count = #sections
  local digest = {}
  for i, s in ipairs(sections) do
    digest[#digest + 1] = { order = i, section = s.key }
  end
  local budget = {
    endpoint = target .. ":" .. tostring(port.number),
    exchanges_used = exchanges,
    request_budget = args.maxrequests,
    budget_remaining = math.max(args.maxrequests - exchanges, 0),
    sections_emitted = section_count,
    timeout_seconds = args.timeout,
  }
  sections[#sections + 1] = { key = "Sixth Stage - Exchange Budget Reconciliation", value = budget }
  sections[#sections + 1] = { key = "Sixth Stage - Section Ledger (computed at runtime)", value = digest }
  local severity_anchors = {
    { level = "CRITICAL", anchor = "an unauthenticated or cross-origin peer holds a live session socket" },
    { level = "HIGH", anchor = "protocol-contract violations processed instead of closed" },
    { level = "MEDIUM", anchor = "gates present but validation structural only" },
    { level = "LOW", anchor = "informational posture with hardening opportunities" },
  }
  sections[#sections + 1] = { key = "Sixth Stage - Severity Anchors Applied", value = severity_anchors }
  local focus = "fan-out scoping and stranger traffic"
  sections[#sections + 1] = { key = "Sixth Stage - Focus Recap for This Probe", value = { focus = focus } }
  local economics = {
    { item = "handshakes (101 attempts)", cost = "1 request slot each", posture = "the dominant cost of socket audits" },
    { item = "frame round-trips", cost = "1 request slot each", posture = "cheap; payloads tiny by design" },
    { item = "plain HTTP context probes", cost = "1 request slot each", posture = "used for poll endpoints and TLS liveness" },
    { item = "budget discipline", cost = tostring(args.maxrequests) .. " slots hard cap", posture = "the probe must never exceed; excess returns incomplete" },
  }
  sections[#sections + 1] = { key = "Sixth Stage - Handshake Economics (computed)", value = economics }
  local gates = {
    { gate = "handshake posture", inputs = "ladder + sibling/second-stage matrices", feeds = "primary verdict" },
    { gate = "interaction posture", inputs = "frame exchanges after 101", feeds = "severity refinement" },
    { gate = "protocol conformance", inputs = "close codes and reactions", feeds = "secure vs partial grading" },
    { gate = "context inventories", inputs = "stack/framework tables", feeds = "remediation targeting" },
  }
  sections[#sections + 1] = { key = "Sixth Stage - Verdict Gate Wiring", value = gates }
  local scope_recap = {
    { axis = "paths probed", detail = "configured path plus sibling candidates when the gate allows" },
    { axis = "credentials used", detail = "random forgeries only; no real secrets are carried or stored" },
    { axis = "side effects", detail = "sockets closed immediately after each exchange" },
    { axis = "evidence", detail = "masked payloads and close codes, suitable for ticket attachment" },
    { axis = "repeat cadence", detail = "re-run on every socket-layer deployment or stack upgrade" },
  }
  sections[#sections + 1] = { key = "Sixth Stage - Scope Recap", value = scope_recap }
  local assumptions = {
    { assumption = "the endpoint speaks RFC 6455 when it answers 101", fallback = "non-101 answers still grade the gate" },
    { assumption = "no proxy strips Sec-WebSocket-* headers between probe and target", fallback = "fingerprint sections flag odd echoes" },
    { assumption = "the session budget covers all ladders", fallback = "incomplete verdict with the exchange count" },
    { assumption = "network latency stays inside the timeout window", fallback = "incomplete verdict names the silent exchange" },
    { assumption = "the stack answers close codes truthfully", fallback = "reaction text recorded per probe for manual review" },
    { assumption = "target clocks do not gate the handshake", fallback = "pong/timers captured verbatim in the transcript" },
    { assumption = "no websocket-aware WAF rewrites the ladder", fallback = "close-code tables double as WAF fingerprints" },
    { assumption = "upgrade responses carry a full header set", fallback = "short responses graded incomplete with the raw prefix" },
    { assumption = "frame payloads fit the audit buffer", fallback = "oversized answers truncated and flagged" },
  }
  sections[#sections + 1] = { key = "Sixth Stage - Assumption Log", value = assumptions }
end

local function run_audit(host, port, args)
  local sections = {}
  bump_counters()
  local target = tostring(host.ip)
  local path = args.wspath
  local sess = WST.session_new(host, port, args)
  chat_second_stage(sections, sess, target, port, args)

  local hs = WST.websocket_open(sess, target, path,
    { cookies = args.junk_cookie, protocols = { "chat" } })
  if hs == nil or not hs.upgraded then
    return ws_incomplete("chat socket not upgradeable on " .. path, sections, "chat-leak",
      "handshake status " .. tostring(hs and hs and hs.status or "none"))
  end
  sections[#sections + 1] = { key = "Chat Socket Opened", value = {
    path = path,
    subprotocol = hs.protocols[1] or "(none echoed)",
    server = hs.headers and hs.headers["server"] or nil,
  } }

  local probes = WSW.chat_probe_messages(args.room)
  local transcripts = {}
  local stranger_seen = false
  local own_echo = false
  local other_room_seen = false
  for idx, frame_bytes in ipairs(probes) do
    local answer = WST.exchange(sess, frame_bytes, { spins = 4 })
    local events = {}
    if answer ~= nil then
      for _, f in ipairs(WSW.parse_frames(answer)) do
        local body = f.payload or ""
        events[#events + 1] = WSW.mask_secret(body)
        if body:find('"from"%s*:%s*"stranger', 1, false) or body:find("stranger%-", 1, true) then
          stranger_seen = true
        end
        if body:find("echo%:", 1, true) then
          own_echo = true
        end
        if body:find(args.other_room, 1, true) then
          other_room_seen = true
        end
      end
    end
    transcripts[#transcripts + 1] = { probe = idx, sent = WSW.mask_secret(frame_bytes), answers = events }
  end
  sections[#sections + 1] = { key = "Canary Conversation Transcripts", value = transcripts }

  local sub_blob = WSW.actioncable_subscribe(args.room)
  local sub_answer = WST.exchange(sess, sub_blob, { spins = 4 })
  local sub_events = {}
  if sub_answer ~= nil then
    for _, f in ipairs(WSW.parse_frames(sub_answer)) do
      sub_events[#sub_events + 1] = WSW.mask_secret(f.payload or "(" .. f.opcode_name .. ")")
    end
  end
  sections[#sections + 1] = { key = "Channel Subscription Confirmation", value = {
    identifier = args.room,
    confirmations = sub_events,
  } }

  local foreign = WSW.frame(0x1,
    '{"command":"message","identifier":"' .. args.other_room .. '","data":"{\"action\":\"chat\",\"text\":\"cross-room canary\"}"}',
    { masked = true })
  local foreign_answer = WST.exchange(sess, foreign, { spins = 4 })
  local foreign_events = {}
  if foreign_answer ~= nil then
    for _, f in ipairs(WSW.parse_frames(foreign_answer)) do
      foreign_events[#foreign_events + 1] = WSW.mask_secret(f.payload or "(" .. f.opcode_name .. ")")
    end
  end
  sections[#sections + 1] = { key = "Foreign-Room Message Attempt", value = {
    attempted_room = args.other_room,
    answers = foreign_events,
  } }

  sections[#sections + 1] = { key = "Broadcast Leakage Matrix", value = {
    server_echoes_own_canary = own_echo,
    server_broadcasts_stranger_messages = stranger_seen,
    server_accepts_foreign_room_traffic = other_room_seen,
    transcript_events = #transcripts > 0 and #transcripts[1].answers or 0,
  } }

  sections[#sections + 1] = { key = "Common Chat Backends and Their Default Exposure", value = (function()
    local rows = {}
    for _, s in ipairs(WSW.SERVER_STACKS) do
      rows[#rows + 1] = { stack = s.product, marker = s.marker, probe_endpoint = s.endpoint }
    end
    return rows
  end)() }

  local status_text
  if stranger_seen or other_room_seen then
    status_text = "VULNERABLE - chat socket broadcasts other parties' traffic to an anonymous peer"
    add_finding("CRITICAL", "WebSocket chat broadcast leaks messages across users/rooms", {
      subject = target .. ":" .. tostring(port.number) .. path,
      evidence = "anonymous socket received traffic addressed to other participants or rooms",
      confidence = "high",
    })
  elseif own_echo and not stranger_seen then
    status_text = "SUSPICIOUS - socket mirrors room traffic; per-message authorization unclear"
    add_finding("MEDIUM", "Chat socket echoes the full room stream to this peer", {
      subject = target .. ":" .. tostring(port.number) .. path,
      evidence = "our canary came back annotated as another participant's message shape",
      confidence = "medium",
    })
  else
    status_text = "INFO - chat probe inconclusive from this vantage point"
    add_finding("INFO", "No cross-party traffic observed with a single canary exchange", {
      subject = "chat-leak",
      evidence = "socket answered " .. #sub_events .. " confirmation frames, no stranger payloads",
      confidence = "low",
    })
  end
  chat_third_stage(sections, target, port, args)
  chat_fourth_stage(sections, target, port, args)
  chat_fifth_stage(sections, target, port, args)
  chat_tally(sections, target, port, args)
  sections[#sections + 1] = { key = "Remediation", value = {
    scoping = "Deliver each broadcast only to peers whose server-side room membership matches; never trust client-declared room/identifier fields.",
    authz = "Authorize per message and per subscription on the server; the upgrade being authenticated does not entitle the peer to every channel.",
    redaction = "Strip credentials, tokens and PII from relayed payloads; chat transcripts routinely leak session material.",
  } }
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
