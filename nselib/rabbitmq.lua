---
-- rabbitmq.lua
-- -------------------------------------------------------------------------
-- A RabbitMQ engine for NSE: the AMQP 0-9-1 wire protocol (framing, field
-- tables, method catalogue, the connection negotiation state machine and the
-- SASL exchanges RabbitMQ ships) plus the management HTTP API, which is where
-- RabbitMQ exposes its own inventory, users and queued message payloads.
--
-- Both halves are written from the published specifications:
--   * AMQP 0-9-1 (RabbitMQ's extended variant): frame = type(1) channel(2)
--     size(4) payload(size) frame-end(0xCE); a method payload is class-id(2)
--     method-id(2) arguments; strings are short (length byte) or long (4 byte
--     length); field tables are a long table of typed entries and every type
--     RabbitMQ emits is decoded here (t b B U u I i L l f d D s S A T F V x).
--   * The rabbitmq_management HTTP API: JSON documents over HTTP on 15672,
--     with HTTP Basic authentication and its own collection of endpoints -
--     some read-only, some that change broker state, and one (/queues/.../get)
--     that reads message payloads and can remove them.
--
-- Two rules drive the design. Nothing in this library changes broker state:
-- the connection negotiation stops at connection.open / channel.open, queue
-- declarations are passive (which cannot create anything), and the message
-- reader only ever asks for ack_requeue_true. And every byte that came back is
-- kept: a scan result has to be traceable to the exchange that produced it.

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
local os = require "os"

local M = {}

-- Forward declarations: the field table codec is mutually recursive (a table
-- can hold an array that holds a table), so the local names exist before the
-- body that refers to them.
local read_field_table, field_table, field_entry, sorted_keys

-- The protocol header is the first thing an AMQP client sends. 0-9-1 is what
-- RabbitMQ speaks; 1.0 is a different protocol with a different header, and
-- sending the 1.0 header is how a probe tells the two apart.
PROTOCOL_HEADER_091 = "AMQP\0\0\9\1"
PROTOCOL_HEADER_100 = "AMQP\0\3\0\0"
FRAME_METHOD = 1
FRAME_HEADER = 2
FRAME_BODY = 3
FRAME_HEARTBEAT = 8
FRAME_END = 0xCE
FRAME_MIN_SIZE = 4096
FRAME_MAX_DEFAULT = 131072
CHANNEL_MAX_DEFAULT = 2047
HEARTBEAT_DEFAULT = 60

-- Name resolution for the frames a report quotes. The catalogue covers the
-- classes a security audit needs to name precisely: connection and channel
-- negotiation, exchange and queue declaration, the basic class that carries
-- messages, transactions and publisher confirms.
CLASSES = {
  [10] = { name = "connection", methods = {
    [10] = { name = "start", sent_by = "server" },
    [11] = { name = "start-ok", sent_by = "client" },
    [20] = { name = "secure", sent_by = "server" },
    [21] = { name = "secure-ok", sent_by = "client" },
    [30] = { name = "tune", sent_by = "server" },
    [31] = { name = "tune-ok", sent_by = "client" },
    [40] = { name = "open", sent_by = "client" },
    [41] = { name = "open-ok", sent_by = "server" },
    [50] = { name = "close", sent_by = "either" },
    [51] = { name = "close-ok", sent_by = "either" },
    [60] = { name = "blocked", sent_by = "server" },
    [61] = { name = "unblocked", sent_by = "server" },
    [70] = { name = "update-secret", sent_by = "client" },
    [71] = { name = "update-secret-ok", sent_by = "server" },
  } },
  [20] = { name = "channel", methods = {
    [10] = { name = "open", sent_by = "client" },
    [11] = { name = "open-ok", sent_by = "server" },
    [20] = { name = "flow", sent_by = "either" },
    [21] = { name = "flow-ok", sent_by = "either" },
    [40] = { name = "close", sent_by = "either" },
    [41] = { name = "close-ok", sent_by = "either" },
  } },
  [40] = { name = "exchange", methods = {
    [10] = { name = "declare", sent_by = "client" },
    [11] = { name = "declare-ok", sent_by = "server" },
    [20] = { name = "delete", sent_by = "client" },
    [21] = { name = "delete-ok", sent_by = "server" },
    [30] = { name = "bind", sent_by = "client" },
    [31] = { name = "bind-ok", sent_by = "server" },
    [40] = { name = "unbind", sent_by = "client" },
    [51] = { name = "unbind-ok", sent_by = "server" },
    [50] = { name = "delete", sent_by = "client" },
  } },
  [50] = { name = "queue", methods = {
    [10] = { name = "declare", sent_by = "client" },
    [11] = { name = "declare-ok", sent_by = "server" },
    [20] = { name = "bind", sent_by = "client" },
    [21] = { name = "bind-ok", sent_by = "server" },
    [30] = { name = "purge", sent_by = "client" },
    [31] = { name = "purge-ok", sent_by = "server" },
    [40] = { name = "delete", sent_by = "client" },
    [41] = { name = "delete-ok", sent_by = "server" },
    [50] = { name = "unbind", sent_by = "client" },
    [51] = { name = "unbind-ok", sent_by = "server" },
  } },
  [60] = { name = "basic", methods = {
    [10] = { name = "qos", sent_by = "client" },
    [11] = { name = "qos-ok", sent_by = "server" },
    [20] = { name = "consume", sent_by = "client" },
    [21] = { name = "consume-ok", sent_by = "server" },
    [30] = { name = "cancel", sent_by = "client" },
    [31] = { name = "cancel-ok", sent_by = "server" },
    [40] = { name = "publish", sent_by = "client" },
    [50] = { name = "return", sent_by = "server" },
    [60] = { name = "deliver", sent_by = "server" },
    [70] = { name = "get", sent_by = "client" },
    [71] = { name = "get-ok", sent_by = "server" },
    [72] = { name = "get-empty", sent_by = "server" },
    [80] = { name = "ack", sent_by = "client" },
    [90] = { name = "reject", sent_by = "client" },
    [100] = { name = "recover-async", sent_by = "client" },
    [110] = { name = "recover", sent_by = "client" },
    [111] = { name = "recover-ok", sent_by = "server" },
    [120] = { name = "nack", sent_by = "client" },
  } },
  [85] = { name = "confirm", methods = {
    [10] = { name = "select", sent_by = "client" },
    [11] = { name = "select-ok", sent_by = "server" },
  } },
  [90] = { name = "tx", methods = {
    [10] = { name = "select", sent_by = "client" },
    [11] = { name = "select-ok", sent_by = "server" },
    [20] = { name = "commit", sent_by = "client" },
    [21] = { name = "commit-ok", sent_by = "server" },
    [30] = { name = "rollback", sent_by = "client" },
    [31] = { name = "rollback-ok", sent_by = "server" },
  } },
}

-- The reply codes that carry meaning for an audit: an access refusal is not a
-- missing resource, and the difference decides whether a permission exists.
REPLY_CODES = {
  [200] = { name = "REPLY_SUCCESS", class = "ok" },
  [311] = { name = "CONTENT_TOO_LARGE", class = "resource" },
  [312] = { name = "NO_ROUTE", class = "routing" },
  [313] = { name = "NO_CONSUMERS", class = "routing" },
  [320] = { name = "CONNECTION_FORCED", class = "connection" },
  [402] = { name = "INVALID_PATH", class = "argument" },
  [403] = { name = "ACCESS_REFUSED", class = "authorization" },
  [404] = { name = "NOT_FOUND", class = "resource" },
  [405] = { name = "RESOURCE_LOCKED", class = "resource" },
  [406] = { name = "PRECONDITION_FAILED", class = "argument" },
  [501] = { name = "FRAME_ERROR", class = "frame" },
  [502] = { name = "SYNTAX_ERROR", class = "frame" },
  [503] = { name = "COMMAND_INVALID", class = "frame" },
  [504] = { name = "CHANNEL_ERROR", class = "frame" },
  [505] = { name = "UNEXPECTED_FRAME", class = "frame" },
  [506] = { name = "RESOURCE_ERROR", class = "frame" },
  [530] = { name = "NOT_ALLOWED", class = "authorization" },
  [540] = { name = "NOT_IMPLEMENTED", class = "unsupported" },
  [541] = { name = "INTERNAL_ERROR", class = "server" },
}

local function class_name(class_id)
  local entry = CLASSES[class_id]
  return entry and entry.name or ("class-" .. tostring(class_id))
end

local function method_name(class_id, method_id)
  local entry = CLASSES[class_id]
  local method = entry and entry.methods[method_id]
  if method then return method.name end
  return string.format("method-%d.%d", class_id, method_id)
end

local function method_text(class_id, method_id)
  return string.format("%s.%s(%d/%d)", class_name(class_id), method_name(class_id, method_id),
    class_id, method_id)
end

local function reply_code_name(code)
  local entry = REPLY_CODES[code]
  return entry and entry.name or ("code-" .. tostring(code))
end

local function reply_code_class(code)
  local entry = REPLY_CODES[code]
  return entry and entry.class or "unknown"
end

-- An access refusal and a missing resource are the two answers an audit reads
-- for permissions, so they are separated here rather than at every call site.
local function is_authorization_refusal(code)
  return code == 403 or code == 530
end

local function is_missing_resource(code)
  return code == 404
end

-- ---------------------------------------------------------------------------
-- 2. Primitives
-- ---------------------------------------------------------------------------
local BYTE, CHAR = string.byte, string.char

local function u16(value)
  local n = math.floor(tonumber(value) or 0) % 65536
  return CHAR(math.floor(n / 256) % 256, n % 256)
end

local function u32(value)
  local n = math.floor(tonumber(value) or 0) % 4294967296
  return CHAR(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256)
end

local function u64(value)
  local n = math.floor(tonumber(value) or 0)
  if n < 0 then n = n + 18446744073709551616 end
  local high = math.floor(n / 4294967296) % 4294967296
  local low = n % 4294967296
  return u32(high) .. u32(low)
end

local function read_u16(data, offset)
  local a, b = BYTE(data, offset, offset + 1)
  if not a then return nil, offset end
  return a * 256 + b, offset + 2
end

local function read_u32(data, offset)
  local a, b, c, d = BYTE(data, offset, offset + 3)
  if not a then return nil, offset end
  return ((a * 256 + b) * 256 + c) * 256 + d, offset + 4
end

local function read_u64(data, offset)
  local high, pos = read_u32(data, offset)
  if not high then return nil, offset end
  local low
  low, pos = read_u32(data, pos)
  if not low then return nil, offset end
  return high * 4294967296 + low, pos
end

local function short_string(value)
  local text = tostring(value or "")
  if #text > 255 then text = string.sub(text, 1, 255) end
  return CHAR(#text) .. text
end

local function long_string(value)
  local text = tostring(value or "")
  return u32(#text) .. text
end

local function read_short_string(data, offset)
  local length = BYTE(data, offset)
  if not length then return nil, offset end
  if #data < offset + length then return nil, offset end
  return string.sub(data, offset + 1, offset + length), offset + 1 + length
end

local function read_long_string(data, offset)
  local length
  length, offset = read_u32(data, offset)
  if not length then return nil, offset end
  if length < 0 or #data < offset - 1 + length then return nil, offset end
  return string.sub(data, offset, offset + length - 1), offset + length
end

local function read_bytes(data, offset, count)
  if #data < offset + count - 1 then return nil, offset end
  return string.sub(data, offset, offset + count - 1), offset + count
end

-- ---------------------------------------------------------------------------
-- 3. Field tables
-- ---------------------------------------------------------------------------
-- RabbitMQ emits the long form (4 byte length prefix); the short form exists
-- for completeness because a server is allowed to send either. Every value type
-- the broker uses is decoded, including nested tables and arrays, because the
-- capability table is what tells an audit what the broker will let a client do.

local FIELD_READERS = {}

FIELD_READERS["t"] = function(data, offset)
  local value = BYTE(data, offset)
  if not value then return nil, offset end
  return value ~= 0, offset + 1
end
FIELD_READERS["b"] = function(data, offset)
  local value = BYTE(data, offset)
  if not value then return nil, offset end
  if value > 127 then value = value - 256 end
  return value, offset + 1
end
FIELD_READERS["B"] = function(data, offset) return BYTE(data, offset), offset + 1 end
FIELD_READERS["U"] = function(data, offset)
  local value
  value, offset = read_u16(data, offset)
  if value and value > 32767 then value = value - 65536 end
  return value, offset
end
FIELD_READERS["u"] = function(data, offset) return read_u16(data, offset) end
FIELD_READERS["I"] = function(data, offset)
  local value
  value, offset = read_u32(data, offset)
  if value and value > 2147483647 then value = value - 4294967296 end
  return value, offset
end
FIELD_READERS["i"] = function(data, offset) return read_u32(data, offset) end
FIELD_READERS["L"] = function(data, offset)
  local value
  value, offset = read_u64(data, offset)
  if value and value > 9223372036854775807 then value = value - 18446744073709551616 end
  return value, offset
end
FIELD_READERS["l"] = function(data, offset) return read_u64(data, offset) end
FIELD_READERS["f"] = function(data, offset)
  local raw
  raw, offset = read_u32(data, offset)
  if not raw then return nil, offset end
  -- IEEE 754 single precision, decoded by hand: the sign, the exponent and the
  -- mantissa, because a float field can carry a threshold a report quotes.
  local sign = raw >= 2147483648 and -1 or 1
  if sign == -1 then raw = raw - 2147483648 end
  local exponent = math.floor(raw / 8388608)
  local mantissa = raw % 8388608
  local value = mantissa / 8388608
  if exponent > 0 and exponent < 255 then value = (value + 1) * 2 ^ (exponent - 127)
  elseif exponent == 0 then value = value * 2 ^ (-126)
  elseif exponent == 255 then value = mantissa == 0 and math.huge or 0 / 0 end
  return sign * value, offset
end
FIELD_READERS["d"] = function(data, offset)
  local raw
  raw, offset = read_u64(data, offset)
  if not raw then return nil, offset end
  if raw == 0 then return 0, offset end
  local sign = 1
  if raw >= 9223372036854775808 then sign, raw = -1, raw - 9223372036854775808 end
  local exponent = math.floor(raw / 4503599627370496)
  local mantissa = raw % 4503599627370496
  if exponent == 0 then return sign * mantissa * 2 ^ (-1074), offset end
  return sign * (mantissa + 4503599627370496) * 2 ^ (exponent - 1075), offset
end
FIELD_READERS["D"] = function(data, offset)
  local scale = BYTE(data, offset)
  local value
  value, offset = read_u32(data, offset + 1)
  if not value then return nil, offset end
  if scale == 0 then return value, offset end
  return value / 10 ^ scale, offset
end
FIELD_READERS["s"] = function(data, offset) return read_short_string(data, offset) end
FIELD_READERS["S"] = function(data, offset) return read_long_string(data, offset) end
FIELD_READERS["x"] = function(data, offset)
  return read_long_string(data, offset)
end
FIELD_READERS["T"] = function(data, offset) return read_u64(data, offset) end
FIELD_READERS["V"] = function(data, offset) return nil, offset end
FIELD_READERS["A"] = function(data, offset)
  local length
  length, offset = read_u32(data, offset)
  if not length then return nil, offset end
  local finish = offset + length - 1
  local items = {}
  while offset <= finish do
    local kind = string.sub(data, offset, offset)
    local reader = FIELD_READERS[kind] or (kind == "F" and read_field_table)
    if not reader then break end
    local value
    value, offset = reader(data, offset + 1)
    items[#items + 1] = value
  end
  return items, offset
end

read_field_table = function(data, offset)
  local length
  length, offset = read_u32(data, offset)
  if not length then return nil, offset end
  local finish = offset + length - 1
  local out = {}
  while offset <= finish do
    local name
    name, offset = read_short_string(data, offset)
    if not name then break end
    local kind = string.sub(data, offset, offset)
    local reader = FIELD_READERS[kind] or (kind == "F" and read_field_table)
    if not reader then break end
    local value
    value, offset = reader(data, offset + 1)
    out[name] = value
  end
  return out, offset
end

FIELD_READERS["F"] = function(data, offset) return read_field_table(data, offset) end

local function parse_table(data, offset)
  return read_field_table(data, offset or 1)
end

local function parse_short_table(data, offset)
  local length = BYTE(data, offset)
  if not length then return nil, offset end
  local finish = offset + length
  local out = {}
  offset = offset + 1
  while offset <= finish do
    local name
    name, offset = read_short_string(data, offset)
    if not name then break end
    local kind = string.sub(data, offset, offset)
    local reader = FIELD_READERS[kind] or (kind == "F" and read_field_table)
    if not reader then break end
    local value
    value, offset = reader(data, offset + 1)
    out[name] = value
  end
  return out, offset
end

-- ---------------------------------------------------------------------------
-- 4. Encoding: client frames
-- ---------------------------------------------------------------------------
-- Only the requests an audit needs are encoded, and each one is written out in
-- full below its caller so a reader can check the field order against the spec.

local TABLES = {}

field_table = function(values, short)
  local body = {}
  local names = {}
  for name in pairs(values or {}) do names[#names + 1] = name end
  table.sort(names)
  for _, name in ipairs(names) do
    body[#body + 1] = field_entry(name, values[name])
  end
  local joined = table.concat(body)
  if short then return CHAR(#joined) .. joined end
  return u32(#joined) .. joined
end

field_entry = function(name, value)
  local kind = type(value)
  if kind == "boolean" then return short_string(name) .. "t" .. (value and CHAR(1) or CHAR(0)) end
  if kind == "string" then return short_string(name) .. "S" .. long_string(value) end
  if kind == "table" then return short_string(name) .. "F" .. field_table(value) end
  if kind == "number" then
    if value == math.floor(value) and math.abs(value) <= 2147483647 then
      return short_string(name) .. "I" .. u32(value % 4294967296)
    end
    return short_string(name) .. "d" .. u64(0) .. ""
  end
  return short_string(name) .. "V"
end

local function method_payload(class_id, method_id, args)
  return u16(class_id) .. u16(method_id) .. (args or "")
end

local function frame(kind, channel, payload)
  return CHAR(kind) .. u16(channel) .. u32(#payload) .. payload .. CHAR(FRAME_END)
end

local function method_frame(class_id, method_id, channel, args)
  return frame(FRAME_METHOD, channel or 0, method_payload(class_id, method_id, args))
end

-- The parts of the codec that callers outside this file use.
M.PROTOCOL_HEADER_091 = PROTOCOL_HEADER_091
M.PROTOCOL_HEADER_100 = PROTOCOL_HEADER_100
M.class_name = class_name
M.field_entry = field_entry
M.field_table = field_table
M.frame = frame
M.is_authorization_refusal = is_authorization_refusal
M.is_missing_resource = is_missing_resource
M.long_string = long_string
M.method_frame = method_frame
M.method_name = method_name
M.method_payload = method_payload
M.method_text = method_text
M.parse_short_table = parse_short_table
M.parse_table = parse_table
M.read_bytes = read_bytes
M.read_long_string = read_long_string
M.read_short_string = read_short_string
M.read_u16 = read_u16
M.read_u32 = read_u32
M.read_u64 = read_u64
M.reply_code_class = reply_code_class
M.reply_code_name = reply_code_name
M.short_string = short_string
M.u16 = u16
M.u32 = u32
M.u64 = u64
M.amqplain_response = amqplain_response
M.client_properties = client_properties
M.close_fields = close_fields
M.external_response = external_response
M.handshake = handshake
M.new_connection = new_connection
M.open_channel = open_channel
M.plain_response = plain_response
M.probe_queue = probe_queue
M.sasl_response = sasl_response
M.sorted_keys = sorted_keys
M.start_response_fields = start_response_fields
M.tune_fields = tune_fields

-- ---------------------------------------------------------------------------
-- 5. Connection
-- ---------------------------------------------------------------------------
-- The frame reader is the part that has to survive a hostile or broken peer:
-- frames arrive split across TCP segments, heartbeats arrive between the
-- frames a caller is waiting for, and a peer may simply stop talking. Every
-- read is bounded by the socket timeout, a partial frame is reported as a
-- truncated frame rather than as a parse error, and anything that is not the
-- frame the caller expected is kept in the transcript with its class, method
-- and reply code so the report can quote it.

local Wire = {}
Wire.__index = Wire

function M.new_connection(host, port, opts)
  opts = opts or {}
  local self = setmetatable({}, Wire)
  self.host, self.port = host, port
  self.timeout_ms = opts.timeout_ms or 5000
  self.client_id = opts.client_id or "nmap-nse-rabbitmq"
  self.buf = ""
  self.transcript = {}
  self.closed = false
  self.stats = { requests = 0, responses = 0, timeouts = 0, errors = 0, bytes_out = 0, bytes_in = 0,
    frames_in = 0, frames_out = 0, heartbeats = 0 }

  local sock = nmap.new_socket("tcp")
  if not sock then
    self.last_error = "socket creation failed"
    return self
  end
  sock:set_timeout(self.timeout_ms)
  local ok, err = sock:connect(host, port)
  if not ok then
    self.last_error = "connect failed: " .. tostring(err)
    return self
  end
  self.sock = sock
  return self
end

function Wire:log(entry)
  entry.at = os.time()
  self.transcript[#self.transcript + 1] = entry
  return entry
end

function Wire:note(kind, detail)
  return self:log({ kind = kind, detail = detail })
end

-- Peek at the first bytes the peer sent without interpreting them as a frame.
-- The first server bytes are what identifies a port: an AMQP 0-9-1 server sends
-- a frame, a server that speaks another protocol version sends its own protocol
-- header, and a management port sends HTTP. Only the first two bytes of a frame
-- header are even needed to tell the three apart, and a frame reader pointed at
-- the other two would report a plausible-size error that explains nothing.
function Wire:read_raw(count)
  count = math.floor(count or 8)
  if #self.buf == 0 then
    local ok, chunk = self.sock:receive_bytes(count)
    if not ok then
      if chunk == "TIMEOUT" then
        self.stats.timeouts = self.stats.timeouts + 1
        return nil, "timeout after " .. tostring(self.timeout_ms) .. "ms"
      end
      self.stats.errors = self.stats.errors + 1
      return nil, "receive failed: " .. tostring(chunk)
    end
    if not chunk or #chunk == 0 then return nil, "the peer closed without sending anything" end
    self.buf = self.buf .. chunk
    self.stats.bytes_in = self.stats.bytes_in + #chunk
  end
  return string.sub(self.buf, 1, math.min(count, #self.buf))
end

-- Drop `count` bytes that read_raw already peeked at.
function Wire:consume(count)
  count = math.floor(count or 0)
  if count <= 0 then return end
  if count >= #self.buf then
    self.buf = ""
  else
    self.buf = string.sub(self.buf, count + 1)
  end
end

function Wire:read_exact(count)
  count = math.floor(count)
  while #self.buf < count do
    local ok, chunk = self.sock:receive_bytes(count - #self.buf)
    if not ok then
      if chunk == "TIMEOUT" then
        self.stats.timeouts = self.stats.timeouts + 1
        return nil, "timeout after " .. tostring(self.timeout_ms) .. "ms"
      end
      self.stats.errors = self.stats.errors + 1
      return nil, "receive failed: " .. tostring(chunk)
    end
    if not chunk or #chunk == 0 then break end
    self.buf = self.buf .. chunk
    self.stats.bytes_in = self.stats.bytes_in + #chunk
  end
  if #self.buf < count then
    return nil, string.format("connection closed with %d of %d byte(s)", #self.buf, count)
  end
  local out = string.sub(self.buf, 1, count)
  self.buf = string.sub(self.buf, count + 1)
  return out
end

function Wire:send(data)
  if self.closed or not self.sock then return nil, "connection is closed" end
  local ok, err = self.sock:send(data)
  if not ok then
    self.stats.errors = self.stats.errors + 1
    return nil, tostring(err)
  end
  self.stats.bytes_out = self.stats.bytes_out + #data
  return true
end

-- One frame as the spec defines it: type, channel, size, payload, frame-end.
function Wire:read_frame()
  local header, err = self:read_exact(7)
  if not header then
    self:note("read-error", err)
    return nil, err
  end
  local size
  size = read_u32(header, 4)
  if not size or size > 134217728 then
    self:note("read-error", "frame size " .. tostring(size) .. " is not plausible")
    return nil, "implausible frame size " .. tostring(size)
  end
  local payload, payload_err = self:read_exact(size)
  if not payload then
    self:note("truncated-frame", string.format("frame with %d byte payload: %s", size, tostring(payload_err)))
    return nil, "truncated frame (" .. tostring(payload_err) .. ")"
  end
  local end_marker, end_err = self:read_exact(1)
  if not end_marker then return nil, "truncated frame end (" .. tostring(end_err) .. ")" end
  if BYTE(end_marker) ~= FRAME_END then
    self:note("frame-error", string.format("frame end is 0x%02x, not 0x%02x", BYTE(end_marker), FRAME_END))
    return nil, "frame end marker missing"
  end
  self.stats.frames_in = self.stats.frames_in + 1
  local kind, channel = BYTE(header, 1), (BYTE(header, 2) * 256 + BYTE(header, 3))
  local out = { kind = kind, channel = channel, size = size, payload = payload }
  if kind == FRAME_METHOD then
    out.class_id = read_u16(payload, 1)
    out.method_id = read_u16(payload, 3)
    out.method = method_text(out.class_id, out.method_id)
    out.args = string.sub(payload, 5)
  elseif kind == FRAME_HEARTBEAT then
    self.stats.heartbeats = self.stats.heartbeats + 1
  end
  self:note("frame-in", string.format("%s channel %d, %d byte(s)", out.method or
    ("type " .. tostring(kind)), channel, size))
  return out
end

function Wire:write_frame(kind, channel, payload)
  local data = frame(kind, channel, payload)
  local ok, err = self:send(data)
  if not ok then return nil, err end
  self.stats.frames_out = self.stats.frames_out + 1
  return true
end

function Wire:write_method(class_id, method_id, channel, args)
  local ok, err = self:write_frame(FRAME_METHOD, channel or 0, method_payload(class_id, method_id, args))
  if not ok then return nil, err end
  self:note("frame-out", method_text(class_id, method_id) .. " on channel " .. tostring(channel or 0))
  return true
end

-- Read until the method the caller is waiting for arrives. Heartbeats and
-- anything else are recorded and skipped: a broker is allowed to interleave
-- them, and treating them as a protocol error is how a scanner misreports a
-- healthy broker. The caller passes a predicate so it can also accept the
-- error replies it knows how to read.
function Wire:await(predicate, limit)
  local seen = {}
  for _ = 1, limit or 8 do
    local packet, err = self:read_frame()
    if not packet then
      return nil, err, seen
    end
    if packet.kind == FRAME_HEARTBEAT then
      self:note("heartbeat", "server heartbeat received and skipped")
    else
      seen[#seen + 1] = packet
      if predicate(packet) then return packet, nil, seen end
    end
  end
  return nil, "no matching frame in " .. tostring(limit or 8) .. " reads", seen
end

function Wire:await_method(class_id, method_id, limit)
  return self:await(function(packet)
    return packet.kind == FRAME_METHOD and packet.class_id == class_id and packet.method_id == method_id
  end, limit)
end

-- connection.close is the polite end of a session, and a broker that answers it
-- got the chance to log the disconnect it deserves.
function Wire:close(reason)
  if self.closed or not self.sock then
    self.closed = true
    return true
  end
  if self.handshaked then
    self:write_method(10, 50, 0, u16(200) .. short_string("") .. u16(0) .. u16(0))
  end
  self.closed = true
  self.sock:close()
  return true
end

-- ---------------------------------------------------------------------------
-- 6. The AMQP 0-9-1 negotiation
-- ---------------------------------------------------------------------------
-- RabbitMQ answers the protocol header with connection.start, which carries the
-- broker's own description of itself: version and platform strings, the
-- capability table (what a client may rely on), the SASL mechanisms it accepts
-- and its locales. An audit reads that frame twice - once for what it says, and
-- once for what it omits.

function start_response_fields(args)
  local out = { version_major = BYTE(args, 1), version_minor = BYTE(args, 2) }
  local offset = 3
  out.server_properties, offset = parse_table(args, offset)
  out.mechanisms, offset = read_long_string(args, offset)
  out.locales, offset = read_long_string(args, offset)
  out.mechanism_list = {}
  for name in string.gmatch(out.mechanisms or "", "[^ ]+") do
    out.mechanism_list[#out.mechanism_list + 1] = name
  end
  out.locale_list = {}
  for name in string.gmatch(out.locales or "", "[^ ]+") do
    out.locale_list[#out.locale_list + 1] = name
  end
  out.capabilities = (out.server_properties or {}).capabilities or {}
  return out
end

function tune_fields(args)
  local out = {}
  local offset
  out.channel_max, offset = read_u16(args, 1)
  out.frame_max, offset = read_u32(args, offset)
  out.heartbeat, offset = read_u16(args, offset)
  return out
end

function close_fields(args)
  local out = {}
  out.reply_code = read_u16(args, 1)
  out.reply_text, _ = read_short_string(args, 3)
  local offset = 3 + (BYTE(args, 3) or 0) + 1
  out.class_id = read_u16(args, offset)
  out.method_id = read_u16(args, offset + 2)
  out.reply_name = reply_code_name(out.reply_code)
  out.reply_class = reply_code_class(out.reply_code)
  return out
end

-- The SASL response for each mechanism RabbitMQ ships by default. PLAIN is the
-- literal NUL-separated triple; AMQPLAIN sends a field table as the response,
-- which is the only place a table is not length-delimited by the frame; and
-- EXTERNAL sends the empty string because the identity comes from the transport.
function plain_response(user, password)
  return "\0" .. tostring(user or "") .. "\0" .. tostring(password or "")
end

function amqplain_response(user, password)
  return field_table({ LOGIN = tostring(user or ""), PASSWORD = tostring(password or "") })
end

function external_response(authzid)
  return tostring(authzid or "")
end

function sasl_response(mechanism, user, password)
  local upper = string.upper(tostring(mechanism or ""))
  if upper == "PLAIN" then return plain_response(user, password) end
  if upper == "AMQPLAIN" then return amqplain_response(user, password) end
  if upper == "EXTERNAL" then return external_response(password) end
  if upper == "RABBIT-CR-DEMO" then return plain_response(user, password) end
  return nil, "no response is implemented for " .. tostring(mechanism)
end

-- Client properties are descriptive, but the capability table has to be honest:
-- claiming a capability the client will not honour is how a probe gets a broker
-- to disable a safety mechanism (consumer_cancel_notify, for example) around it.
function client_properties(client_id, opts)
  opts = opts or {}
  local properties = {
    product = "Nmap NSE rabbitmq engine",
    version = "1.0.0",
    platform = "Lua " .. tostring(_VERSION),
    copyright = "Same as Nmap",
    information = "RabbitMQ AMQP 0-9-1 audit client",
  }
  local capabilities = {
    publisher_confirms = false,
    exchange_exchange_bindings = false,
    basic_nack = false,
    consumer_cancel_notify = false,
    connection_blocked = false,
    consumer_priorities = false,
    authentication_failure_close = false,
  }
  if opts.capabilities then
    for name, value in pairs(opts.capabilities) do capabilities[name] = value end
  end
  if opts.authentication_failure_close then capabilities.authentication_failure_close = true end
  properties.capabilities = capabilities
  if client_id then properties.connection_name = "Nmap " .. tostring(client_id) end
  return properties
end

-- The whole handshake, in the order the spec requires it:
--   protocol header -> connection.start -> connection.start-ok
--   -> connection.tune -> connection.tune-ok -> connection.open -> connection.open-ok
-- Every step is reported, including the ones that were refused, because the step
-- that failed is the finding: a broker that refuses start-ok with 403 is
-- enforcing credentials, one that answers 530 on connection.open is refusing the
-- vhost, and one that answers open-ok has authenticated the client.
function M.handshake(host, port, opts)
  opts = opts or {}
  local conn = opts.connection or M.new_connection(host, port, opts)
  local out = { ok = false, connection = conn, stages = {}, mechanisms = {}, locales = {},
    capabilities = {}, vhost = opts.vhost or "/" }
  local function stage(name, detail, ok)
    out.stages[#out.stages + 1] = { name = name, detail = detail, ok = ok ~= false }
    return out.stages[#out.stages + 1]
  end
  if not conn.sock then
    stage("connect", tostring(conn.last_error or "connection failed"), false)
    out.error = conn.last_error or "connection failed"
    return out
  end
  stage("connect", string.format("TCP connection to %s:%d", tostring(host), port))

  local header = opts.header or PROTOCOL_HEADER_091
  local sent, send_err = conn:send(header)
  if not sent then
    stage("protocol-header", tostring(send_err), false)
    out.error = send_err
    return out
  end
  conn:note("protocol-header", string.format("%d byte AMQP header sent (%s)",
    #header, header == PROTOCOL_HEADER_091 and "0-9-1" or "not 0-9-1"))
  stage("protocol-header", header == PROTOCOL_HEADER_091 and "AMQP 0-9-1 header sent"
    or "AMQP 1.0 header sent")

  -- The first server bytes decide what this port is. An AMQP 0-9-1 server answers
  -- the header with connection.start (a frame). A server that does not speak the
  -- requested version answers with a protocol header of its own, as the
  -- specification requires, and a management port answers with HTTP. Either of
  -- the latter two would be misread as a frame, so the bytes are peeked at and
  -- classified before the frame reader touches them.
  local peek, peek_err = conn:read_raw(64)
  if peek == nil then
    stage("connection.start", string.format("not answered (%s)", tostring(peek_err)), false)
    out.error = "the server did not answer the protocol header: " .. tostring(peek_err)
    out.status = "no-answer"
    out.refused = true
    return out
  end
  if string.sub(peek, 1, 4) == "AMQP" and #peek >= 8 then
    conn:consume(8)
    -- The header is "AMQP" + a zero byte + major + minor + revision, so the three
    -- version bytes are the last three of the eight.
    out.protocol_reply = { family = "AMQP", major = BYTE(peek, 6), minor = BYTE(peek, 7),
      revision = BYTE(peek, 8) }
    out.first_reply = string.format("the server's own protocol header AMQP %d.%d.%d: it does not speak "
      .. "the version that was sent", BYTE(peek, 6), BYTE(peek, 7), BYTE(peek, 8))
    stage("protocol-header reply", out.first_reply, false)
    out.error = "the server answered the protocol header with its own"
    out.status = "protocol-version-mismatch"
    out.refused = true
    conn:close()
    return out
  end
  if BYTE(peek, 1) == 0x16 and BYTE(peek, 2) == 0x03 then
    -- A TLS record in answer to a plaintext protocol header: the port is an
    -- amqps listener (or a TLS front end), and nothing AMQP can be read from it
    -- without a handshake this script does not perform.
    out.protocol_reply = { family = "TLS", record_type = BYTE(peek, 1),
      record_version = string.format("%d.%d", BYTE(peek, 2), BYTE(peek, 3)),
      record_length = BYTE(peek, 4) * 256 + BYTE(peek, 5) }
    out.first_reply = string.format("a TLS record (content type %d, version %s): the listener speaks TLS",
      BYTE(peek, 1), out.protocol_reply.record_version)
    stage("protocol-header reply", out.first_reply, false)
    out.error = "the port answered the AMQP protocol header with a TLS record"
    out.status = "tls-listener"
    out.refused = true
    conn:close()
    return out
  end
  if string.sub(peek, 1, 5) == "HTTP/" then
    conn:consume(8)
    local more = conn:read_raw(200) or ""
    local line = more
    local crlf = string.find(more, "\r\n")
    if crlf then line = string.sub(more, 1, crlf - 1) end
    out.first_reply = "HTTP response: " .. tostring(line)
    out.protocol_reply = { family = "HTTP" }
    stage("protocol-header reply", out.first_reply, false)
    out.error = "the port answered the AMQP protocol header with HTTP rather than AMQP"
    out.status = "http-listener"
    out.refused = true
    conn:close()
    return out
  end

  local start, start_err, seen = conn:await_method(10, 10)
  if not start then
    -- Anything else that arrived first is the answer: a frame the reader did not
    -- expect, or a close with nothing in it.
    local first = seen and seen[1]
    out.first_reply = first and (first.method or ("frame type " .. tostring(first.kind))) or nil
    stage("connection.start", string.format("not answered (%s; first reply: %s)", tostring(start_err),
      tostring(out.first_reply or "nothing")), false)
    out.error = "connection.start was not answered: " .. tostring(start_err)
    out.refused = true
    return out
  end
  out.start = start_response_fields(start.args)
  -- The frame carries the major and minor version only; the revision comes from
  -- the protocol header the client sent and the broker accepted, so a 0/9 pair
  -- that answered a 0-9-1 header is reported as 0-9-1 rather than 0.9.
  out.version_major, out.version_minor = out.start.version_major, out.start.version_minor
  out.version = (tonumber(out.start.version_major) == 0 and tonumber(out.start.version_minor) == 9)
    and "0-9-1" or string.format("%s.%s", tostring(out.start.version_major),
      tostring(out.start.version_minor))
  out.mechanisms = out.start.mechanism_list
  out.locales = out.start.locale_list
  out.capabilities = out.start.capabilities
  out.server_properties = out.start.server_properties
  stage("connection.start", string.format("AMQP %s, %s, mechanisms [%s], capabilities [%s]",
    out.version, tostring((out.server_properties or {}).product or "unknown product"),
    table.concat(out.mechanisms, " "), table.concat(sorted_keys(out.capabilities), " ")))

  local mechanism = opts.mechanism
  if not mechanism then
    for _, candidate in ipairs({ "PLAIN", "AMQPLAIN", "EXTERNAL" }) do
      for _, offered in ipairs(out.mechanisms) do
        if offered == candidate and not mechanism then mechanism = candidate end
      end
    end
    mechanism = mechanism or out.mechanisms[1]
  end
  -- Without an identity there is nothing to authenticate: sending start-ok with
  -- an empty PLAIN response would be a login attempt the operator never asked
  -- for, and a failed login in the broker's log. The handshake stops here, with
  -- everything the start frame disclosed.
  if opts.user == nil and opts.password == nil and not opts.send_empty_credentials then
    out.status = "start-only"
    out.ok = true
    out.authenticated = false
    stage("credentials", "no credential was supplied, so connection.start-ok was not sent")
    return out
  end

  out.mechanism = mechanism
  out.mechanism_offered = false
  for _, offered in ipairs(out.mechanisms) do
    if offered == mechanism then out.mechanism_offered = true end
  end
  if not out.mechanism_offered then
    stage("mechanism", string.format("%s is not offered by this broker", tostring(mechanism)), false)
    out.error = "the requested mechanism is not offered"
    out.status = "mechanism-not-offered"
    return out
  end

  local response, response_err = sasl_response(mechanism, opts.user, opts.password)
  if not response then
    stage("sasl", tostring(response_err), false)
    out.error = response_err
    return out
  end
  if type(response) ~= "string" then response = table.concat({ response }) end

  local properties = client_properties(opts.client_id or conn.client_id, opts)
  -- start-ok: client-properties(table) mechanism(short) response(long) locale(short)
  local start_ok = field_table(properties) .. short_string(mechanism) .. long_string(response)
    .. short_string(opts.locale or (out.locales[1] or "en_US"))
  local ok_start, start_ok_err = conn:write_method(10, 11, 0, start_ok)
  if not ok_start then
    stage("connection.start-ok", tostring(start_ok_err), false)
    out.error = start_ok_err
    return out
  end
  out.response_bytes = #response
  out.password_bytes = opts.password and #tostring(opts.password) or 0
  out.user = opts.user
  stage("connection.start-ok", string.format("%s with a %d byte response for %s", tostring(mechanism),
    out.response_bytes, opts.user and ("account " .. tostring(opts.user)) or "an anonymous identity"))

  -- The broker either tunes the connection or refuses the credentials. A
  -- refusal is the interesting case: RabbitMQ 3.2+ answers connection.close with
  -- 403 ACCESS_REFUSED when authentication_failure_close was advertised.
  local reply, reply_err, after = conn:await(function(packet)
    if packet.kind ~= FRAME_METHOD then return false end
    if packet.class_id == 10 and (packet.method_id == 30 or packet.method_id == 50) then return true end
    return packet.class_id == 10 and packet.method_id == 20
  end, 6)
  if not reply then
    stage("connection.tune", string.format("not answered (%s)", tostring(reply_err)), false)
    out.error = "the broker did not tune the connection: " .. tostring(reply_err)
    out.status = "no-tune"
    return out
  end
  if reply.class_id == 10 and reply.method_id == 50 then
    out.close = close_fields(reply.args)
    stage("connection.close", string.format("%s (%s) during negotiation", out.close.reply_name,
      tostring(out.close.reply_text)), false)
    out.status = is_authorization_refusal(out.close.reply_code) and "authentication-refused" or "closed"
    out.authenticated = false
    return out
  end
  if reply.class_id == 10 and reply.method_id == 20 then
    -- RabbitMQ answers a challenge for mechanisms such as RABBIT-CR-DEMO; this
    -- client does not implement a challenge response, and says so instead of
    -- pretending the exchange completed.
    out.challenge = string.sub(reply.args or "", 5)
    stage("connection.secure", string.format("the broker sent a %d byte challenge, which this client does not answer",
      #out.challenge), false)
    out.error = "SASL challenge not answered"
    out.status = "challenge-not-answered"
    return out
  end

  out.tune = tune_fields(reply.args)
  stage("connection.tune", string.format("channel-max %s, frame-max %s, heartbeat %s",
    tostring(out.tune.channel_max), tostring(out.tune.frame_max), tostring(out.tune.heartbeat)))

  -- tune-ok echoes the values the client accepts. Taking the server's maxima
  -- keeps the rest of the session inside what the broker announced.
  local channel_max = math.min(out.tune.channel_max or CHANNEL_MAX_DEFAULT, CHANNEL_MAX_DEFAULT)
  local frame_max = out.tune.frame_max or FRAME_MAX_DEFAULT
  if frame_max < FRAME_MIN_SIZE then frame_max = FRAME_MIN_SIZE end
  local heartbeat = opts.heartbeat or 0
  local ok_tune, tune_err = conn:write_method(10, 31, 0, u16(channel_max) .. u32(frame_max) .. u16(heartbeat))
  if not ok_tune then
    stage("connection.tune-ok", tostring(tune_err), false)
    out.error = tune_err
    return out
  end
  out.accepted = { channel_max = channel_max, frame_max = frame_max, heartbeat = heartbeat }
  stage("connection.tune-ok", string.format("channel-max %d, frame-max %d, heartbeat %d",
    channel_max, frame_max, heartbeat))

  -- connection.open: vhost(short) reserved(short) reserved(bit)
  local ok_open, open_err = conn:write_method(10, 40, 0, short_string(out.vhost) .. short_string("") .. CHAR(0))
  if not ok_open then
    stage("connection.open", tostring(open_err), false)
    out.error = open_err
    return out
  end
  local opened, open_read_err = conn:await(function(packet)
    if packet.kind ~= FRAME_METHOD then return false end
    return packet.class_id == 10 and (packet.method_id == 41 or packet.method_id == 50)
  end, 4)
  if not opened then
    stage("connection.open", string.format("not answered (%s)", tostring(open_read_err)), false)
    out.error = "connection.open was not answered: " .. tostring(open_read_err)
    out.status = "open-not-answered"
    return out
  end
  if opened.method_id == 50 then
    out.close = close_fields(opened.args)
    stage("connection.open", string.format("%s for vhost %s (%s)", out.close.reply_name, out.vhost,
      tostring(out.close.reply_text)), false)
    out.status = is_authorization_refusal(out.close.reply_code) and "vhost-refused" or "closed"
    out.authenticated = true
    out.access_refused = is_authorization_refusal(out.close.reply_code)
    return out
  end

  conn.handshaked = true
  out.authenticated = true
  out.status = "open"
  out.vhost_open = true
  stage("connection.open", string.format("vhost %s opened: the identity is authenticated for it", out.vhost))
  -- channel.open: reserved(short) on a channel the client picked.
  local channel = opts.channel or 1
  local ok_channel, channel_err = conn:write_method(20, 10, channel, short_string(""))
  if not ok_channel then
    stage("channel.open", tostring(channel_err), false)
    return out
  end
  local channel_ok, channel_read_err = conn:await(function(packet)
    if packet.kind ~= FRAME_METHOD then return false end
    return packet.channel == channel and packet.class_id == 20
  end, 4)
  out.channel = channel
  if channel_ok and channel_ok.method_id == 11 then
    out.channel_open = true
    stage("channel.open", string.format("channel %d opened", channel))
  else
    stage("channel.open", tostring(channel_read_err or (channel_ok and method_text(channel_ok.class_id,
      channel_ok.method_id)) or "no reply"), false)
  end
  return out
end

function sorted_keys(values)
  local keys = {}
  for name in pairs(values or {}) do keys[#keys + 1] = name end
  table.sort(keys)
  return keys
end

-- A passive queue declaration is the read-only permission test: it cannot
-- create a queue, and RabbitMQ answers 404 for a queue that is not there while
-- answering 403 for a name the authenticated identity may not look at. That
-- difference is a permission, not an existence question, and it is exactly what
-- a vhost audit wants to know.
function M.probe_queue(conn, channel, vhost, name, opts)
  opts = opts or {}
  local args = u16(0) .. short_string(name) .. CHAR(0x01) .. CHAR(0)
    .. field_table({}) .. field_table({})
  local out = { queue = name, vhost = vhost, channel = channel }
  local ok, err = conn:write_method(50, 10, channel, args)
  if not ok then
    out.error = err
    return out
  end
  local reply, read_err = conn:await(function(packet)
    if packet.kind ~= FRAME_METHOD or packet.channel ~= channel then return false end
    if packet.class_id == 50 and (packet.method_id == 11 or packet.method_id == 40) then return true end
    return packet.class_id == 20 and packet.method_id == 40
  end, 6)
  if not reply then
    out.error = read_err or "no reply"
    return out
  end
  if reply.class_id == 50 and reply.method_id == 11 then
    out.exists = true
    out.declare_ok = true
    local queue_name, offset = read_short_string(reply.args, 1)
    out.queue_name = queue_name
    out.message_count = read_u32(reply.args, offset)
    out.consumer_count = read_u32(reply.args, offset + 4)
    return out
  end
  if reply.class_id == 50 then
    out.close = close_fields(reply.args)
    out.exists = false
    out.reply_code = out.close.reply_code
    out.reply_name = out.close.reply_name
    out.refused = is_authorization_refusal(out.close.reply_code)
    out.missing = is_missing_resource(out.close.reply_code)
    return out
  end
  out.close = close_fields(reply.args)
  out.reply_code = out.close.reply_code
  out.channel_closed = true
  return out
end

-- The error replies of the AMQP surface, collected in one place: a channel
-- error closes the channel and leaves the connection usable, which is how a
-- scan keeps going after a refusal instead of tearing the session down.
function M.open_channel(conn, channel)
  local ok, err = conn:write_method(20, 10, channel, short_string(""))
  if not ok then return nil, err end
  local reply, read_err = conn:await(function(packet)
    if packet.kind ~= FRAME_METHOD or packet.channel ~= channel then return false end
    return packet.class_id == 20 or packet.class_id == 10
  end, 4)
  if not reply then return nil, read_err or "no reply" end
  if reply.class_id == 20 and reply.method_id == 11 then return true end
  if reply.class_id == 10 and reply.method_id == 50 then
    return nil, "connection closed: " .. close_fields(reply.args).reply_name
  end
  return nil, "channel.open answered with " .. method_text(reply.class_id, reply.method_id)
end


M.base64_decode = base64_decode
M.base64_encode = base64_encode
M.http_request = http_request
M.json_decode = json_decode
M.json_path = json_path

-- ---------------------------------------------------------------------------
-- 7. JSON
-- ---------------------------------------------------------------------------
-- The management API speaks JSON, so the engine has to read it properly: no
-- pattern matching on a document, a real recursive decoder that handles nests,
-- arrays, escapes, numbers with exponents, unicode escapes and both literal
-- forms. A decoder that returns nil for a document it cannot read is better
-- than one that returns half a table and lets a report draw conclusions from it.

local function json_error(text, message)
  return nil, string.format("%s at byte %d", message, text.position)
end

local function json_skip_space(text)
  while true do
    local byte = BYTE(text.data, text.position)
    if byte == 32 or byte == 9 or byte == 10 or byte == 13 then
      text.position = text.position + 1
    else
      return
    end
  end
end

local json_decode_value

local ESCAPES = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n",
  r = "\r", t = "\t" }

local function json_string(text)
  text.position = text.position + 1
  local out = {}
  while true do
    local byte = BYTE(text.data, text.position)
    if not byte then return json_error(text, "unterminated string") end
    if byte == 34 then
      text.position = text.position + 1
      return table.concat(out)
    end
    if byte == 92 then
      local escape = string.sub(text.data, text.position + 1, text.position + 1)
      if escape == "u" then
        local code = tonumber(string.sub(text.data, text.position + 2, text.position + 5), 16)
        if not code then return json_error(text, "bad unicode escape") end
        -- A surrogate pair is joined before encoding, so a name outside the BMP
        -- round-trips instead of arriving as two replacement characters.
        if code >= 0xD800 and code <= 0xDBFF then
          local low = tonumber(string.sub(text.data, text.position + 8, text.position + 11), 16)
          if low and low >= 0xDC00 and low <= 0xDFFF then
            code = 0x10000 + (code - 0xD800) * 0x400 + (low - 0xDC00)
            text.position = text.position + 6
          end
        end
        if code < 0x80 then
          out[#out + 1] = CHAR(code)
        elseif code < 0x800 then
          out[#out + 1] = CHAR(192 + math.floor(code / 64), 128 + code % 64)
        elseif code < 0x10000 then
          out[#out + 1] = CHAR(224 + math.floor(code / 4096), 128 + math.floor(code / 64) % 64,
            128 + code % 64)
        else
          out[#out + 1] = CHAR(240 + math.floor(code / 262144), 128 + math.floor(code / 4096) % 64,
            128 + math.floor(code / 64) % 64, 128 + code % 64)
        end
        text.position = text.position + 6
      else
        local mapped = ESCAPES[escape]
        if not mapped then return json_error(text, "unknown escape") end
        out[#out + 1] = mapped
        text.position = text.position + 2
      end
    else
      out[#out + 1] = CHAR(byte)
      text.position = text.position + 1
    end
  end
end

local function json_number(text)
  local start = text.position
  local byte = BYTE(text.data, text.position)
  while byte do
    if (byte >= 48 and byte <= 57) or byte == 45 or byte == 43 or byte == 46 or byte == 101 or byte == 69 then
      text.position = text.position + 1
    else
      break
    end
    byte = BYTE(text.data, text.position)
  end
  local value = tonumber(string.sub(text.data, start, text.position - 1))
  if not value then return json_error(text, "bad number") end
  return value
end

json_decode_value = function(text)
  json_skip_space(text)
  local byte = BYTE(text.data, text.position)
  if not byte then return json_error(text, "unexpected end of document") end
  if byte == 34 then return json_string(text) end
  if byte == 123 then
    text.position = text.position + 1
    local out = {}
    json_skip_space(text)
    if BYTE(text.data, text.position) == 125 then
      text.position = text.position + 1
      return out
    end
    while true do
      json_skip_space(text)
      if BYTE(text.data, text.position) ~= 34 then return json_error(text, "object key is not a string") end
      local key, key_err = json_string(text)
      if key == nil then return nil, key_err end
      json_skip_space(text)
      if BYTE(text.data, text.position) ~= 58 then return json_error(text, "missing colon") end
      text.position = text.position + 1
      local value, value_err = json_decode_value(text)
      if value == nil and value_err then return nil, value_err end
      out[key] = value
      json_skip_space(text)
      local separator = BYTE(text.data, text.position)
      if separator == 44 then
        text.position = text.position + 1
      elseif separator == 125 then
        text.position = text.position + 1
        return out
      else
        return json_error(text, "expected , or } in object")
      end
    end
  end
  if byte == 91 then
    text.position = text.position + 1
    local out = {}
    json_skip_space(text)
    if BYTE(text.data, text.position) == 93 then
      text.position = text.position + 1
      return out
    end
    while true do
      local value, value_err = json_decode_value(text)
      if value == nil and value_err then return nil, value_err end
      out[#out + 1] = value
      json_skip_space(text)
      local separator = BYTE(text.data, text.position)
      if separator == 44 then
        text.position = text.position + 1
      elseif separator == 93 then
        text.position = text.position + 1
        return out
      else
        return json_error(text, "expected , or ] in array")
      end
    end
  end
  if string.sub(text.data, text.position, text.position + 3) == "true" then
    text.position = text.position + 4
    return true
  end
  if string.sub(text.data, text.position, text.position + 3) == "null" then
    text.position = text.position + 4
    return nil
  end
  if string.sub(text.data, text.position, text.position + 4) == "false" then
    text.position = text.position + 5
    return false
  end
  return json_number(text)
end

function M.json_decode(data)
  if type(data) ~= "string" then return nil, "not a string" end
  local text = { data = data, position = 1 }
  local value, err = json_decode_value(text)
  if value == nil and err then return nil, err end
  json_skip_space(text)
  if text.position <= #data then
    return nil, string.format("trailing data after a complete document at byte %d", text.position)
  end
  return value
end

-- A JSON path reader: the API documents nest three deep, and reading the fields
-- of a nest by hand at every call site is where a report starts printing nil.
function M.json_path(document, path)
  local current = document
  for step in string.gmatch(tostring(path or ""), "[^.]+") do
    if type(current) ~= "table" then return nil end
    if tonumber(step) then
      current = current[tonumber(step)]
    else
      current = current[step]
    end
  end
  return current
end

-- ---------------------------------------------------------------------------
-- 8. The management HTTP API
-- ---------------------------------------------------------------------------
-- Written on the socket rather than through the http library, so that the
-- request line, the headers and the body stay visible to the caller: an audit
-- has to report exactly what it asked for and what came back, and it has to
-- notice a redirect, a chunked body, a truncated response or an HTTP error page
-- that is not JSON at all.

function M.http_request(host, port, method, path, opts)
  opts = opts or {}
  local conn = opts.connection or M.new_connection(host, port, opts)
  local out = { method = string.upper(method or "GET"), path = path, headers = {}, ok = false }
  if not conn.sock then
    out.error = conn.last_error or "connection failed"
    return out, conn
  end
  local request = { string.format("%s %s HTTP/1.1", out.method, path) }
  local headers = {
    ["Host"] = opts.host_header or string.format("%s:%d", tostring(host), port),
    ["Accept"] = "application/json",
    ["User-Agent"] = opts.user_agent or "nmap-nse-rabbitmq",
    ["Connection"] = "close",
  }
  local body = opts.body
  if opts.auth then headers["Authorization"] = "Basic " .. M.base64_encode(opts.auth) end
  if body then
    headers["Content-Type"] = opts.content_type or "application/json"
    headers["Content-Length"] = tostring(#body)
  end
  for _, name in ipairs(sorted_keys(headers)) do
    if headers[name] then request[#request + 1] = string.format("%s: %s", name, headers[name]) end
  end
  request[#request + 1] = ""
  request[#request + 1] = body or ""
  local payload = table.concat(request, "\r\n")
  local sent, send_err = conn:send(payload)
  if not sent then
    out.error = send_err
    return out, conn
  end
  conn:note("http-request", string.format("%s %s (%d byte(s), %s)", out.method, path, #payload,
    opts.auth and ("basic auth as " .. string.gsub(opts.auth, ":.*$", "")) or "no credentials"))

  local head = ""
  while not string.find(head, "\r\n\r\n", 1, true) do
    local byte, err = conn:read_exact(1)
    if not byte then
      out.error = "truncated response head: " .. tostring(err)
      return out, conn
    end
    head = head .. byte
    if #head > 65536 then
      out.error = "response head larger than 64 KiB"
      return out, conn
    end
  end
  local head_text = string.sub(head, 1, #head - 4)
  out.head_bytes = #head
  local code, reason = string.match(head_text, "^HTTP/%d%.%d (%d+)%s*(.-)\r?\n")
  if not code then
    out.error = "not an HTTP response: " .. string.sub(head_text, 1, 80)
    out.raw_head = head_text
    return out, conn
  end
  out.status, out.reason = tonumber(code), reason
  out.http_version = string.match(head_text, "^(HTTP/%d%.%d)")
  for line in string.gmatch(head_text, "\r?\n([^\r\n]+)") do
    local name, value = string.match(line, "^([^:]+):%s*(.*)$")
    if name then
      local key = string.lower(name)
      out.headers[key] = out.headers[key] and (out.headers[key] .. ", " .. value) or value
    end
  end
  out.content_type = out.headers["content-type"]

  -- The body: a length, a chunk sequence, or the connection close. All three are
  -- real responses from a proxy in front of the management API.
  local chunks = {}
  local function pull(count)
    if count <= 0 then return true end
    local data, err = conn:read_exact(count)
    if not data then return nil, err end
    chunks[#chunks + 1] = data
    return true
  end
  if out.headers["transfer-encoding"] and string.find(string.lower(out.headers["transfer-encoding"]), "chunked") then
    while true do
      local size_line, err = conn:read_bytes_until_crlf()
      if not size_line then
        out.error = "truncated chunk size: " .. tostring(err)
        break
      end
      local size = tonumber(string.match(size_line, "^%s*(%x+)"), 16)
      if not size then
        out.error = "unreadable chunk size: " .. tostring(size_line)
        break
      end
      if size == 0 then
        conn:read_bytes_until_crlf()
        out.chunked = true
        break
      end
      local ok_pull, pull_err = pull(size)
      if not ok_pull then
        out.error = "truncated chunk: " .. tostring(pull_err)
        break
      end
      if not conn:read_exact(2) then
        out.error = "chunk without a terminator"
        break
      end
    end
  elseif out.headers["content-length"] then
    local cap = opts.max_body or 4194304
    local length = tonumber(out.headers["content-length"])
    if length and length > cap then
      out.error = string.format("body of %d byte(s) exceeds the %d byte cap", length, cap)
      out.truncated = true
      length = cap
    end
    if length then
      local ok_pull, pull_err = pull(length)
      if not ok_pull then
        out.truncated = true
        out.error = tostring(pull_err)
      end
    end
  else
    -- No length at all: read until the peer closes, under the same cap.
    while true do
      local block = conn:read_exact(1)
      if not block then break end
      chunks[#chunks + 1] = block
      if #table.concat(chunks) > (opts.max_body or 4194304) then
        out.truncated = true
        break
      end
    end
  end
  out.body = table.concat(chunks)
  out.body_bytes = #out.body
  out.ok = out.status ~= nil and out.status >= 200 and out.status < 300
  conn:note("http-response", string.format("%d %s, %d byte(s)%s", out.status or 0, tostring(reason),
    out.body_bytes, out.truncated and " (truncated)" or ""))
  return out, conn
end

-- The chunked transfer encoding has no fixed length, so a line reader is what
-- reads the chunk sizes and their trailers.
function Wire:read_bytes_until_crlf()
  local out = {}
  for _ = 1, 8192 do
    local byte, err = self:read_exact(1)
    if not byte then return nil, err end
    if byte == "\n" then
      return (string.gsub(table.concat(out), "\r$", ""))
    end
    out[#out + 1] = byte
  end
  return nil, "line longer than 8192 bytes"
end

function M.base64_encode(data)
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local out = {}
  for index = 1, #data, 3 do
    local a, b, c = BYTE(data, index, index + 2)
    local triple = a * 65536 + (b or 0) * 256 + (c or 0)
    local first = math.floor(triple / 262144) % 64 + 1
    local second = math.floor(triple / 4096) % 64 + 1
    local third = math.floor(triple / 64) % 64 + 1
    out[#out + 1] = string.sub(alphabet, first, first)
    out[#out + 1] = string.sub(alphabet, second, second)
    out[#out + 1] = b and string.sub(alphabet, third, third) or "="
    out[#out + 1] = c and string.sub(alphabet, triple % 64 + 1, triple % 64 + 1) or "="
  end
  return table.concat(out)
end

function M.base64_decode(data)
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local values = {}
  for index = 1, #alphabet do values[string.sub(alphabet, index, index)] = index - 1 end
  local clean = string.gsub(tostring(data or ""), "[^A-Za-z0-9%+/=]", "")
  local out, buffer, bits = {}, 0, 0
  for index = 1, #clean do
    local character = string.sub(clean, index, index)
    if character == "=" then break end
    local value = values[character]
    if not value then return nil, "not base64" end
    buffer = buffer * 64 + value
    bits = bits + 6
    if bits >= 8 then
      bits = bits - 8
      out[#out + 1] = CHAR(math.floor(buffer / 2 ^ bits) % 256)
    end
  end
  return table.concat(out)
end


M.ENDPOINTS = ENDPOINTS
M.DEFAULT_CREDENTIALS = DEFAULT_CREDENTIALS
M.HASH_SCHEMES = HASH_SCHEMES
M.INVENTORY_PATHS = INVENTORY_PATHS
M.MANAGEMENT_PERMISSIONS = MANAGEMENT_PERMISSIONS
M.PAYLOAD_INDICATORS = PAYLOAD_INDICATORS
M.PAYLOAD_PATHS = PAYLOAD_PATHS
M.SENSITIVE_KEYS = SENSITIVE_KEYS
M.SENSITIVE_PATHS = SENSITIVE_PATHS
M.classify_payload = classify_payload
M.cluster_name_credential = cluster_name_credential
M.endpoint_by_path = endpoint_by_path
M.fill_path = fill_path
M.find_sensitive = find_sensitive
M.hash_scheme = hash_scheme
M.is_sensitive_key = is_sensitive_key
M.json_encode_simple = json_encode_simple
M.management_call = management_call
M.queue_get_body = queue_get_body
M.redact = redact
M.summarise_call = summarise_call
M.uri_encode = uri_encode

-- ---------------------------------------------------------------------------
-- 9. The management API catalogue
-- ---------------------------------------------------------------------------
-- Every endpoint below was taken from the rabbitmq_management API reference.
-- The catalogue carries the three facts an audit needs before it sends a
-- request: what the endpoint returns, what permission it requires, and whether
-- asking for it can change broker state. The last one is not decoration - a
-- scanner that fetches /api/queues/<vhost>/<queue>/get with the wrong ackmode
-- consumes the messages it was only supposed to look at.

-- Permission levels, weakest first. RabbitMQ grants them per vhost (and per
-- topic, for topic authorization), and the level decides which endpoints answer.
MANAGEMENT_PERMISSIONS = {
  { name = "monitor", rank = 1, exposes = "queues, exchanges, bindings, connections, channels, consumers, "
    .. "node and cluster statistics - the inventory of everything the broker is doing" },
  { name = "management", rank = 2, exposes = "the monitor set plus vhost and permission listings (/api/vhosts, "
    .. "/api/permissions) and the queue action endpoints (get messages, purge, delete)" },
  { name = "policymaker", rank = 3, exposes = "the management set plus policies, parameters and operator policies" },
  { name = "administrator", rank = 4, exposes = "everything: users with their password hashes, definitions "
    .. "import and export, cluster actions" },
}

local function endpoint(method, path, opts)
  return {
    method = method, path = path, purpose = opts.purpose, permission = opts.permission or "monitor",
    changes_state = opts.changes_state or false, reads_payloads = opts.reads_payloads or false,
    returns = opts.returns or "json", note = opts.note,
  }
end

ENDPOINTS = {
  endpoint("GET", "/api/overview", { purpose = "broker version, node inventory, listener ports and their "
    .. "protocols, message/service statistics, enabled plugin list", permission = "monitor",
    returns = "object" }),
  endpoint("GET", "/api/whoami", { purpose = "the identity the request authenticated as (or 401)",
    permission = "monitor", returns = "object" }),
  endpoint("GET", "/api/nodes", { purpose = "per-node inventory: name, type, uptime, memory/disk alarms, "
    .. "application and context paths, TLS listener options", permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/cluster/name", { purpose = "the cluster name, which RabbitMQ uses as the default "
    .. "inter-node authentication identity", permission = "monitor", returns = "object" }),
  endpoint("GET", "/api/queues", { purpose = "every queue with message counts, consumers, durability, "
    .. "arguments and policy", permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/queues/%s", { purpose = "one vhost's queues", permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/queues/%s/%s", { purpose = "one queue: depth, consumer utilisation, head message "
    .. "details, arguments (x-dead-letter-*, x-max-priority, x-queue-type)", permission = "monitor",
    returns = "object" }),
  endpoint("POST", "/api/queues/%s/%s/get", { purpose = "read message payloads from a queue; ackmode decides "
    .. "whether the messages survive (ack_requeue_true requeues them, ack_requeue_false removes them)",
    permission = "management", reads_payloads = true, changes_state = false,
    returns = "array", note = "count is capped by the broker and each request counts as a delivery" }),
  endpoint("DELETE", "/api/queues/%s/%s/contents", { purpose = "purge a queue - all messages are lost",
    permission = "management", changes_state = true, returns = "empty" }),
  endpoint("GET", "/api/exchanges", { purpose = "every exchange: name, type, durability, arguments",
    permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/bindings", { purpose = "every binding in every vhost: the routing graph",
    permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/vhosts", { purpose = "vhost inventory with message counts per vhost",
    permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/vhosts/%s/permissions", { purpose = "which users may access one vhost and at which "
    .. "level", permission = "management", returns = "array" }),
  endpoint("GET", "/api/permissions", { purpose = "the full user/vhost permission matrix",
    permission = "management", returns = "array" }),
  endpoint("GET", "/api/topic-permissions", { purpose = "the topic exchange permission matrix",
    permission = "management", returns = "array" }),
  endpoint("GET", "/api/users", { purpose = "every user with tags and password_hash",
    permission = "administrator", returns = "array" }),
  endpoint("GET", "/api/users/%s", { purpose = "one user with tags and password_hash",
    permission = "administrator", returns = "object" }),
  endpoint("GET", "/api/users/without-permissions", { purpose = "users that exist but cannot reach any vhost",
    permission = "administrator", returns = "array" }),
  endpoint("GET", "/api/policies", { purpose = "every policy: HA mode, TTL, dead-lettering, queue limits",
    permission = "policymaker", returns = "array" }),
  endpoint("GET", "/api/parameters", { purpose = "component parameters: shovel, federation, "
    .. "consistent-hash exchange state", permission = "policymaker", returns = "array" }),
  endpoint("GET", "/api/global-parameters", { purpose = "global parameters, for example cluster name and "
    .. "internal authentication settings", permission = "policymaker", returns = "array" }),
  endpoint("GET", "/api/operator-policies", { purpose = "operator policies (they override user policies)",
    permission = "policymaker", returns = "array" }),
  endpoint("GET", "/api/connections", { purpose = "every open AMQP connection: peer address, user, vhost, "
    .. "client properties, TLS details, frame statistics", permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/channels", { purpose = "every channel with its consumer list, prefetch and rates",
    permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/consumers", { purpose = "every consumer: queue, tag, ack mode, exclusive flag",
    permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/definitions", { purpose = "the whole broker configuration as a downloadable "
    .. "document, including users with password_hash, permissions, policies, queues and bindings",
    permission = "administrator", returns = "object",
    note = "also available per vhost and as an export download" }),
  endpoint("GET", "/api/definitions/%s", { purpose = "one vhost's definitions document",
    permission = "administrator", returns = "object" }),
  endpoint("GET", "/api/healthchecks/node", { purpose = "node health check: the login response, "
    .. "unauthenticated in some deployments", permission = "monitor", returns = "object" }),
  endpoint("GET", "/api/aliveness-test/%s", { purpose = "declares, consumes and deletes a probe queue in the "
    .. "vhost - the only common endpoint that creates broker state on purpose",
    permission = "monitor", changes_state = true, returns = "object" }),
  endpoint("GET", "/api/feature-flags", { purpose = "which feature flags are enabled, which dates the broker",
    permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/extensions", { purpose = "the management plugin's own schema: which endpoints a "
    .. "client may expect", permission = "monitor", returns = "array" }),
  endpoint("GET", "/api/whoami", { purpose = "the authenticated identity", permission = "monitor",
    returns = "object" }),
}

function endpoint_by_path(path)
  for _, entry in ipairs(ENDPOINTS) do
    if entry.path == path then return entry end
  end
  return nil
end

-- The endpoints the management scripts ask for by name, with the URL templates
-- filled in. Keeping the list here means the scripts cannot drift apart in what
-- they consider the inventory.
INVENTORY_PATHS = {
  "/api/overview", "/api/nodes", "/api/cluster/name", "/api/vhosts", "/api/queues",
  "/api/exchanges", "/api/bindings", "/api/connections", "/api/channels", "/api/consumers",
  "/api/feature-flags", "/api/extensions",
}

SENSITIVE_PATHS = {
  "/api/users", "/api/whoami", "/api/permissions", "/api/topic-permissions", "/api/policies",
  "/api/parameters", "/api/global-parameters", "/api/operator-policies", "/api/definitions",
  "/api/healthchecks/node",
}

-- The endpoints that read message payloads. Only one of them can do it without
-- destroying what it read, and the ackmode in the request body is what decides.
PAYLOAD_PATHS = { "/api/queues/%s/%s/get" }

function uri_encode(value)
  local text = tostring(value or "")
  local out = {}
  for index = 1, #text do
    local byte = BYTE(text, index)
    local character = string.sub(text, index, index)
    if (byte >= 65 and byte <= 90) or (byte >= 97 and byte <= 122) or (byte >= 48 and byte <= 57)
      or character == "-" or character == "_" or character == "." or character == "~" then
      out[#out + 1] = character
    else
      out[#out + 1] = string.format("%%%02X", byte)
    end
  end
  return table.concat(out)
end

function fill_path(template, ...)
  local values = { ... }
  local index = 0
  return (string.gsub(template, "%%s", function()
    index = index + 1
    return uri_encode(values[index])
  end))
end

-- ---------------------------------------------------------------------------
-- 10. Credentials
-- ---------------------------------------------------------------------------
-- RabbitMQ ships one documented default credential (guest/guest) that is
-- restricted to localhost since 3.3, and deployments add their own: the cluster
-- name as the inter-node identity, and the names administrators pick. The list
-- below is deliberately short and documented - it is not a wordlist, and every
-- attempt on a broker that does not accept it is a failed login the operator
-- will see in the log.

DEFAULT_CREDENTIALS = {
  { user = "guest", password = "guest", note = "the RabbitMQ default, restricted to localhost since 3.3" },
  { user = "guest", password = "guest", note = "the same pair against the management API" },
  { user = "admin", password = "admin", note = "a name and password administrators commonly pick" },
  { user = "rabbitmq", password = "rabbitmq", note = "the package name as a credential" },
  { user = "user", password = "password", note = "the scaffold pair a project template left behind" },
  { user = "test", password = "test", note = "a staging credential left in production" },
  { user = "monitoring", password = "monitoring", note = "the monitoring account with its name as password" },
}

-- The cluster name is the default inter-node credential in RabbitMQ, and the
-- management API reports it: a client that can read /api/cluster/name without
-- authentication has the name half of the internal authentication pair.
function cluster_name_credential(name)
  if not name or #name == 0 then return nil end
  return { user = name, password = name,
    note = "the cluster name used as the inter-node credential" }
end

-- ---------------------------------------------------------------------------
-- 11. Hashes, secrets and payload indicators
-- ---------------------------------------------------------------------------
-- The management API publishes password hashes. Which scheme produced one is
-- the difference between a credential that has to be cracked and a credential
-- that is one base64 decode away, so the scheme is classified here.

HASH_SCHEMES = {
  { prefix = "rabbit_password_hashing_sha512", scheme = "SHA-512 with a per-user salt and 5,000 iterations",
    strength = "strong", note = "a plugin-provided scheme; an offline attack has to pay the iteration count" },
  { prefix = "rabbit_password_hashing_sha256", scheme = "SHA-256 with a per-user salt and 5,000 iterations",
    strength = "strong", note = "the RabbitMQ 3.6+ default" },
  { prefix = "rabbit_password_hashing_md5", scheme = "MD5 with a per-user salt",
    strength = "weak", note = "retired: MD5 is not a password hash, and a GPU reaches it quickly" },
  { prefix = "rabbit_password_hashing_sha1", scheme = "SHA-1 with a per-user salt", strength = "weak",
    note = "retired for the same reason as the MD5 scheme" },
}

function hash_scheme(hash)
  local text = tostring(hash or "")
  for _, entry in ipairs(HASH_SCHEMES) do
    if string.sub(text, 1, #entry.prefix) == entry.prefix then
      return { id = entry.prefix, scheme = entry.scheme, strength = entry.strength, note = entry.note,
        encoded = string.sub(text, #entry.prefix + 2) }
    end
  end
  -- The pre-3.6 format is "base64(salt)base64(password)" with no prefix at all:
  -- a hash that looks like two base64 blobs is a stored password, not a digest.
  if string.match(text, "^[A-Za-z0-9+/]+=[A-Za-z0-9+/=]*$") and not string.find(text, "%$") then
    return { id = "legacy-base64", scheme = "base64(salt) .. base64(password)", strength = "broken",
      note = "the pre-3.6 format stores an unsalted digest, and the salt travels with it" }
  end
  return { id = "unknown", scheme = "an unrecognised format", strength = "unknown",
    note = "the value was not modified by this script" }
end

-- Keys whose presence in a JSON document is the finding. The management API puts
-- every one of these in a document it serves without authentication on a broker
-- that has lost control of its API permissions.
SENSITIVE_KEYS = {
  password_hash = { severity = "CRITICAL", note = "the stored password hash for a user" },
  password = { severity = "CRITICAL", note = "a password in clear text" },
  secret = { severity = "HIGH", note = "a shared secret" },
  token = { severity = "HIGH", note = "an access token" },
  private_key = { severity = "CRITICAL", note = "a private key" },
  pem = { severity = "CRITICAL", note = "key material in PEM form" },
  amqp_uri = { severity = "HIGH", note = "a connection URI that carries credentials" },
  uri = { severity = "MEDIUM", note = "a URI that may carry credentials" },
  consumer_tag = { severity = "LOW", note = "an identifier that names a consumer" },
  auth_mechanism = { severity = "INFO", note = "the SASL mechanism a connection used" },
  username = { severity = "LOW", note = "an account name" },
  peer_host = { severity = "LOW", note = "a peer address" },
  client_properties = { severity = "LOW", note = "client-supplied connection metadata, which often "
    .. "carries a hostname, a library version or an application name" },
}

-- Every sensitive key in a document, with a redacted preview. The value is never
-- printed: a report that quotes a password hash teaches a reader to grep for it.
function find_sensitive(document, opts)
  opts = opts or {}
  local limit = opts.limit or 64
  local findings = {}
  local function walk(node, path)
    if #findings >= limit or type(node) ~= "table" then return end
    for key, value in pairs(node) do
      local next_path = path == "" and tostring(key) or (path .. "." .. tostring(key))
      local entry = SENSITIVE_KEYS[key]
      if entry then
        findings[#findings + 1] = { path = next_path, key = key, severity = entry.severity,
          note = entry.note, preview = redact(value) }
      end
      if type(value) == "table" then walk(value, next_path) end
    end
  end
  walk(document, "")
  table.sort(findings, function(a, b)
    if a.path == b.path then return false end
    return a.path < b.path
  end)
  return findings
end

-- A value is described, not disclosed: its type, its length, and for a hash the
-- scheme that produced it.
function redact(value)
  if value == nil then return "null" end
  local kind = type(value)
  if kind == "boolean" or kind == "number" then return tostring(value) end
  if kind == "table" then
    local count = 0
    for _ in pairs(value) do count = count + 1 end
    return string.format("%s with %d entr(ies)", kind, count)
  end
  local text = tostring(value)
  if #text == 0 then return "empty string" end
  local scheme = hash_scheme(text)
  if scheme.id ~= "unknown" then
    return string.format("%d character(s), scheme %s (%s)", #text, scheme.id, scheme.strength)
  end
  return string.format("%d character(s), begins %s", #text, string.sub(text, 1, 3) .. "...")
end

function is_sensitive_key(key)
  return SENSITIVE_KEYS[key] ~= nil
end

-- What a message payload can contain. The queue reader runs these over the
-- bodies it read, so a report can say "12 of 20 messages carry a JSON password
-- field" instead of dumping application data into a scan result.
PAYLOAD_INDICATORS = {
  { id = "private-key", severity = "CRITICAL", pattern = "%-%-%-%-%-BEGIN [A-Z ]*PRIVATE KEY%-%-%-%-%-",
    description = "a PEM private key" },
  { id = "jwt", severity = "HIGH", pattern = "eyJ[A-Za-z0-9_%-]+%.eyJ[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+",
    description = "a JSON web token with a readable header and payload" },
  { id = "aws-access-key", severity = "HIGH", pattern = "AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]",
    description = "an AWS access key id" },
  { id = "json-password", severity = "HIGH", pattern = "\"pass[wo]*rd\"%s*:%s*\"[^\"]+\"",
    description = "a password field in a JSON document" },
  { id = "basic-auth", severity = "HIGH", pattern = "Basic [A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/]+=*",
    description = "an HTTP Basic credential" },
  { id = "connection-string", severity = "HIGH", pattern = "amqps?://[^%s/:@]+:[^%s/@]+@",
    description = "an AMQP URI with an embedded password" },
  { id = "email", severity = "LOW", pattern = "[%w%.%-_]+@[%w%-]+%.[%a][%a][%a]*",
    description = "an email address" },
  { id = "iban-or-card", severity = "HIGH", pattern = "%f[%d]%d%d%d%d[ %-]?%d%d%d%d[ %-]?%d%d%d%d[ %-]?%d%d%d%d%f[%D]",
    description = "a sixteen digit number - a payment card or an account identifier" },
  { id = "latency-trace", severity = "LOW", pattern = "trace[_%-]?id",
    description = "a distributed-tracing identifier, which correlates every hop of one request" },
}

-- Classify one payload without printing it: the length, whether it is printable
-- text, the content type it looks like, and which indicators matched.
function classify_payload(data)
  local out = { bytes = #(data or ""), indicators = {}, printable = true, likely_text = false }
  local sample = string.sub(data or "", 1, 8192)
  for index = 1, #sample do
    local byte = BYTE(sample, index)
    if byte < 9 or (byte > 13 and byte < 32) then
      out.printable = false
      break
    end
  end
  out.likely_text = out.printable and #sample > 0
  if out.likely_text then
    out.looks_like_json = string.sub(sample, 1, 1) == "{" or string.sub(sample, 1, 1) == "["
    out.looks_like_xml = string.sub(sample, 1, 5) == "<?xml"
    out.first_line = string.sub(sample, 1, math.min(#sample, 96))
  end
  for _, indicator in ipairs(PAYLOAD_INDICATORS) do
    if string.find(sample, indicator.pattern) then
      out.indicators[#out.indicators + 1] = indicator
    end
  end
  out.severity = "INFO"
  local order = { CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0 }
  for _, indicator in ipairs(out.indicators) do
    if order[indicator.severity] > order[out.severity] then out.severity = indicator.severity end
  end
  return out
end

-- ---------------------------------------------------------------------------
-- 12. Management requests
-- ---------------------------------------------------------------------------
-- One wrapper for every management call, so the script never has to remember
-- whether it authenticated, whether the answer was JSON, or whether the broker
-- asked for a permission it did not have.

function management_call(host, port, path, opts)
  opts = opts or {}
  local method = opts.method or "GET"
  local body = opts.body
  if body and type(body) == "table" then body = M.json_encode_simple(body) end
  local response, conn = M.http_request(host, port, method, path, {
    auth = opts.auth, body = body, connection = opts.connection, timeout_ms = opts.timeout_ms,
    max_body = opts.max_body, host_header = opts.host_header, user_agent = opts.user_agent,
  })
  local out = {
    path = path, method = method, status = response.status, ok = response.ok,
    headers = response.headers, bytes = response.body_bytes, error = response.error,
    truncated = response.truncated, authenticated = opts.auth ~= nil, connection = conn,
    challenge = response.headers and response.headers["www-authenticate"] or nil,
  }
  if response.body and #response.body > 0 then
    local document, json_err = M.json_decode(response.body)
    if document ~= nil then
      out.document = document
      out.json = true
    else
      out.json = false
      out.json_error = json_err
      out.body_preview = string.sub(response.body, 1, 160)
    end
  end
  if out.status == 401 then
    out.verdict = "authentication-required"
  elseif out.status == 403 then
    out.verdict = "authenticated-but-refused"
  elseif out.status == 404 then
    out.verdict = "not-found"
  elseif out.status and out.status >= 200 and out.status < 300 then
    out.verdict = opts.auth and "granted" or "anonymous-granted"
  elseif out.status and out.status >= 500 then
    out.verdict = "server-error"
  elseif not out.status then
    out.verdict = "no-answer"
  else
    out.verdict = "http-" .. tostring(out.status)
  end
  return out
end

-- A tiny encoder, used only for the two request bodies this engine sends: the
-- queue get document and the aliveness test. A full encoder is not needed and
-- half of one is how a request body ends up malformed.
function json_encode_simple(value)
  local kind = type(value)
  if kind == "nil" then return "null" end
  if kind == "boolean" then return value and "true" or "false" end
  if kind == "number" then return tostring(value) end
  if kind == "string" then
    return '"' .. string.gsub(value, '[%c"\\]', function(character)
      if character == '"' then return '\\"' end
      if character == "\\" then return "\\\\" end
      return string.format("\\u%04x", BYTE(character))
    end) .. '"'
  end
  if kind == "table" then
    local is_array = #value > 0
    local parts = {}
    if is_array then
      for _, item in ipairs(value) do parts[#parts + 1] = json_encode_simple(item) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local names = {}
    for name in pairs(value) do names[#names + 1] = name end
    table.sort(names)
    for _, name in ipairs(names) do
      parts[#parts + 1] = json_encode_simple(tostring(name)) .. ":" .. json_encode_simple(value[name])
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

-- The read side of the queue endpoints: ack_requeue_true returns the messages
-- with the requeue flag already set, so the broker puts a copy back exactly as it
-- was. The destructive alternative (ack_requeue_false) is never built here.
function queue_get_body(count, ackmode, encoding)
  count = math.max(1, math.min(math.floor(tonumber(count) or 1), 500))
  local mode = ackmode or "ack_requeue_true"
  if mode ~= "ack_requeue_true" and mode ~= "reject_requeue_true" then
    mode = "ack_requeue_true"
  end
  return { count = count, ackmode = mode, encoding = encoding or "auto" }
end

function summarise_call(call)
  if not call.status then
    return string.format("%s %s: no HTTP answer (%s)", call.method, call.path, tostring(call.error))
  end
  local access = call.verdict == "anonymous-granted" and "without credentials"
    or (call.verdict == "granted" and "with the supplied credentials" or call.verdict)
  return string.format("%s %s: HTTP %d, %s, %d byte(s)", call.method, call.path, call.status, access,
    call.bytes or 0)
end

return M
