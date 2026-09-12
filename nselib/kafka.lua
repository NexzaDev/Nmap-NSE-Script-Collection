--- Apache Kafka wire protocol engine (nselib/kafka.lua)
--
-- This library implements the Kafka protocol the way a broker actually speaks
-- it: a four-byte big-endian frame length followed by a request whose schema is
-- selected by (api_key, api_version), and a response whose schema is selected
-- by the same pair. Every encoder and decoder below is version aware, because
-- a single Kafka cluster will answer ApiVersions v0..v3, Metadata v0..v12 and
-- ListGroups v0..v4 at the same time and a probe that assumes one schema will
-- misparse the others.
--
-- The library deliberately does not implement the whole protocol. It implements
-- the part an unauthenticated audit needs:
--
--   * ApiVersions        - which API versions the broker offers at all
--   * Metadata           - cluster id, controller, broker list, topic topology
--   * DescribeCluster    - the same view through the newer admin API
--   * ListGroups         - every consumer group the broker knows
--   * DescribeGroups     - members, client ids, client hosts, protocols
--   * FindCoordinator    - the group coordinator broker for a group id
--   * OffsetFetch        - committed offsets and lag per partition and group
--   * ListOffsets        - earliest/latest(or high watermark) per partition
--   * Fetch              - a bounded sample of real records (opt-in)
--   * DescribeConfigs    - topic/broker configuration, including what the
--                          broker marks sensitive
--   * CreateTopics       - validate_only calls, which change nothing
--   * DeleteTopics       - used only against names that cannot exist
--   * SaslHandshake      - mechanism list, and the cleartext-policy evidence
--   * SaslAuthenticate   - PLAIN and SCRAM-SHA-256/SCRAM-SHA-512, with a real
--                          client implementation of both mechanisms
--
-- Nothing in this file mutates broker state: CreateTopics is always sent with
-- validate_only set, DeleteTopics is only ever pointed at a random name the
-- caller generated for the probe, and no request ever carries a payload the
-- broker would interpret as a destructive admin operation.
--
-- Authors: Nmap NSE Script Collection
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html

local M = {}

M.VERSION = "1.0.0"

----------------------------------------------------------------------------
-- 1. Numeric helpers
----------------------------------------------------------------------------

local floor = math.floor
local char = string.char
local byte = string.byte
local sub = string.sub
local concat = table.concat
local rep = string.rep

-- Kafka uses unsigned big-endian integers of 8, 16, 32 and 64 bits, plus
-- signed varints (zigzag) and unsigned varints (LEB128) in the flexible
-- (tagged) schema family introduced by KIP-482.
M.INT32_MAX = 2147483647
M.INT32_MIN = -2147483648
M.INT64_MAX = 9223372036854775807

-- A Lua number is a double, so the 64-bit helpers below split every value into
-- two 32-bit halves. That loses precision past 2^53, which no broker field a
-- probe reads (offsets, timestamps in milliseconds, watermarks) ever reaches.
-- Every value that can exceed 2^31 is kept in the float subtype. A host that
-- implements Lua integers as 32-bit quantities (fengari does) wraps integer
-- arithmetic at 2^32, which silently corrupts checksums and ciphers; floats are
-- exact to 2^53, which is far beyond anything these protocols carry.
local function num(v)
  return (v or 0) + 0.0
end

M.num = num

function M.u32(value)
  return num(value) % 4294967296
end

function M.i32(value)
  value = num(value) % 4294967296
  if value >= 2147483648 then value = value - 4294967296 end
  return value
end

function M.hi32(value)
  return floor(num(value) / 4294967296) % 4294967296
end

function M.lo32(value)
  return num(value) % 4294967296
end

function M.join64(hi, lo)
  return num(hi) * 4294967296 + num(lo)
end

-- Hex rendering never goes through string.format("%x"): on a double-only host
-- the integer-subtype check rejects a float even when its value is integral, so
-- the digits are peeled off arithmetically instead.
function M.hex(value, width)
  width = width or 0
  local digits = "0123456789abcdef"
  value = num(value) % 4294967296
  local out = {}
  repeat
    local d = value % 16
    out[#out + 1] = string.sub(digits, d + 1, d + 1)
    value = math.floor(value / 16)
  until value <= 0
  local text = string.reverse(table.concat(out))
  if #text < width then text = rep("0", width - #text) .. text end
  return text
end

-- Integer rendering for the same reason: report fields must never fail because
-- a counter happens to be stored in the float subtype.
function M.int(value)
  value = num(value)
  local neg = value < 0
  if neg then value = -value end
  local text = ""
  repeat
    text = string.sub("0123456789", value % 10 + 1, value % 10 + 1) .. text
    value = math.floor(value / 10)
  until value <= 0
  if neg then text = "-" .. text end
  return text
end

function M.hex64(value)
  return M.hex(M.hi32(value), 8) .. M.hex(M.lo32(value), 8)
end

----------------------------------------------------------------------------
-- 1b. Portable 32-bit bitwise arithmetic
----------------------------------------------------------------------------
--
-- Lua 5.3 integers are 64-bit, but host a Lua VM on top of a double-only
-- runtime and the bitwise operators degrade to signed 32-bit: a value above
-- 2^31 has "no integer representation" and 255 << 24 comes back negative.
-- Ciphers and checksums cannot afford that, so every bit operation below is
-- table driven on nibbles and stays in the closed range [0, 2^32). It is a few
-- hundred nanoseconds slower per call and exactly correct everywhere.

local AND4, OR4, XOR4 = {}, {}, {}
do
  for a = 0, 15 do
    AND4[a], OR4[a], XOR4[a] = {}, {}, {}
    for b = 0, 15 do
      local av, bv, bitv = a, b, 1
      local andv, orv, xorv = 0, 0, 0
      for _ = 1, 4 do
        local abit = av % 2
        local bbit = bv % 2
        if abit == 1 and bbit == 1 then andv = andv + bitv end
        if abit == 1 or bbit == 1 then orv = orv + bitv end
        if abit ~= bbit then xorv = xorv + bitv end
        av = (av - abit) / 2
        bv = (bv - bbit) / 2
        bitv = bitv * 2
      end
      AND4[a][b], OR4[a][b], XOR4[a][b] = andv, orv, xorv
    end
  end
end

local function op32(tbl, a, b)
  a, b = num(a) % 4294967296, num(b) % 4294967296
  local res, scale = 0.0, 1.0
  for _ = 1, 8 do
    local an, bn = a % 16, b % 16
    res = res + tbl[an][bn] * scale
    a = (a - an) / 16
    b = (b - bn) / 16
    scale = scale * 16
  end
  return res
end

local function band32(a, b) return op32(AND4, a, b) end
local function bor32(a, b) return op32(OR4, a, b) end
local function bxor32(a, b) return op32(XOR4, a, b) end
local function bnot32(a) return 4294967295 - num(a) % 4294967296 end
local function shl32(a, n)
  if n <= 0 then return num(a) % 4294967296 end
  if n >= 32 then return 0.0 end
  return (num(a) % 4294967296) * (2 ^ n) % 4294967296
end
local function shr32(a, n)
  if n <= 0 then return num(a) % 4294967296 end
  if n >= 32 then return 0.0 end
  return math.floor((num(a) % 4294967296) / (2 ^ n))
end
local function rotr32(a, n)
  n = n % 32
  if n == 0 then return num(a) % 4294967296 end
  return shl32(a, 32 - n) + shr32(a, n)
end
local function add32(...)
  local sum = 0.0
  for i = 1, select("#", ...) do
    sum = (sum + num(select(i, ...))) % 4294967296
  end
  return sum
end

M.band32, M.bor32, M.bxor32 = band32, bor32, bxor32
M.bnot32, M.shl32, M.shr32, M.rotr32, M.add32 = bnot32, shl32, shr32, rotr32, add32

----------------------------------------------------------------------------
-- 2. Encoding primitives (writer)
----------------------------------------------------------------------------
--
-- Every method returns the writer so calls chain: w:u16(api):u16(ver):raw(...).
-- Kafka strings are INT16 length prefixed byte sequences, "bytes" and record
-- data are INT32 prefixed, and both gain a "+1" compact form (length 0 means
-- null in the flexible schema) once KIP-482 tagging is in play.

function M.writer()
  local w = { parts = {}, len = 0 }
  w.parts = w.parts

  function w:raw(data)
    if data and #data > 0 then
      self.parts[#self.parts + 1] = data
      self.len = self.len + #data
    end
    return self
  end

  function w:u8(v)
    return self:raw(char(math.floor(num(v)) % 256))
  end

  function w:i8(v)
    return self:u8(v)
  end

  function w:bool(v)
    return self:u8(v and 1 or 0)
  end

  function w:u16(v)
    v = num(v) % 65536
    return self:raw(char(floor(v / 256) % 256, v % 256))
  end

  function w:i16(v)
    v = num(v)
    if v < 0 then v = v + 65536 end
    return self:u16(v)
  end

  function w:u32(v)
    v = num(v) % 4294967296
    return self:raw(char(floor(v / 16777216) % 256, floor(v / 65536) % 256,
      floor(v / 256) % 256, v % 256))
  end

  function w:i32(v)
    if v < 0 then v = v + 4294967296 end
    return self:u32(v)
  end

  function w:u64(v)
    return self:u32(M.hi32(v)):u32(M.lo32(v))
  end

  function w:i64(v)
    v = num(v)
    if v < 0 then v = v + 18446744073709551616 end
    return self:u64(v)
  end

  -- Unsigned LEB128, used for array/string lengths and record counts inside a
  -- flexible schema.
  function w:uvarint(v)
    v = num(v) % 4294967296
    local out = {}
    repeat
      local b = v % 128
      v = floor(v / 128)
      if v > 0 then b = b + 128 end
      out[#out + 1] = char(b)
    until v == 0
    return self:raw(concat(out))
  end

  -- Zigzag signed varint (Kafka's record format uses these heavily).
  function w:varint(v)
    if v < 0 then
      return self:uvarint(-(v + 1) * 2 + 1)
    end
    return self:uvarint(v * 2)
  end

  function w:str(s)
    if s == nil then return self:i16(-1) end
    return self:i16(#s):raw(s)
  end

  function w:bytes(s)
    if s == nil then return self:i32(-1) end
    return self:i32(#s):raw(s)
  end

  function w:compact_str(s)
    if s == nil then return self:uvarint(0) end
    return self:uvarint(#s + 1):raw(s)
  end

  function w:compact_bytes(s)
    if s == nil then return self:uvarint(0) end
    return self:uvarint(#s + 1):raw(s)
  end

  -- A non-flexible array is INT32 count followed by the elements; the flexible
  -- form is an unsigned varint of count+1 so that zero means null.
  function w:array(items, encode)
    local n = items and #items or 0
    self:i32(n)
    for i = 1, n do
      encode(self, items[i], i)
    end
    return self
  end

  function w:compact_array(items, encode)
    local n = items and #items or 0
    self:uvarint(n + 1)
    for i = 1, n do
      encode(self, items[i], i)
    end
    return self
  end

  -- Tagged fields are the extension point of the flexible schema. A probe has
  -- nothing to add, so it always writes the empty tag buffer Kafka requires.
  function w:tags()
    return self:u8(0)
  end

  function w:result()
    return concat(self.parts)
  end

  return w
end

----------------------------------------------------------------------------
-- 3. Decoding primitives (reader)
----------------------------------------------------------------------------
--
-- Every reader method signals a short read as (nil, reason) instead of raising,
-- because a truncated response is a normal event for a network probe: the
-- caller has to decide whether to retry, to report the truncation or to give
-- up. Values are returned as (value) on success, and every 64-bit field is
-- returned as a Lua number.

function M.reader(data)
  local r = { data = data or "", pos = 1 }

  function r:remaining()
    return #self.data - self.pos + 1
  end

  function r:eof()
    return self.pos > #self.data
  end

  function r:take(n)
    n = n or 0
    if n < 0 then return nil, "negative length" end
    if self.pos + n - 1 > #self.data then
      return nil, string.format("truncated: wanted %d byte(s), %d left", n, #self.data - self.pos + 1)
    end
    local out = sub(self.data, self.pos, self.pos + n - 1)
    self.pos = self.pos + n
    return out
  end

  function r:u8()
    local b, err = self:take(1)
    if not b then return nil, err end
    return byte(b)
  end

  function r:i8()
    local v, err = self:u8()
    if not v then return nil, err end
    if v >= 128 then v = v - 256 end
    return v
  end

  function r:bool()
    local v, err = self:u8()
    if not v then return nil, err end
    return v ~= 0
  end

  function r:u16()
    local b, err = self:take(2)
    if not b then return nil, err end
    local hi, lo = byte(b, 1, 2)
    return num(hi) * 256 + lo
  end

  function r:i16()
    local v, err = self:u16()
    if not v then return nil, err end
    if v >= 32768 then v = v - 65536 end
    return v
  end

  function r:u32()
    local b, err = self:take(4)
    if not b then return nil, err end
    local a, b2, c, d = byte(b, 1, 4)
    return num(a) * 256 * 256 * 256 + b2 * 65536 + c * 256 + d
  end

  function r:i32()
    local v, err = self:u32()
    if not v then return nil, err end
    if v >= 2147483648 then v = v - 4294967296 end
    return v
  end

  function r:u64()
    local hi, err = self:u32()
    if not hi then return nil, err end
    local lo, err2 = self:u32()
    if not lo then return nil, err2 end
    return M.join64(hi, lo)
  end

  function r:i64()
    local v, err = self:u64()
    if not v then return nil, err end
    if v >= 9223372036854775808 then
      -- Only reachable for the all-ones sentinel values Kafka uses (-1).
      v = v - 18446744073709551616
    end
    return v
  end

  function r:uvarint()
    local shift, value, bytes = 0, 0, 0
    while true do
      local b, err = self:u8()
      if not b then return nil, err end
      bytes = bytes + 1
      if bytes > 5 then return nil, "varint longer than five bytes" end
      value = num(value) + (b % 128) * (2 ^ shift)
      if b < 128 then break end
      shift = shift + 7
    end
    return value
  end

  function r:varint()
    local v, err = self:uvarint()
    if not v then return nil, err end
    if v % 2 == 1 then
      return -(v + 1) / 2
    end
    return v / 2
  end

  -- Zigzag encoded 64-bit deltas appear in record timestamps.
  function r:uvarint64()
    local shift, value, bytes = 0, 0, 0
    while true do
      local b, err = self:u8()
      if not b then return nil, err end
      bytes = bytes + 1
      if bytes > 10 then return nil, "varint64 longer than ten bytes" end
      value = num(value) + (b % 128) * (2 ^ shift)
      if b < 128 then break end
      shift = shift + 7
    end
    return value
  end

  function r:varlong()
    local v, err = self:uvarint64()
    if not v then return nil, err end
    if v % 2 == 1 then return -(v + 1) / 2 end
    return v / 2
  end

  function r:str()
    local n, err = self:i16()
    if not n then return nil, err end
    if n < 0 then return nil end
    return self:take(n)
  end

  function r:bytes()
    local n, err = self:i32()
    if not n then return nil, err end
    if n < 0 then return nil end
    return self:take(n)
  end

  function r:compact_str()
    local n, err = self:uvarint()
    if not n then return nil, err end
    if n == 0 then return nil end
    return self:take(n - 1)
  end

  function r:compact_bytes()
    local n, err = self:uvarint()
    if not n then return nil, err end
    if n == 0 then return nil end
    return self:take(n - 1)
  end

  function r:array(decode)
    local n, err = self:i32()
    if not n then return nil, err end
    if n < 0 then return {} end
    local out = {}
    for i = 1, n do
      local item, derr = decode(self, i)
      if item == nil and derr then return nil, derr end
      out[i] = item
    end
    return out
  end

  function r:compact_array(decode)
    local n, err = self:uvarint()
    if not n then return nil, err end
    if n == 0 then return {} end
    n = n - 1
    local out = {}
    for i = 1, n do
      local item, derr = decode(self, i)
      if item == nil and derr then return nil, derr end
      out[i] = item
    end
    return out
  end

  -- Tagged fields are length prefixed blobs of (tag, size, data). A probe has
  -- to skip them to stay aligned, and records what it saw for the fingerprint.
  function r:tags()
    local count, err = self:uvarint()
    if not count then return nil, err end
    local tags = {}
    for i = 1, count do
      local tag, terr = self:uvarint()
      if not tag then return nil, terr end
      local size, serr = self:uvarint()
      if not size then return nil, serr end
      local payload, perr = self:take(size)
      if not payload then return nil, perr end
      tags[#tags + 1] = { tag = tag, size = size, value = payload }
    end
    return tags
  end

  function r:rest()
    if self.pos > #self.data then return "" end
    local out = sub(self.data, self.pos)
    self.pos = #self.data + 1
    return out
  end

  return r
end

----------------------------------------------------------------------------
-- 4. API catalogue
----------------------------------------------------------------------------
--
-- flexible_from is the first API version that uses the KIP-482 tagged schema.
-- Request/response header versions follow Kafka's rule: a flexible request
-- uses header v2 and its response uses header v1, except ApiVersions, which
-- always answers with a v0 response header so that a client can parse it
-- before it knows the broker's version support.

M.FLEXIBLE_FROM = {
  [0] = 9,   -- Produce
  [1] = 12,  -- Fetch
  [2] = 6,   -- ListOffsets
  [3] = 9,   -- Metadata
  [8] = 8,   -- OffsetCommit
  [9] = 6,   -- OffsetFetch
  [10] = 3,  -- FindCoordinator
  [11] = 6,  -- JoinGroup
  [12] = 4,  -- Heartbeat
  [13] = 4,  -- LeaveGroup
  [14] = 4,  -- SyncGroup
  [15] = 5,  -- DescribeGroups
  [16] = 3,  -- ListGroups
  [18] = 3,  -- ApiVersions
  [19] = 5,  -- CreateTopics
  [20] = 4,  -- DeleteTopics
  [21] = 2,  -- DeleteRecords
  [22] = 2,  -- InitProducerId
  [32] = 4,  -- DescribeConfigs
  [33] = 2,  -- AlterConfigs
  [35] = 2,  -- DescribeLogDirs
  [36] = 2,  -- SaslAuthenticate
  [37] = 3,  -- CreatePartitions
  [42] = 2,  -- DeleteGroups
  [44] = 1,  -- IncrementalAlterConfigs
  [46] = 0,  -- ListPartitionReassignments
  [47] = 0,  -- OffsetDelete
  [50] = 0,  -- DescribeUserScramCredentials
  [60] = 0,  -- DescribeCluster
  [61] = 0,  -- DescribeProducers
  [68] = 0,  -- ConsumerGroupHeartbeat
}

M.API_NAMES = {
  [0] = "Produce", [1] = "Fetch", [2] = "ListOffsets", [3] = "Metadata",
  [8] = "OffsetCommit", [9] = "OffsetFetch", [10] = "FindCoordinator",
  [11] = "JoinGroup", [12] = "Heartbeat", [13] = "LeaveGroup", [14] = "SyncGroup",
  [15] = "DescribeGroups", [16] = "ListGroups", [17] = "SaslHandshake",
  [18] = "ApiVersions", [19] = "CreateTopics", [20] = "DeleteTopics",
  [21] = "DeleteRecords", [22] = "InitProducerId", [32] = "DescribeConfigs",
  [33] = "AlterConfigs", [35] = "DescribeLogDirs", [36] = "SaslAuthenticate",
  [37] = "CreatePartitions", [42] = "DeleteGroups", [44] = "IncrementalAlterConfigs",
  [46] = "ListPartitionReassignments", [47] = "OffsetDelete",
  [50] = "DescribeUserScramCredentials", [60] = "DescribeCluster",
  [61] = "DescribeProducers", [68] = "ConsumerGroupHeartbeat",
}

-- Highest API version this library knows how to encode and decode. A probe
-- negotiates min(local, broker), so an older broker is handled by falling back
-- to the older schema rather than by sending a request it cannot parse.
M.LOCAL_MAX_VERSION = {
  [0] = 9, [1] = 13, [2] = 7, [3] = 12, [8] = 8, [9] = 8, [10] = 4, [11] = 9,
  [12] = 4, [13] = 5, [14] = 5, [15] = 5, [16] = 4, [17] = 1, [18] = 3,
  [19] = 7, [20] = 6, [21] = 2, [22] = 4, [32] = 4, [33] = 2, [35] = 2,
  [36] = 2, [37] = 3, [42] = 2, [44] = 2, [46] = 0, [47] = 0, [50] = 0,
  [60] = 1, [61] = 0,
}

function M.api_name(key)
  return M.API_NAMES[key] or ("Unknown(" .. tostring(key) .. ")")
end

function M.flexible(key, version)
  local from = M.FLEXIBLE_FROM[key]
  if not from then return false end
  return version >= from
end

function M.request_header_version(key, version)
  return M.flexible(key, version) and 2 or 1
end

-- ApiVersions is the one API whose response header never carries tags, because
-- the client must be able to parse the answer before it has learned whether the
-- broker supports tagged headers at all.
function M.response_header_version(key, version)
  if key == 18 then return 0 end
  return M.flexible(key, version) and 1 or 0
end

----------------------------------------------------------------------------
-- 5. Error codes
----------------------------------------------------------------------------
--
-- The numeric error is often the only thing an unauthenticated probe can see,
-- and it is the difference between "the broker has no ACLs at all" and "the
-- broker has ACLs and this principal is not on them".

M.ERRORS = {
  [0]  = { name = "NONE", class = "ok", note = "request succeeded" },
  [1]  = { name = "OFFSET_OUT_OF_RANGE", class = "data", retriable = false },
  [2]  = { name = "CORRUPT_MESSAGE", class = "data" },
  [3]  = { name = "UNKNOWN_TOPIC_OR_PARTITION", class = "missing" },
  [4]  = { name = "INVALID_FETCH_SIZE", class = "client" },
  [5]  = { name = "LEADER_NOT_AVAILABLE", class = "transient", retriable = true },
  [6]  = { name = "NOT_LEADER_OR_FOLLOWER", class = "transient", retriable = true },
  [7]  = { name = "REQUEST_TIMED_OUT", class = "transient", retriable = true },
  [8]  = { name = "BROKER_NOT_AVAILABLE", class = "transient", retriable = true },
  [9]  = { name = "REPLICA_NOT_AVAILABLE", class = "transient", retriable = true },
  [10] = { name = "MESSAGE_TOO_LARGE", class = "client" },
  [11] = { name = "STALE_CONTROLLER_EPOCH", class = "transient", retriable = true },
  [12] = { name = "OFFSET_METADATA_TOO_LARGE", class = "client" },
  [13] = { name = "NETWORK_EXCEPTION", class = "transient", retriable = true },
  [14] = { name = "COORDINATOR_LOAD_IN_PROGRESS", class = "transient", retriable = true },
  [15] = { name = "COORDINATOR_NOT_AVAILABLE", class = "transient", retriable = true },
  [16] = { name = "NOT_COORDINATOR", class = "transient", retriable = true },
  [17] = { name = "INVALID_TOPIC_EXCEPTION", class = "client" },
  [18] = { name = "RECORD_LIST_TOO_LARGE", class = "client" },
  [19] = { name = "NOT_ENOUGH_REPLICAS", class = "transient", retriable = true },
  [20] = { name = "NOT_ENOUGH_REPLICAS_AFTER_APPEND", class = "transient", retriable = true },
  [21] = { name = "INVALID_REQUIRED_ACKS", class = "client" },
  [22] = { name = "ILLEGAL_GENERATION", class = "group" },
  [23] = { name = "INCONSISTENT_GROUP_PROTOCOL", class = "group" },
  [24] = { name = "INVALID_GROUP_ID", class = "client" },
  [25] = { name = "UNKNOWN_MEMBER_ID", class = "group" },
  [26] = { name = "INVALID_SESSION_TIMEOUT", class = "client" },
  [27] = { name = "REBALANCE_IN_PROGRESS", class = "group", retriable = true },
  [28] = { name = "INVALID_COMMIT_OFFSET_SIZE", class = "client" },
  [29] = { name = "TOPIC_AUTHORIZATION_FAILED", class = "authz" },
  [30] = { name = "GROUP_AUTHORIZATION_FAILED", class = "authz" },
  [31] = { name = "CLUSTER_AUTHORIZATION_FAILED", class = "authz" },
  [32] = { name = "INVALID_TIMESTAMP", class = "client" },
  [33] = { name = "UNSUPPORTED_SASL_MECHANISM", class = "auth" },
  [34] = { name = "ILLEGAL_SASL_STATE", class = "auth" },
  [35] = { name = "UNSUPPORTED_VERSION", class = "client" },
  [36] = { name = "TOPIC_ALREADY_EXISTS", class = "conflict" },
  [37] = { name = "INVALID_PARTITIONS", class = "client" },
  [38] = { name = "INVALID_REPLICATION_FACTOR", class = "client" },
  [39] = { name = "INVALID_REPLICA_ASSIGNMENT", class = "client" },
  [40] = { name = "INVALID_CONFIG", class = "client" },
  [41] = { name = "NOT_CONTROLLER", class = "transient", retriable = true },
  [42] = { name = "INVALID_REQUEST", class = "client" },
  [43] = { name = "UNSUPPORTED_FOR_MESSAGE_FORMAT", class = "client" },
  [44] = { name = "POLICY_VIOLATION", class = "authz" },
  [45] = { name = "OUT_OF_ORDER_SEQUENCE_NUMBER", class = "producer" },
  [46] = { name = "DUPLICATE_SEQUENCE_NUMBER", class = "producer" },
  [47] = { name = "INVALID_PRODUCER_EPOCH", class = "producer" },
  [48] = { name = "INVALID_TXN_STATE", class = "transaction" },
  [49] = { name = "INVALID_PRODUCER_ID_MAPPING", class = "transaction" },
  [50] = { name = "INVALID_TRANSACTION_TIMEOUT", class = "transaction" },
  [51] = { name = "CONCURRENT_TRANSACTIONS", class = "transaction", retriable = true },
  [52] = { name = "TRANSACTION_COORDINATOR_FENCED", class = "transaction" },
  [53] = { name = "TRANSACTIONAL_ID_AUTHORIZATION_FAILED", class = "authz" },
  [54] = { name = "SECURITY_DISABLED", class = "auth" },
  [55] = { name = "OPERATION_NOT_ATTEMPTED", class = "transient" },
  [56] = { name = "KAFKA_STORAGE_ERROR", class = "storage", retriable = true },
  [57] = { name = "LOG_DIR_NOT_FOUND", class = "storage" },
  [58] = { name = "SASL_AUTHENTICATION_FAILED", class = "auth" },
  [59] = { name = "UNKNOWN_PRODUCER_ID", class = "producer" },
  [60] = { name = "REASSIGNMENT_IN_PROGRESS", class = "admin" },
  [61] = { name = "DELEGATION_TOKEN_AUTH_DISABLED", class = "auth" },
  [62] = { name = "DELEGATION_TOKEN_NOT_FOUND", class = "auth" },
  [63] = { name = "DELEGATION_TOKEN_OWNER_MISMATCH", class = "auth" },
  [64] = { name = "DELEGATION_TOKEN_REQUEST_NOT_ALLOWED", class = "auth" },
  [65] = { name = "DELEGATION_TOKEN_AUTHORIZATION_FAILED", class = "authz" },
  [66] = { name = "DELEGATION_TOKEN_EXPIRED", class = "auth" },
  [67] = { name = "INVALID_PRINCIPAL_TYPE", class = "client" },
  [68] = { name = "NON_EMPTY_GROUP", class = "group" },
  [69] = { name = "GROUP_ID_NOT_FOUND", class = "group" },
  [70] = { name = "FETCH_SESSION_ID_NOT_FOUND", class = "client" },
  [71] = { name = "INVALID_FETCH_SESSION_EPOCH", class = "client" },
  [72] = { name = "LISTENER_NOT_FOUND", class = "admin" },
  [73] = { name = "TOPIC_DELETION_DISABLED", class = "admin" },
  [74] = { name = "FENCED_LEADER_EPOCH", class = "transient", retriable = true },
  [75] = { name = "UNKNOWN_LEADER_EPOCH", class = "transient", retriable = true },
  [76] = { name = "UNSUPPORTED_COMPRESSION_TYPE", class = "client" },
  [77] = { name = "STALE_BROKER_EPOCH", class = "transient", retriable = true },
  [78] = { name = "OFFSET_NOT_AVAILABLE", class = "transient", retriable = true },
  [79] = { name = "MEMBER_ID_REQUIRED", class = "group" },
  [80] = { name = "PREFERRED_LEADER_NOT_AVAILABLE", class = "transient", retriable = true },
  [81] = { name = "GROUP_MAX_SIZE_REACHED", class = "group" },
  [82] = { name = "FENCED_INSTANCE_ID", class = "group" },
  [83] = { name = "ELIGIBLE_LEADERS_NOT_AVAILABLE", class = "transient", retriable = true },
  [84] = { name = "ELECTION_NOT_NEEDED", class = "admin" },
  [85] = { name = "NO_REASSIGNMENT_IN_PROGRESS", class = "admin" },
  [86] = { name = "GROUP_SUBSCRIBED_TO_TOPIC", class = "group" },
  [87] = { name = "INVALID_RECORD", class = "data" },
  [88] = { name = "UNSTABLE_OFFSET_COMMIT", class = "group", retriable = true },
  [89] = { name = "THROTTLING_QUOTA_EXCEEDED", class = "quota", retriable = true },
  [90] = { name = "PRODUCER_FENCED", class = "producer" },
  [91] = { name = "RESOURCE_NOT_FOUND", class = "missing" },
  [92] = { name = "DUPLICATE_RESOURCE", class = "conflict" },
  [93] = { name = "UNACCEPTABLE_CREDENTIAL", class = "auth" },
  [94] = { name = "INCONSISTENT_VOTER_SET", class = "admin" },
  [95] = { name = "INVALID_UPDATE_VERSION", class = "admin" },
  [96] = { name = "FEATURE_UPDATE_FAILED", class = "admin" },
  [97] = { name = "PRINCIPAL_DESERIALIZATION_FAILURE", class = "auth" },
  [100] = { name = "UNKNOWN_TOPIC_ID", class = "missing" },
  [101] = { name = "DUPLICATE_BROKER_REGISTRATION", class = "admin" },
  [102] = { name = "BROKER_ID_NOT_REGISTERED", class = "admin" },
  [103] = { name = "INCONSISTENT_TOPIC_ID", class = "data" },
  [104] = { name = "INCONSISTENT_CLUSTER_ID", class = "data" },
  [105] = { name = "TRANSACTIONAL_ID_NOT_FOUND", class = "transaction" },
  [106] = { name = "FETCH_SESSION_TOPIC_ID_ERROR", class = "client" },
  [107] = { name = "INELIGIBLE_REPLICA", class = "cluster" },
  [108] = { name = "NEW_LEADER_ELECTED", class = "transient", retriable = true },
}

function M.error_name(code)
  local entry = M.ERRORS[code]
  if entry then return entry.name end
  return "UNKNOWN_ERROR_" .. tostring(code)
end

function M.error_class(code)
  local entry = M.ERRORS[code]
  if entry then return entry.class end
  return "unknown"
end

function M.error_text(code)
  local entry = M.ERRORS[code]
  if not entry then return "unknown error " .. tostring(code) end
  local parts = { entry.name, "(" .. tostring(code) .. ")" }
  if entry.class ~= "ok" then parts[#parts + 1] = "[" .. entry.class .. "]" end
  if entry.retriable then parts[#parts + 1] = "retriable" end
  if entry.note then parts[#parts + 1] = entry.note end
  return concat(parts, " ")
end

-- An unauthenticated probe reads authorization errors as a positive signal:
-- somebody configured ACLs, and the anonymous principal is not on them.
M.AUTHZ_ERRORS = {
  [29] = true, [30] = true, [31] = true, [44] = true, [53] = true, [65] = true,
}

function M.is_authz_error(code)
  return M.AUTHZ_ERRORS[code] == true
end

----------------------------------------------------------------------------
-- 6. Connection handling
----------------------------------------------------------------------------
--
-- Kafka is a strict request/response protocol over a single TCP connection:
-- every request carries a correlation id and the broker echoes it in the
-- response header. Matching on that id is what makes it safe to reuse one
-- socket for a long probe, and it is also what detects a broker that answers
-- asynchronously or reassembles frames wrongly.

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local math = require "math"
local os = require "os"

function M.new_connection(host, port, opts)
  opts = opts or {}
  local conn = {
    host = host,
    port = port,
    timeout_ms = opts.timeout_ms or 5000,
    client_id = opts.client_id or "nmap-nse-kafka",
    correlation = 0,
    buf = "",
    transcript = {},
    stats = { requests = 0, responses = 0, timeouts = 0, errors = 0, bytes_out = 0, bytes_in = 0 },
    versions = {},
    negotiated = false,
    closed = false,
    api_check = opts.api_check,
    debug = opts.debug,
  }

  local sock = nmap.new_socket("tcp")
  if not sock then
    conn.last_error = "socket creation failed"
    return conn
  end
  sock:set_timeout(conn.timeout_ms)
  local ok, err = sock:connect(host, port)
  if not ok then
    conn.last_error = "connect failed: " .. tostring(err)
    return conn
  end
  conn.sock = sock

  -- A frame is a four byte big-endian length followed by the payload. The
  -- socket API may hand back fewer bytes than asked for (and a real broker may
  -- split a frame across segments), so bytes are accumulated until the frame is
  -- complete or the read times out.
  function conn:read_exact(n)
    while #self.buf < n do
      -- NSE's socket contract is (true, data) | (false, error). The status has
      -- to be captured separately: a single variable assignment would bind the
      -- boolean true instead of the bytes that were received.
      local ok, chunk = self.sock:receive_bytes(n - #self.buf)
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
    end
    if #self.buf < n then
      return nil, string.format("connection closed with %d of %d byte(s)", #self.buf, n)
    end
    local out = string.sub(self.buf, 1, n)
    self.buf = string.sub(self.buf, n + 1)
    self.stats.bytes_in = self.stats.bytes_in + n
    return out
  end

  function conn:close()
    if self.sock and not self.closed then
      self.sock:close()
      self.closed = true
    end
    return true
  end

  return conn
end

-- Build a complete request frame for (key, version, body).
function M.build_request(key, version, correlation, client_id, body)
  local w = M.writer()
  local header_version = M.request_header_version(key, version)
  w:u16(key):u16(version):i32(correlation)
  if header_version == 2 then
    w:compact_str(client_id or ""):tags()
  else
    w:str(client_id or "")
  end
  w:raw(body or "")
  local payload = w:result()
  local frame = M.writer():u32(#payload):raw(payload):result()
  return frame, payload
end

-- Send a request and read exactly one response. Returns the response payload
-- (header already consumed) plus metadata, or nil and a reason. Truncated and
-- mismatched responses are reported, never silently accepted: a probe that
-- treated a partial frame as a valid answer would invent conclusions.
function M.exchange(conn, key, version, body)
  if not conn.sock or conn.closed then
    return nil, "not connected"
  end
  conn.correlation = conn.correlation + 1
  local correlation = conn.correlation
  local frame = M.build_request(key, version, correlation, conn.client_id, body)

  local entry = {
    api = key,
    api_name = M.api_name(key),
    version = version,
    correlation = correlation,
    request_bytes = #frame,
  }
  conn.transcript[#conn.transcript + 1] = entry

  local ok, serr = conn.sock:send(frame)
  if not ok then
    entry.error = tostring(serr)
    conn.stats.errors = conn.stats.errors + 1
    return nil, "send failed: " .. tostring(serr), entry
  end
  conn.stats.requests = conn.stats.requests + 1
  conn.stats.bytes_out = conn.stats.bytes_out + #frame

  local len_hex, err = conn:read_exact(4)
  if not len_hex then
    entry.error = err
    return nil, err, entry
  end
  local len = (string.byte(len_hex, 1) * 256 + string.byte(len_hex, 2)) * 65536
    + string.byte(len_hex, 3) * 256 + string.byte(len_hex, 4)
  entry.response_bytes = len
  if len < 4 then
    conn.stats.errors = conn.stats.errors + 1
    entry.error = "response frame shorter than a correlation id"
    return nil, entry.error, entry
  end
  if len > 100 * 1024 * 1024 then
    conn.stats.errors = conn.stats.errors + 1
    entry.error = "response frame absurdly large (" .. tostring(len) .. " bytes)"
    return nil, entry.error, entry
  end

  local payload, perr = conn:read_exact(len)
  if not payload then
    entry.error = perr
    return nil, perr, entry
  end
  conn.stats.responses = conn.stats.responses + 1

  local r = M.reader(payload)
  local echoed, cerr = r:i32()
  if not echoed then
    entry.error = "truncated response header: " .. tostring(cerr)
    conn.stats.errors = conn.stats.errors + 1
    return nil, entry.error, entry
  end
  if echoed ~= correlation then
    entry.error = string.format("correlation mismatch: sent %d, broker echoed %d", correlation, echoed)
    conn.stats.errors = conn.stats.errors + 1
    return nil, entry.error, entry
  end
  if M.response_header_version(key, version) == 1 then
    local tags, terr = r:tags()
    if not tags then
      entry.error = "truncated response header tags"
      conn.stats.errors = conn.stats.errors + 1
      return nil, entry.error, entry
    end
    entry.header_tags = #tags
  end

  entry.ok = true
  return r, nil, entry
end

----------------------------------------------------------------------------
-- 7. Version negotiation
----------------------------------------------------------------------------
--
-- The first thing a probe must do is ask the broker what it supports, because
-- the answer decides which schemas every later request uses. ApiVersions v0 is
-- the universal lowest common denominator: its request body is empty and its
-- response is parseable by any broker from 0.10.0 onwards.

function M.negotiate(conn, opts)
  opts = opts or {}
  local r, err, entry = M.exchange(conn, 18, 0, "")
  if not r then
    return nil, err, entry
  end
  local error_code = r:i16()
  local keys, kerr = r:array(function(rr)
    local k = rr:i16()
    local min = rr:i16()
    local max = rr:i16()
    if k == nil or min == nil or max == nil then return nil, "truncated api key entry" end
    return { key = k, min = min, max = max, name = M.api_name(k) }
  end)
  if not keys then
    return nil, kerr or "truncated api versions response", entry
  end
  local throttle = r:i32()

  local versions = {}
  for _, item in ipairs(keys) do
    versions[item.key] = { min = item.min, broker_max = item.max, name = item.name }
  end
  conn.versions = versions
  conn.negotiated = true
  conn.throttle_ms = throttle
  conn.api_error = error_code

  local summary = {
    error_code = error_code,
    error_name = M.error_name(error_code),
    throttle_ms = throttle,
    count = #keys,
    keys = keys,
    versions = versions,
    body_left = r:remaining(),
  }
  return summary, nil, entry
end

-- The version this library should use for an API on this broker: the newest
-- schema both sides understand. nil means the broker does not offer the API at
-- all, which is itself a finding (an old broker, or AclAuthorizer rejecting the
-- whole API surface).
function M.version_for(conn, key, preference)
  local local_max = M.LOCAL_MAX_VERSION[key]
  if not local_max then return nil end
  local broker = conn.versions[key]
  if not broker then
    if conn.negotiated then return nil end
    return preference or local_max
  end
  local chosen = math.min(local_max, broker.broker_max)
  if broker.min and chosen < broker.min then return nil end
  return chosen
end

function M.version_table(conn)
  local rows = {}
  for key, local_max in pairs(M.LOCAL_MAX_VERSION) do
    local broker = conn.versions[key]
    rows[#rows + 1] = {
      key = key,
      name = M.api_name(key),
      local_max = local_max,
      broker_min = broker and broker.min,
      broker_max = broker and broker.broker_max,
      chosen = M.version_for(conn, key),
    }
  end
  table.sort(rows, function(a, b) return a.key < b.key end)
  return rows
end

----------------------------------------------------------------------------
-- 7b. Version aware read helpers
----------------------------------------------------------------------------
--
-- `obj:method` is only valid when it is immediately called, so
-- `(flexible and rd:compact_array or rd:array)` is a syntax error, not a
-- ternary. Behind a flag every read goes through one of these helpers instead.

function M.read_string(rd, flexible)
  if flexible then return rd:compact_str() end
  return rd:str()
end

function M.read_bytes(rd, flexible)
  if flexible then return rd:compact_bytes() end
  return rd:bytes()
end

function M.read_array(rd, flexible, decode)
  if flexible then return rd:compact_array(decode) end
  return rd:array(decode)
end

----------------------------------------------------------------------------
-- 8. Metadata
----------------------------------------------------------------------------
--
-- A Metadata request with a null topic array means "everything the cluster
-- knows". That single request is the difference between a probe that guesses
-- topic names and one that enumerates the real topology: internal topics
-- included, partition leaders, replicas and the in-sync set.

function M.metadata(conn, topics, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 3)
  if not version then return { ok = false, error = "Metadata API not offered by broker" } end
  local flex = M.flexible(3, version)

  local w = M.writer()
  if topics == nil then
    -- A null topic array is the protocol's "all topics" wildcard from v1
    -- onwards. In the flexible schema null is an unsigned varint of zero; the
    -- classic schema spells it as an INT32 of -1.
    if version == 0 then return { ok = false, error = "Metadata v0 cannot request all topics" } end
    if flex then w:uvarint(0) else w:i32(-1) end
  elseif flex then
    -- The topic list is an array of strings, so there is no per-element tag
    -- buffer here; only the request itself ends with one.
    w:compact_array(topics, function(ww, name) ww:compact_str(name) end)
  else
    w:array(topics, function(ww, name) ww:str(name) end)
  end
  if version >= 4 then w:bool(opts.auto_create == true) end
  if version >= 8 then
    w:bool(opts.cluster_authorized_operations == true)
    w:bool(opts.topic_authorized_operations == true)
  end
  if flex then w:tags() end

  local r, err = M.exchange(conn, 3, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version, flexible = flex, topics_requested = topics == nil and "all" or #topics }
  if version >= 3 then
    out.throttle_ms = r:i32()
  end
  local brokers = r[flex and "compact_array" or "array"](r, function(rr)
    local node_id = rr:i32()
    local host =M.read_string(rr, flex)local port = rr:i32()
    local rack = (version >= 1) and M.read_string(rr, flex) or nil
    if node_id == nil or host == nil or port == nil then return nil, "truncated broker entry" end
    if flex then rr:tags() end
    return { node_id = node_id, host = host, port = port, rack = rack }
  end)
  if not brokers then return { ok = false, error = "truncated broker list", version = version } end
  out.brokers = brokers
  if version >= 2 then out.cluster_id =M.read_string(r, flex)end
  if version >= 1 then out.controller_id = r:i32() end

  local topic_list = r[flex and "compact_array" or "array"](r, function(rr)
    local ec = rr:i16()
    local name =M.read_string(rr, flex)local topic_id = version >= 10 and rr:take(16) or nil
    local is_internal = version >= 1 and rr:bool() or false
    local partitions = M.read_array(rr, flex, function(r3)
      local perr = r3:i16()
      local index = r3:i32()
      local leader = r3:i32()
      local epoch = version >= 7 and r3:i32() or -1
      local replicas = r3[flex and "compact_array" or "array"](r3, function(r4) return r4:i32() end)
      local isr = r3[flex and "compact_array" or "array"](r3, function(r4) return r4:i32() end)
      local offline = version >= 5 and r3[flex and "compact_array" or "array"](r3, function(r4) return r4:i32() end) or {}
      if flex then r3:tags() end
      if index == nil or leader == nil then return nil, "truncated partition entry" end
      return {
        error_code = perr, error_name = M.error_name(perr or 0), index = index,
        leader_id = leader, leader_epoch = epoch,
        replicas = replicas or {}, isr = isr or {}, offline_replicas = offline or {},
      }
    end)
    local authorized = version >= 8 and rr:i32() or nil
    if flex then rr:tags() end
    return {
      error_code = ec, error_name = M.error_name(ec or 0), name = name, topic_id = topic_id,
      is_internal = is_internal, partitions = partitions or {}, authorized_operations = authorized,
    }
  end)
  if not topic_list then return { ok = false, error = "truncated topic list", version = version } end
  out.topics = topic_list
  if version >= 8 and version <= 10 then out.cluster_authorized_operations = r:i32() end
  if version >= 13 then
    out.error_code = r:i16()
    out.error_name = M.error_name(out.error_code or 0)
  end
  if flex then out.tail_tags = r:tags() end
  out.trailing_bytes = r:remaining()
  return out
end

----------------------------------------------------------------------------
-- 9. DescribeCluster (KIP-700)
----------------------------------------------------------------------------
--
-- Newer brokers answer an explicit cluster description with the cluster id and
-- the full broker inventory, without the caller having to ask for topics. It is
-- flexible from v0, so it is also a good probe for whether a broker really
-- implements the modern schema its ApiVersions response advertises.

function M.describe_cluster(conn, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 60)
  if not version then return { ok = false, error = "DescribeCluster API not offered by broker" } end

  local w = M.writer()
  w:bool(opts.include_authorized_operations == true)
  if version >= 1 then w:i8(opts.endpoint_type or 1) end
  w:tags()

  local r, err = M.exchange(conn, 60, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version }
  out.throttle_ms = r:i32()
  out.error_code = r:i16()
  out.error_name = M.error_name(out.error_code or 0)
  out.error_message = r:compact_str()
  if version >= 1 then out.endpoint_type = r:i8() end
  out.cluster_id = r:compact_str()
  out.controller_id = r:i32()
  out.brokers = r:compact_array(function(rr)
    local id = rr:i32()
    local host = rr:compact_str()
    local port = rr:i32()
    local rack = rr:compact_str()
    local fenced = version >= 2 and rr:bool() or nil
    rr:tags()
    if id == nil or port == nil then return nil, "truncated describe cluster broker" end
    return { broker_id = id, host = host, port = port, rack = rack, is_fenced = fenced }
  end) or {}
  out.cluster_authorized_operations = r:i32()
  out.trailing_bytes = r:remaining()
  return out
end

----------------------------------------------------------------------------
-- 10. Consumer group APIs
----------------------------------------------------------------------------
--
-- Group metadata is the part of a Kafka cluster that leaks the most: group
-- names, the protocol each group speaks, every member id, the client id each
-- member reports and the host it connects from. None of it is secret by
-- design, which is exactly why it must not be exposed without authentication.

function M.list_groups(conn, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 16)
  if not version then return { ok = false, error = "ListGroups API not offered by broker" } end
  local flex = M.flexible(16, version)

  local w = M.writer()
  -- StatesFilter is not nullable: the field is always present from v4 onwards,
  -- and an empty filter is written as an empty array (length 0 in the classic
  -- schema, an unsigned varint of 1 in the compact one).
  if version >= 4 then
    local states = opts.states or {}
    if flex then
      w:compact_array(states, function(ww, s) ww:compact_str(s) end)
    else
      w:array(states, function(ww, s) ww:str(s) end)
    end
  end
  if flex then w:tags() end

  local r, err = M.exchange(conn, 16, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version }
  if version >= 1 then out.throttle_ms = r:i32() end
  out.error_code = r:i16()
  out.error_name = M.error_name(out.error_code or 0)
  local groups = r[flex and "compact_array" or "array"](r, function(rr)
    local id =M.read_string(rr, flex)local protocol_type =M.read_string(rr, flex)local state = version >= 4 and M.read_string(rr, flex) or nil
    local group_type = version >= 5 and M.read_string(rr, flex) or nil
    if flex then rr:tags() end
    if id == nil then return nil, "truncated group entry" end
    return { group_id = id, protocol_type = protocol_type or "", state = state, group_type = group_type }
  end)
  if not groups then return { ok = false, error = "truncated group list", version = version } end
  out.groups = groups
  out.trailing_bytes = r:remaining()
  return out
end

function M.describe_groups(conn, names, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 15)
  if not version then return { ok = false, error = "DescribeGroups API not offered by broker" } end
  local flex = M.flexible(15, version)

  local w = M.writer()
  if flex then
    w:compact_array(names, function(ww, n) ww:compact_str(n) end)
  else
    w:array(names, function(ww, n) ww:str(n) end)
  end
  if version >= 3 then w:bool(opts.include_authorized_operations == true) end
  if flex then w:tags() end

  local r, err = M.exchange(conn, 15, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version }
  if version >= 1 then out.throttle_ms = r:i32() end
  local groups = r[flex and "compact_array" or "array"](r, function(rr)
    local ec = rr:i16()
    local error_message = version >= 6 and M.read_string(rr, flex) or nil
    local group_id =M.read_string(rr, flex)local state =M.read_string(rr, flex)local protocol_type =M.read_string(rr, flex)local protocol_data =M.read_string(rr, flex)local members = M.read_array(rr, flex, function(r3)
      local member_id =M.read_string(r3, flex)local instance_id = version >= 4 and M.read_string(r3, flex) or nil
      local client_id =M.read_string(r3, flex)local client_host =M.read_string(r3, flex)local member_metadata =M.read_bytes(r3, flex)local member_assignment =M.read_bytes(r3, flex)if flex then r3:tags() end
      if member_id == nil then return nil, "truncated member entry" end
      return {
        member_id = member_id, group_instance_id = instance_id, client_id = client_id,
        client_host = client_host, metadata_bytes = member_metadata and #member_metadata or 0,
        assignment_bytes = member_assignment and #member_assignment or 0,
        member_metadata = member_metadata, member_assignment = member_assignment,
      }
    end)
    local authorized = version >= 3 and rr:i32() or nil
    if flex then rr:tags() end
    if group_id == nil then return nil, "truncated group description" end
    return {
      error_code = ec, error_name = M.error_name(ec or 0), error_message = error_message,
      group_id = group_id, state = state, protocol_type = protocol_type,
      protocol_data = protocol_data, members = members or {}, authorized_operations = authorized,
    }
  end)
  if not groups then return { ok = false, error = "truncated group descriptions", version = version } end
  out.groups = groups
  out.trailing_bytes = r:remaining()
  return out
end

function M.find_coordinator(conn, key, opts)
  opts = opts or {}
  local version = opts.version or (M.version_for(conn, 10, 3) or 1)
  local flex = M.flexible(10, version)

  local w = M.writer()
  w:str(key)
  if version >= 1 then w:i8(opts.key_type or 0) end
  if flex then w:tags() end

  local r, err = M.exchange(conn, 10, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version, key = key }
  if version >= 1 then out.throttle_ms = r:i32() end
  if version <= 3 then
    out.error_code = r:i16()
    out.error_name = M.error_name(out.error_code or 0)
    if version >= 1 then out.error_message =M.read_string(r, flex)end
    out.node_id = r:i32()
    out.host =M.read_string(r, flex)out.port = r:i32()
  else
    out.coordinators = r:compact_array(function(rr)
      local k = rr:compact_str()
      local node = rr:i32()
      local host = rr:compact_str()
      local port = rr:i32()
      local ec = rr:i16()
      local msg = rr:compact_str()
      rr:tags()
      return { key = k, node_id = node, host = host, port = port, error_code = ec,
        error_name = M.error_name(ec or 0), error_message = msg }
    end) or {}
    local first = out.coordinators[1]
    if first then
      out.node_id, out.host, out.port = first.node_id, first.host, first.port
      out.error_code, out.error_name = first.error_code, first.error_name
    end
  end
  out.trailing_bytes = r:remaining()
  return out
end

function M.offset_fetch(conn, group, topics, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 9)
  if not version then return { ok = false, error = "OffsetFetch API not offered by broker" } end
  local flex = M.flexible(9, version)

  local w = M.writer()
  if version >= 8 then
    w:compact_array({ { group_id = group, topics = topics } }, function(ww, entry)
      ww:compact_str(entry.group_id)
      if entry.topics == nil then
        ww:uvarint(0)
      else
        ww:compact_array(entry.topics, function(w3, topic)
          w3:compact_str(topic.name)
          w3:compact_array(topic.partitions, function(w4, index) w4:i32(index) end)
          w3:tags()
        end)
      end
      ww:tags()
    end)
    w:bool(opts.require_stable == true)
    w:tags()
  else
    w:str(group)
    if topics == nil then
      if version < 2 then return { ok = false, error = "OffsetFetch v0/v1 cannot request all partitions" } end
      w:i32(-1)
    elseif flex then
      w:compact_array(topics, function(ww, topic)
        ww:compact_str(topic.name)
        ww:compact_array(topic.partitions, function(w3, index) w3:i32(index) end)
        ww:tags()
      end)
    else
      w:array(topics, function(ww, topic)
        ww:str(topic.name)
        ww:array(topic.partitions, function(w3, index) w3:i32(index) end)
      end)
    end
    if flex then w:tags() end
  end

  local r, err = M.exchange(conn, 9, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version, group_id = group }
  if version >= 3 then out.throttle_ms = r:i32() end

  local function read_partition(rr)
    local index = rr:i32()
    local offset = rr:i64()
    local epoch = version >= 5 and rr:i32() or -1
    local metadata =M.read_string(rr, flex)local ec = rr:i16()
    if flex then rr:tags() end
    if index == nil or offset == nil then return nil, "truncated offset entry" end
    return { partition = index, committed_offset = offset, leader_epoch = epoch,
      metadata = metadata, error_code = ec, error_name = M.error_name(ec or 0) }
  end

  if version >= 8 then
    out.groups = r:compact_array(function(rr)
      local gid = rr:compact_str()
      local tlist = rr:compact_array(function(r3)
        local name = rr and r3:compact_str()
        local partitions = r3:compact_array(read_partition)
        r3:tags()
        return { name = name, partitions = partitions or {} }
      end)
      local ec = rr:i16()
      rr:tags()
      return { group_id = gid, topics = tlist or {}, error_code = ec, error_name = M.error_name(ec or 0) }
    end) or {}
    local first = out.groups[1]
    if first then
      out.topics = first.topics
      out.error_code = first.error_code
      out.error_name = first.error_name
    end
  else
    local topics_out = r[flex and "compact_array" or "array"](r, function(rr)
      local name =M.read_string(rr, flex)local partitions = M.read_array(rr, flex, read_partition)
      if flex then rr:tags() end
      return { name = name, partitions = partitions or {} }
    end)
    out.topics = topics_out or {}
    if version >= 2 then
      out.error_code = r:i16()
      out.error_name = M.error_name(out.error_code or 0)
    end
  end
  out.trailing_bytes = r:remaining()
  return out
end

function M.list_offsets(conn, entries, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 2)
  if not version then return { ok = false, error = "ListOffsets API not offered by broker" } end
  local flex = M.flexible(2, version)

  local w = M.writer()
  w:i32(opts.replica_id or -1)
  if version >= 2 then w:i8(opts.isolation_level or 0) end
  local function write_topics(ww)
    ww[flex and "compact_array" or "array"](ww, entries, function(w3, topic)
      if flex then w3:compact_str(topic.name) else w3:str(topic.name) end
      w3[flex and "compact_array" or "array"](w3, topic.partitions, function(w4, part)
        w4:i32(part.partition)
        if version >= 4 then w4:i32(part.current_leader_epoch or -1) end
        w4:i64(part.timestamp or -1)
        if flex then w4:tags() end
      end)
      if flex then w3:tags() end
    end)
  end
  write_topics(w)
  if flex then w:tags() end

  local r, err = M.exchange(conn, 2, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version }
  if version >= 2 then out.throttle_ms = r:i32() end
  out.topics = r[flex and "compact_array" or "array"](r, function(rr)
    local name =M.read_string(rr, flex)local partitions = M.read_array(rr, flex, function(r3)
      local index = r3:i32()
      local ec = r3:i16()
      local timestamp = r3:i64()
      local offset = r3:i64()
      local epoch = version >= 4 and r3:i32() or -1
      if flex then r3:tags() end
      if index == nil then return nil, "truncated offset row" end
      return { partition = index, error_code = ec, error_name = M.error_name(ec or 0),
        timestamp = timestamp, offset = offset, leader_epoch = epoch }
    end)
    if flex then rr:tags() end
    return { name = name, partitions = partitions or {} }
  end) or {}
  out.trailing_bytes = r:remaining()
  return out
end

----------------------------------------------------------------------------
-- 11. Fetch and the record format
----------------------------------------------------------------------------
--
-- Fetch is the only request that returns actual records, so the engine treats
-- it carefully: the caller must opt in, the response is bounded by max_bytes,
-- and the decoder never loops past the bytes the broker sent. A truncated
-- record batch is reported as truncated instead of being silently dropped,
-- because "there is data here" and "the read was cut short" are different
-- findings.

function M.fetch(conn, entries, opts)
  opts = opts or {}
  local version = opts.version or math.min(4, M.version_for(conn, 1) or 0)
  if not version or version < 1 then return { ok = false, error = "Fetch API not offered by broker" } end

  local w = M.writer()
  w:i32(opts.replica_id or -1)
  w:i32(opts.max_wait_ms or 0)
  w:i32(opts.min_bytes or 1)
  if version >= 3 then w:i32(opts.max_bytes or 1048576) end
  if version >= 4 then w:i8(opts.isolation_level or 0) end
  if version >= 7 then
    w:i32(opts.session_id or 0)
    w:i32(opts.session_epoch or -1)
  end
  w:array(entries, function(ww, topic)
    ww:str(topic.name)
    ww:array(topic.partitions, function(w3, part)
      w3:i32(part.partition)
      if version >= 9 then w3:i32(part.current_leader_epoch or -1) end
      w3:i64(part.fetch_offset or 0)
      if version >= 5 then w3:i64(part.log_start_offset or -1) end
      w3:i32(part.max_bytes or opts.partition_max_bytes or 1048576)
    end)
  end)
  if version >= 7 then w:array({}, function() end) end

  local r, err = M.exchange(conn, 1, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version }
  if version >= 1 then out.throttle_ms = r:i32() end
  if version >= 7 then
    out.error_code = r:i16()
    out.error_name = M.error_name(out.error_code or 0)
    out.session_id = r:i32()
  end
  out.topics = r:array(function(rr)
    local name = rr:str()
    local partitions = rr:array(function(r3)
      local index = r3:i32()
      local ec = r3:i16()
      local high_watermark = r3:i64()
      local last_stable = version >= 4 and r3:i64() or nil
      local log_start = version >= 5 and r3:i64() or nil
      local aborted = version >= 4 and r3:array(function(r4)
        local producer_id = r4:i64()
        local first_offset = r4:i64()
        return { producer_id = producer_id, first_offset = first_offset }
      end) or {}
      local records = r3:bytes()
      if index == nil then return nil, "truncated fetch partition" end
      local decoded = records and M.decode_records(records, { limit = opts.record_limit }) or nil
      return {
        partition = index, error_code = ec, error_name = M.error_name(ec or 0),
        high_watermark = high_watermark, last_stable_offset = last_stable,
        log_start_offset = log_start, aborted_transactions = aborted,
        records_bytes = records and #records or 0, records = decoded,
      }
    end)
    return { name = name, partitions = partitions or {} }
  end) or {}
  out.trailing_bytes = r:remaining()
  return out
end

-- CRC-32C (Castagnoli), the checksum every Kafka record batch carries. The
-- table is built once per Lua state; a probe that cannot verify the checksum
-- cannot tell a real record batch from an injected blob.
local CRC32C_POLY = 0x82F63B78
local crc32c_table
local function crc32c_init()
  local t = {}
  for i = 0, 255 do
    local crc = i
    for _ = 1, 8 do
      local lsb = crc % 2
      crc = shr32(crc, 1)
      if lsb == 1 then crc = bxor32(crc, CRC32C_POLY) end
    end
    t[i] = crc
  end
  return t
end

function M.crc32c(data)
  if not crc32c_table then crc32c_table = crc32c_init() end
  local crc = 4294967295.0
  for i = 1, #data do
    crc = bxor32(shr32(crc, 8), crc32c_table[bxor32(crc, string.byte(data, i)) % 256])
  end
  return bxor32(crc, 4294967295.0)
end

M.COMPRESSION = {
  [0] = "none", [1] = "gzip", [2] = "snappy", [3] = "lz4", [4] = "zstd",
}

-- Decode the record batches carried in a Fetch response. Batch headers are
-- never compressed (only the records inside them are), so even a compressed
-- batch yields offsets, timestamps, producer identity and record counts; the
-- individual records are only decoded for uncompressed batches, and that
-- limitation is reported instead of being papered over.
function M.decode_records(data, opts)
  opts = opts or {}
  local limit = opts.limit or 8
  local out = { batches = {}, truncated = false, bytes = #data, codecs = {}, records = {} }
  local pos = 1
  while pos + 12 <= #data do
    local r = M.reader(string.sub(data, pos))
    local base_offset = r:i64()
    local batch_length = r:i32()
    if not base_offset or not batch_length then break end
    if batch_length < 49 or pos + 12 + batch_length - 1 > #data then
      out.truncated = true
      out.truncated_at = pos
      break
    end
    local header = r:take(8)  -- partition_leader_epoch, magic
    local leader_epoch = (string.byte(header, 1) * 16777216 + string.byte(header, 2) * 65536
      + string.byte(header, 3) * 256 + string.byte(header, 4))
    if leader_epoch >= 2147483648 then leader_epoch = leader_epoch - 4294967296 end
    local magic = string.byte(header, 5)
    local crc = r:u32()
    local attrs = r:i16()
    local last_offset_delta = r:i32()
    local base_ts = r:i64()
    local max_ts = r:i64()
    local producer_id = r:i64()
    local producer_epoch = r:i16()
    local base_sequence = r:i32()
    local count = r:i32()
    local codec = attrs and band32(attrs, 7) or 0
    local batch = {
      base_offset = base_offset, batch_length = batch_length, magic = magic,
      partition_leader_epoch = leader_epoch, crc = crc, attributes = attrs,
      compression = M.COMPRESSION[codec] or ("unknown(" .. tostring(codec) .. ")"),
      compression_codec = codec, timestamp_type = (attrs and band32(attrs, 8) ~= 0) and "log_append" or "create",
      transactional = (attrs and band32(attrs, 16) ~= 0) or false,
      control = (attrs and band32(attrs, 32) ~= 0) or false,
      last_offset_delta = last_offset_delta, base_timestamp = base_ts, max_timestamp = max_ts,
      producer_id = producer_id, producer_epoch = producer_epoch, base_sequence = base_sequence,
      record_count = count, records = {},
    }
    out.codecs[batch.compression] = (out.codecs[batch.compression] or 0) + 1
    -- CRC-32C covers everything from the attributes field to the batch end.
    local crc_span = string.sub(data, pos + 21, pos + 12 + batch_length - 1)
    batch.crc_ok = (M.crc32c(crc_span) == crc)
    out.batches[#out.batches + 1] = batch

    if codec == 0 and count and count > 0 then
      local body = string.sub(data, pos + 61, pos + 12 + batch_length - 1)
      local br = M.reader(body)
      for i = 1, math.min(count, limit) do
        local rlen = br:varint()
        if not rlen then out.truncated = true break end
        local start = br.pos
        local rattrs = br:i8()
        local ts_delta = br:varlong()
        local offset_delta = br:varint()
        local klen = br:varint()
        local key
        if klen and klen > 0 then key = br:take(klen) end
        local vlen = br:varint()
        local value
        if vlen and vlen > 0 then value = br:take(vlen) end
        local hcount = br:varint()
        local headers = {}
        for h = 1, (hcount or 0) do
          local hk = br:varint()
          local header_key = hk and hk > 0 and br:take(hk) or nil
          local hv = br:varint()
          local header_value = hv and hv > 0 and br:take(hv) or nil
          headers[#headers + 1] = { key = header_key, value = header_value }
        end
        if br.pos - start ~= rlen then br.pos = start + rlen end
        local record = {
          attributes = rattrs, timestamp_delta = ts_delta, offset_delta = offset_delta,
          offset = num(base_offset) + num(offset_delta), timestamp = num(base_ts) + num(ts_delta),
          key = key, value = value, headers = headers,
        }
        batch.records[#batch.records + 1] = record
        out.records[#out.records + 1] = record
      end
      if count > limit then batch.records_truncated = true end
    elseif codec ~= 0 then
      batch.records_decodable = false
      batch.records_note = "batch is " .. batch.compression .. " compressed; header fields are decoded, record payload is not"
    end
    pos = pos + 12 + batch_length
  end
  out.batch_count = #out.batches
  out.first_offset = out.batches[1] and out.batches[1].base_offset or nil
  local last = out.batches[#out.batches]
  out.last_offset = last and (last.base_offset + (last.last_offset_delta or 0)) or nil
  return out
end

----------------------------------------------------------------------------
-- 12. Cryptography for SASL
----------------------------------------------------------------------------
--
-- SCRAM is a real challenge/response mechanism, so an audit that claims a
-- SCRAM credential works has to compute the proof: that needs SHA-256 for
-- SCRAM-SHA-256 and SHA-512 for SCRAM-SHA-512. Both are implemented here in
-- pure Lua, built exclusively on the nibble-table primitives from section 1b,
-- so the digests are identical on a 64-bit Lua 5.3 and on a double-only host.

local BYTE = string.byte
local CHAR = string.char

M.hash = {}

local function get_be32(data, offset)
  local a, b, c, d = BYTE(data, offset, offset + 3)
  return num(a) * 256 * 256 * 256 + b * 65536 + c * 256 + d
end

local function put_be32(value)
  value = num(value) % 4294967296
  return CHAR(math.floor(value / 16777216) % 256, math.floor(value / 65536) % 256,
    math.floor(value / 256) % 256, value % 256)
end

-- Round constants: the first 32 bits of the fractional parts of the cube roots
-- of the first sixty-four primes.
local SHA256_K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

function M.hash.sha256(data)
  local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  local bitlen = #data * 8
  local padded = data .. "\128" .. string.rep("\0", (55 - #data % 64) % 64)
    .. put_be32(math.floor(bitlen / 4294967296)) .. put_be32(bitlen % 4294967296)
  local w = {}
  for off = 1, #padded, 64 do
    for i = 0, 15 do w[i] = get_be32(padded, off + i * 4) end
    for i = 16, 63 do
      local x, y = w[i - 15], w[i - 2]
      local s0 = bxor32(bxor32(rotr32(x, 7), rotr32(x, 18)), shr32(x, 3))
      local s1 = bxor32(bxor32(rotr32(y, 17), rotr32(y, 19)), shr32(y, 10))
      w[i] = add32(w[i - 16], s0, w[i - 7], s1)
    end
    local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
    for i = 0, 63 do
      local S1 = bxor32(bxor32(rotr32(e, 6), rotr32(e, 11)), rotr32(e, 25))
      local ch = bxor32(band32(e, f), band32(bnot32(e), g))
      local t1 = add32(hh, S1, ch, SHA256_K[i + 1], w[i])
      local S0 = bxor32(bxor32(rotr32(a, 2), rotr32(a, 13)), rotr32(a, 22))
      local maj = bxor32(bxor32(band32(a, b), band32(a, c)), band32(b, c))
      local t2 = add32(S0, maj)
      -- e_new feeds on the *old* d and a_new on both temporaries, so the
      -- rotation has to keep the previous state alive until they are computed.
      local new_e = add32(d, t1)
      local new_a = add32(t1, t2)
      hh, g, f, e, d, c, b, a = g, f, e, new_e, c, b, a, new_a
    end
    h[1], h[2], h[3], h[4] = add32(h[1], a), add32(h[2], b), add32(h[3], c), add32(h[4], d)
    h[5], h[6], h[7], h[8] = add32(h[5], e), add32(h[6], f), add32(h[7], g), add32(h[8], hh)
  end
  local out = {}
  for i = 1, 8 do out[i] = put_be32(h[i]) end
  return table.concat(out)
end

M.hash.SHA256_BLOCK = 64

-- SHA-512 carries every word as two 32-bit halves (hi, lo) so that no
-- intermediate value ever exceeds 2^32 and the arithmetic is exact.
local function u64_add(ahi, alo, bhi, blo)
  -- Normalise first: a host may hand back a large constant as a negative
  -- 32-bit integer, and the carry test below only works on unsigned values.
  ahi, alo = num(ahi) % 4294967296, num(alo) % 4294967296
  bhi, blo = num(bhi) % 4294967296, num(blo) % 4294967296
  local lo = alo + blo
  local carry = 0.0
  if lo >= 4294967296 then lo = lo - 4294967296; carry = 1.0 end
  return (ahi + bhi + carry) % 4294967296, lo
end

local function u64_rotr(hi, lo, n)
  n = n % 64
  if n == 0 then return hi, lo end
  if n >= 32 then
    hi, lo = lo, hi
    n = n - 32
    if n == 0 then return hi, lo end
  end
  return bor32(shr32(hi, n), shl32(lo, 32 - n)), bor32(shr32(lo, n), shl32(hi, 32 - n))
end

local function u64_shr(hi, lo, n)
  if n == 0 then return hi, lo end
  if n >= 32 then
    n = n - 32
    if n == 0 then return 0, hi end
    return 0, shr32(hi, n)
  end
  return shr32(hi, n), bor32(shr32(lo, n), shl32(hi, 32 - n))
end

local function u64_xor(ahi, alo, bhi, blo)
  return bxor32(ahi, bhi), bxor32(alo, blo)
end

local function u64_from_hex(text)
  return tonumber(string.sub(text, 3, 10), 16), tonumber(string.sub(text, 11, 18), 16)
end

-- First 64 bits of the fractional parts of the cube roots of the first eighty
-- primes: the SHA-512 round constants.
local SHA512_K = {
  "0x428a2f98d728ae22", "0x7137449123ef65cd", "0xb5c0fbcfec4d3b2f", "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538", "0x59f111f1b605d019", "0x923f82a4af194f9b", "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242", "0x12835b0145706fbe", "0x243185be4ee4b28c", "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f", "0x80deb1fe3b1696b1", "0x9bdc06a725c71235", "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2", "0xefbe4786384f25e3", "0x0fc19dc68b8cd5b5", "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275", "0x4a7484aa6ea6e483", "0x5cb0a9dcbd41fbd4", "0x76f988da831153b5",
  "0x983e5152ee66dfab", "0xa831c66d2db43210", "0xb00327c898fb213f", "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2", "0xd5a79147930aa725", "0x06ca6351e003826f", "0x142929670a0e6e70",
  "0x27b70a8546d22ffc", "0x2e1b21385c26c926", "0x4d2c6dfc5ac42aed", "0x53380d139d95b3df",
  "0x650a73548baf63de", "0x766a0abb3c77b2a8", "0x81c2c92e47edaee6", "0x92722c851482353b",
  "0xa2bfe8a14cf10364", "0xa81a664bbc423001", "0xc24b8b70d0f89791", "0xc76c51a30654be30",
  "0xd192e819d6ef5218", "0xd69906245565a910", "0xf40e35855771202a", "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8", "0x1e376c085141ab53", "0x2748774cdf8eeb99", "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63", "0x4ed8aa4ae3418acb", "0x5b9cca4f7763e373", "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc", "0x78a5636f43172f60", "0x84c87814a1f0ab72", "0x8cc702081a6439ec",
  "0x90befffa23631e28", "0xa4506cebde82bde9", "0xbef9a3f7b2c67915", "0xc67178f2e372532b",
  "0xca273eceea26619c", "0xd186b8c721c0c207", "0xeada7dd6cde0eb1e", "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba", "0x0a637dc5a2c898a6", "0x113f9804bef90dae", "0x1b710b35131c471b",
  "0x28db77f523047d84", "0x32caab7b40c72493", "0x3c9ebe0a15c9bebc", "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6", "0x597f299cfc657e2a", "0x5fcb6fab3ad6faec", "0x6c44198c4a475817",
}

local SHA512_H0 = {
  "0x6a09e667f3bcc908", "0xbb67ae8584caa73b", "0x3c6ef372fe94f82b", "0xa54ff53a5f1d36f1",
  "0x510e527fade682d1", "0x9b05688c2b3e6c1f", "0x1f83d9abfb41bd6b", "0x5be0cd19137e2179",
}

local function sha512_block(h, chunk)
  local w = {}
  for i = 0, 15 do
    local o = i * 8 + 1
    -- 0.0 seeds the float subtype: 32-bit integer arithmetic would wrap the
    -- high word of a 64-bit word the moment bit 31 becomes set.
    local hi = 0.0
    local lo = 0.0
    for j = 0, 3 do hi = hi * 256 + BYTE(chunk, o + j) end
    for j = 4, 7 do lo = lo * 256 + BYTE(chunk, o + j) end
    w[i] = { hi, lo }
  end
  for i = 16, 79 do
    local x, y = w[i - 15], w[i - 2]
    local s0hi, s0lo = u64_rotr(x[1], x[2], 1)
    local t1hi, t1lo = u64_rotr(x[1], x[2], 8)
    s0hi, s0lo = u64_xor(s0hi, s0lo, t1hi, t1lo)
    local s1hi, s1lo = u64_shr(x[1], x[2], 7)
    s0hi, s0lo = u64_xor(s0hi, s0lo, s1hi, s1lo)
    local s2hi, s2lo = u64_rotr(y[1], y[2], 19)
    local s3hi, s3lo = u64_rotr(y[1], y[2], 61)
    s2hi, s2lo = u64_xor(s2hi, s2lo, s3hi, s3lo)
    local s4hi, s4lo = u64_shr(y[1], y[2], 6)
    s2hi, s2lo = u64_xor(s2hi, s2lo, s4hi, s4lo)
    local a1, b1 = u64_add(w[i - 16][1], w[i - 16][2], s0hi, s0lo)
    local a2, b2 = u64_add(a1, b1, w[i - 7][1], w[i - 7][2])
    local whi, wlo = u64_add(a2, b2, s2hi, s2lo)
    w[i] = { whi, wlo }
  end
  local a, b, c, d = { h[1][1], h[1][2] }, { h[2][1], h[2][2] }, { h[3][1], h[3][2] }, { h[4][1], h[4][2] }
  local e, f, g, hh = { h[5][1], h[5][2] }, { h[6][1], h[6][2] }, { h[7][1], h[7][2] }, { h[8][1], h[8][2] }
  for i = 0, 79 do
    local khi, klo = u64_from_hex(SHA512_K[i + 1])
    local S1hi, S1lo = u64_rotr(e[1], e[2], 14)
    local x1hi, x1lo = u64_rotr(e[1], e[2], 18)
    S1hi, S1lo = u64_xor(S1hi, S1lo, x1hi, x1lo)
    local x2hi, x2lo = u64_rotr(e[1], e[2], 41)
    S1hi, S1lo = u64_xor(S1hi, S1lo, x2hi, x2lo)
    local chhi = bxor32(band32(e[1], f[1]), band32(bnot32(e[1]), g[1]))
    local chlo = bxor32(band32(e[2], f[2]), band32(bnot32(e[2]), g[2]))
    local t1hi, t1lo = u64_add(hh[1], hh[2], S1hi, S1lo)
    t1hi, t1lo = u64_add(t1hi, t1lo, chhi, chlo)
    t1hi, t1lo = u64_add(t1hi, t1lo, khi, klo)
    t1hi, t1lo = u64_add(t1hi, t1lo, w[i][1], w[i][2])
    local S0hi, S0lo = u64_rotr(a[1], a[2], 28)
    local y1hi, y1lo = u64_rotr(a[1], a[2], 34)
    S0hi, S0lo = u64_xor(S0hi, S0lo, y1hi, y1lo)
    local y2hi, y2lo = u64_rotr(a[1], a[2], 39)
    S0hi, S0lo = u64_xor(S0hi, S0lo, y2hi, y2lo)
    local majhi = bxor32(bxor32(band32(a[1], b[1]), band32(a[1], c[1])), band32(b[1], c[1]))
    local majlo = bxor32(bxor32(band32(a[2], b[2]), band32(a[2], c[2])), band32(b[2], c[2]))
    local t2hi, t2lo = u64_add(S0hi, S0lo, majhi, majlo)
    hh, g, f = g, f, e
    local ehi, elo = u64_add(d[1], d[2], t1hi, t1lo)
    e = { ehi, elo }
    d, c, b = c, b, a
    local ahi, alo = u64_add(t1hi, t1lo, t2hi, t2lo)
    a = { ahi, alo }
  end
  local acc = { a, b, c, d, e, f, g, hh }
  for i = 1, 8 do
    local nhi, nlo = u64_add(h[i][1], h[i][2], acc[i][1], acc[i][2])
    h[i] = { nhi, nlo }
  end
end

function M.hash.sha512(data)
  local h = {}
  for i = 1, 8 do
    local hi, lo = u64_from_hex(SHA512_H0[i])
    h[i] = { hi, lo }
  end
  local bitlen = #data * 8
  local padded = data .. "\128" .. string.rep("\0", (111 - #data % 128) % 128)
  local w = M.writer()
  w:u64(0):u64(bitlen)
  padded = padded .. w:result()
  for off = 1, #padded, 128 do
    sha512_block(h, string.sub(padded, off, off + 127))
  end
  local out = {}
  for i = 1, 8 do
    out[#out + 1] = put_be32(h[i][1])
    out[#out + 1] = put_be32(h[i][2])
  end
  return table.concat(out)
end

M.hash.SHA512_BLOCK = 128

-- Hash descriptors used by HMAC and PBKDF2: the block size, the digest length
-- and the function itself, so SCRAM can be parameterised by mechanism name.
-- Exposed for the wire level self-test suite: the 64-bit primitives are the
-- foundation of SHA-512 and a mistake in them is otherwise invisible.
M._u64_rotr, M._u64_shr, M._u64_add = u64_rotr, u64_shr, u64_add

M.HASH = {
  ["SHA-256"] = { f = M.hash.sha256, BLOCK = 64, LENGTH = 32, name = "SHA-256" },
  ["SHA-512"] = { f = M.hash.sha512, BLOCK = 128, LENGTH = 64, name = "SHA-512" },
}

-- HMAC and PBKDF2-HMAC on top of an arbitrary hash: both SCRAM variants need
-- them, and the SASL section below picks the pair by mechanism name.
function M.hmac(hash, key, message)
  local block = hash.BLOCK
  if #key > block then key = hash.f(key) end
  key = key .. string.rep("\0", block - #key)
  local opad, ipad = {}, {}
  for i = 1, block do
    local b = BYTE(key, i)
    ipad[i] = CHAR(bxor32(b, 0x36))
    opad[i] = CHAR(bxor32(b, 0x5C))
  end
  return hash.f(table.concat(opad) .. hash.f(table.concat(ipad) .. message))
end

function M.pbkdf2(hash, password, salt, iterations, dklen)
  dklen = dklen or hash.LENGTH
  local blocks = {}
  local count = 1
  while #table.concat(blocks) < dklen do
    local u = M.hmac(hash, password, salt .. put_be32(count))
    local acc = u
    for _ = 2, iterations do
      u = M.hmac(hash, password, u)
      local x = {}
      for i = 1, #acc do x[i] = CHAR(bxor32(BYTE(acc, i), BYTE(u, i))) end
      acc = table.concat(x)
    end
    blocks[#blocks + 1] = acc
    count = count + 1
  end
  return string.sub(table.concat(blocks), 1, dklen)
end

----------------------------------------------------------------------------
-- 13. Base64 (SASL SCRAM exchanges base64 encoded fields)
----------------------------------------------------------------------------

local B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function M.base64_encode(data)
  local out = {}
  local i = 1
  while i <= #data do
    local b1 = BYTE(data, i)
    local b2 = BYTE(data, i + 1)
    local b3 = BYTE(data, i + 2)
    local n = b1 * 65536 + (b2 or 0) * 256 + (b3 or 0)
    local c1 = math.floor(n / 262144) % 64
    local c2 = math.floor(n / 4096) % 64
    local c3 = math.floor(n / 64) % 64
    local c4 = n % 64
    out[#out + 1] = string.sub(B64_ALPHABET, c1 + 1, c1 + 1)
    out[#out + 1] = string.sub(B64_ALPHABET, c2 + 1, c2 + 1)
    out[#out + 1] = b2 and string.sub(B64_ALPHABET, c3 + 1, c3 + 1) or "="
    out[#out + 1] = b3 and string.sub(B64_ALPHABET, c4 + 1, c4 + 1) or "="
    i = i + 3
  end
  return table.concat(out)
end

local function b64_value(c)
  return string.find(B64_ALPHABET, c, 1, true) - 1
end

function M.base64_decode(text)
  if not text then return nil end
  text = string.gsub(text, "[^A-Za-z0-9+/=]", "")
  local out = {}
  for i = 1, #text, 4 do
    local c1, c2 = b64_value(string.sub(text, i, i)), b64_value(string.sub(text, i + 1, i + 1))
    local c3, c4 = string.sub(text, i + 2, i + 2), string.sub(text, i + 3, i + 3)
    if c1 < 0 or c2 < 0 then return nil end
    local n = c1 * 262144 + c2 * 4096
    out[#out + 1] = CHAR(math.floor(n / 65536) % 256)
    if c3 ~= "=" and c3 ~= "" then
      local v3 = b64_value(c3)
      if v3 < 0 then return nil end
      n = n + v3 * 64
      out[#out + 1] = CHAR(math.floor(n / 256) % 256)
      if c4 ~= "=" and c4 ~= "" then
        local v4 = b64_value(c4)
        if v4 < 0 then return nil end
        n = n + v4
        out[#out + 1] = CHAR(n % 256)
      end
    end
  end
  return table.concat(out)
end

----------------------------------------------------------------------------
-- 14. Configuration and admin APIs
----------------------------------------------------------------------------
--
-- DescribeConfigs is the only way to see broker and topic configuration with
-- no credentials, and the way it answers is itself evidence: a broker that
-- returns config values to an anonymous principal has no ACL for the cluster
-- resource, and one that returns CLUSTER_AUTHORIZATION_FAILED has.
--
-- CreateTopics and DeleteTopics are the two APIs that can change a cluster, so
-- the engine enforces the audit contract in code: CreateTopics is always sent
-- with validate_only set (the broker validates and creates nothing), and
-- DeleteTopics refuses any name that existed before the probe started.

M.RESOURCE_TYPE = {
  [2] = "TOPIC", [4] = "BROKER", [8] = "BROKER_LOGGER", [16] = "CLIENT_METRICS",
}

M.CONFIG_SOURCE = {
  [0] = "UNKNOWN", [1] = "DYNAMIC_TOPIC_CONFIG", [2] = "DYNAMIC_BROKER_CONFIG",
  [3] = "DYNAMIC_DEFAULT_BROKER_CONFIG", [4] = "STATIC_BROKER_CONFIG", [5] = "DEFAULT_CONFIG",
}

function M.describe_configs(conn, resources, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 32)
  if not version then return { ok = false, error = "DescribeConfigs API not offered by broker" } end
  local flex = M.flexible(32, version)

  local w = M.writer()
  if flex then
    w:compact_array(resources, function(ww, resource)
      ww:i8(resource.type or 2)
      ww:compact_str(resource.name)
      if resource.configs == nil then
        ww:uvarint(0)
      else
        ww:compact_array(resource.configs, function(w3, name) w3:compact_str(name) end)
      end
      ww:tags()
    end)
  else
    w:array(resources, function(ww, resource)
      ww:i8(resource.type or 2)
      ww:str(resource.name)
      if resource.configs == nil then
        ww:i32(-1)
      else
        ww:array(resource.configs, function(w3, name) w3:str(name) end)
      end
    end)
  end
  if version >= 1 then w:bool(opts.include_synonyms == true) end
  if version >= 3 then w:bool(opts.include_documentation == true) end
  if flex then w:tags() end

  local r, err = M.exchange(conn, 32, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version }
  out.throttle_ms = r:i32()
  out.results = M.read_array(r, flex, function(rr)
    local ec = rr:i16()
    local message = M.read_string(rr, flex)
    local rtype = rr:i8()
    local rname = M.read_string(rr, flex)
    local configs = M.read_array(rr, flex, function(r3)
      local name = M.read_string(r3, flex)
      local value = M.read_string(r3, flex)
      local read_only = r3:bool()
      local is_default = version == 0 and r3:bool() or nil
      local source = version >= 1 and r3:i8() or nil
      local sensitive = r3:bool()
      local synonyms = version >= 1 and M.read_array(r3, flex, function(r4)
        local sname = M.read_string(r4, flex)
        local svalue = M.read_string(r4, flex)
        local ssource = r4:i8()
        if flex then r4:tags() end
        return { name = sname, value = svalue, source = M.CONFIG_SOURCE[ssource] or ssource }
      end) or {}
      local ctype = version >= 3 and r3:i8() or nil
      local documentation = version >= 3 and M.read_string(r3, flex) or nil
      if flex then r3:tags() end
      local name_lc = name and string.lower(name) or ""
      return {
        name = name, value = value, read_only = read_only, is_default = is_default,
        source = source and (M.CONFIG_SOURCE[source] or source) or nil,
        source_code = source, is_sensitive = sensitive, synonyms = synonyms,
        config_type = ctype, documentation = documentation,
        secret_bearing = name_lc:find("password") ~= nil or name_lc:find("secret") ~= nil
          or name_lc:find("key") ~= nil or name_lc:find("credential") ~= nil,
      }
    end) or {}
    if flex then rr:tags() end
    return { error_code = ec, error_name = M.error_name(ec or 0), error_message = message,
      resource_type = M.RESOURCE_TYPE[rtype] or rtype, resource_type_code = rtype,
      resource_name = rname, configs = configs }
  end) or {}
  out.trailing_bytes = r:remaining()
  return out
end

-- CreateTopics is never allowed to create anything: validate_only is forced on
-- for every version that supports it, and the call is refused outright on v0
-- (where the field did not exist yet).
function M.create_topics(conn, specs, opts)
  opts = opts or {}
  local version = opts.version or M.version_for(conn, 19)
  if not version then return { ok = false, error = "CreateTopics API not offered by broker" } end
  if version < 1 then
    return { ok = false, error = "CreateTopics v0 has no validate_only flag; refusing to create a topic" }
  end
  local flex = M.flexible(19, version)

  local w = M.writer()
  if flex then
    w:compact_array(specs, function(ww, spec)
      ww:compact_str(spec.name)
      ww:i32(spec.partitions or 1)
      ww:i16(spec.replication_factor or 1)
      ww:uvarint(1)  -- empty assignment array
      if spec.configs == nil then
        ww:uvarint(1)
      else
        ww:compact_array(spec.configs, function(w3, config)
          w3:compact_str(config.name)
          w3:compact_str(config.value)
          w3:tags()
        end)
      end
      ww:tags()
    end)
  else
    w:array(specs, function(ww, spec)
      ww:str(spec.name)
      ww:i32(spec.partitions or 1)
      ww:i16(spec.replication_factor or 1)
      ww:array({}, function() end)
      ww:array(spec.configs or {}, function(w3, config)
        w3:str(config.name)
        w3:str(config.value)
      end)
    end)
  end
  w:i32(opts.timeout_ms or 5000)
  w:bool(true)  -- validate_only, hard coded
  if flex then w:tags() end

  local r, err = M.exchange(conn, 19, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version, validate_only = true }
  if version >= 2 then out.throttle_ms = r:i32() end
  out.topics = M.read_array(r, flex, function(rr)
    local name = M.read_string(rr, flex)
    local topic_id = version >= 7 and rr:take(16) or nil
    local ec = rr:i16()
    local message = M.read_string(rr, flex)
    local num_partitions, replication = nil, nil
    local configs = {}
    local tagged = {}
    if version >= 5 then
      num_partitions = rr:i32()
      replication = rr:i16()
      configs = M.read_array(rr, flex, function(r3)
        local cname = M.read_string(r3, flex)
        local cvalue = M.read_string(r3, flex)
        local read_only = r3:bool()
        local source = r3:i8()
        local sensitive = r3:bool()
        if flex then r3:tags() end
        return { name = cname, value = cvalue, read_only = read_only,
          source = M.CONFIG_SOURCE[source] or source, is_sensitive = sensitive }
      end) or {}
    end
    if flex then
      tagged = rr:tags() or {}
      for _, tag in ipairs(tagged) do
        if tag.tag == 0 and tag.size >= 2 then
          local a, b = string.byte(tag.value, 1, 2)
          local code = (a * 256 + b)
          if code >= 32768 then code = code - 65536 end
          out.config_error_code = code
          out.config_error_name = M.error_name(code)
        end
      end
    end
    return { name = name, topic_id = topic_id, error_code = ec, error_name = M.error_name(ec or 0),
      error_message = message, num_partitions = num_partitions, replication_factor = replication,
      configs = configs, tags = tagged }
  end) or {}
  out.trailing_bytes = r:remaining()
  return out
end

-- DeleteTopics is only ever pointed at a name the caller generated for the
-- probe. Passing expect_existing keeps the guarantee explicit at the call site.
function M.delete_topics(conn, names, opts)
  opts = opts or {}
  if opts.expect_existing then
    return { ok = false, error = "refusing to send DeleteTopics for a topic that exists" }
  end
  local version = opts.version or M.version_for(conn, 20)
  if not version then return { ok = false, error = "DeleteTopics API not offered by broker" } end
  local flex = M.flexible(20, version)

  local w = M.writer()
  if version >= 6 then
    w:compact_array(names, function(ww, name)
      ww:compact_str(name)
      ww:raw(string.rep("\0", 16)):tags()
    end)
  else
    w:array(names, function(ww, name) ww:str(name) end)
  end
  w:i32(opts.timeout_ms or 5000)
  if flex then w:tags() end

  local r, err = M.exchange(conn, 20, version, w:result())
  if not r then return { ok = false, error = err, version = version } end

  local out = { ok = true, version = version }
  if version >= 1 then out.throttle_ms = r:i32() end
  out.topics = M.read_array(r, flex, function(rr)
    local name = M.read_string(rr, flex)
    local ec = rr:i16()
    local message = version >= 5 and M.read_string(rr, flex) or nil
    if flex then rr:tags() end
    return { name = name, error_code = ec, error_name = M.error_name(ec or 0), error_message = message }
  end) or {}
  out.trailing_bytes = r:remaining()
  return out
end

----------------------------------------------------------------------------
-- 15. SASL
----------------------------------------------------------------------------
--
-- A Kafka cluster that allows anonymous access is a finding in itself, but the
-- more common (and more nuanced) case is a listener that announces SASL and
-- still answers metadata: that tells the auditor that authentication is
-- configured but not enforced for everything, or that a PLAINTEXT listener is
-- reachable directly. The engine implements the handshake plus two mechanisms
-- so a credential can actually be tested instead of guessed.

function M.sasl_handshake(conn, mechanism, opts)
  opts = opts or {}
  local version = opts.version or math.min(1, M.version_for(conn, 17, 1) or 1)
  local w = M.writer()
  w:str(mechanism)
  local r, err = M.exchange(conn, 17, version, w:result())
  if not r then return { ok = false, error = err, version = version } end
  local out = { ok = true, version = version, requested = mechanism }
  out.error_code = r:i16()
  out.error_name = M.error_name(out.error_code or 0)
  out.mechanisms = r:array(function(rr)
    local name = rr:str()
    return name
  end) or {}
  out.trailing_bytes = r:remaining()
  return out
end

function M.sasl_authenticate(conn, payload, opts)
  opts = opts or {}
  local version = opts.version or math.min(2, M.version_for(conn, 36, 2) or 0)
  local flex = M.flexible(36, version)
  local w = M.writer()
  if flex then w:compact_bytes(payload) else w:bytes(payload) end
  if flex then w:tags() end
  local r, err = M.exchange(conn, 36, version, w:result())
  if not r then return { ok = false, error = err, version = version } end
  local out = { ok = true, version = version }
  out.error_code = r:i16()
  out.error_name = M.error_name(out.error_code or 0)
  out.error_message = M.read_string(r, flex)
  out.auth_bytes =M.read_bytes(r, flex)if version >= 1 then out.session_lifetime_ms = r:i64() end
  out.authenticated = out.error_code == 0
  out.trailing_bytes = r:remaining()
  return out
end

M.sasl = {}

-- PLAIN (RFC 4616): a zero byte, the user, a zero byte, the password.
function M.sasl.plain_token(user, password)
  return "\0" .. (user or "") .. "\0" .. (password or "")
end

-- SCRAM (RFC 5802) over SHA-256 or SHA-512. The client implementation is real:
-- it derives SaltedPassword with PBKDF2, builds the ClientKey/StoredKey pair,
-- and verifies the ServerSignature the broker returns.
function M.sasl.scram(hash_name, user, password, opts)
  opts = opts or {}
  local hash = M.HASH[hash_name]
  if not hash then return nil, "unsupported SCRAM hash " .. tostring(hash_name) end
  local client = {
    hash = hash, hash_name = hash_name, user = user, password = password,
    state = "initial", gs2 = opts.gs2 or "n,,", error = nil,
  }
  client.nonce = opts.nonce or (function()
    local seed = tostring(os.time()) .. tostring(os.clock()) .. tostring(#user or 0)
    local digest = hash.f(seed)
    return M.base64_encode(string.sub(digest, 1, 18)):gsub("[^A-Za-z0-9]", "A")
  end)()

  -- SCRAM escapes '=' as '=3D' and ',' as '=2C' in the username.
  local function escape(value)
    return (string.gsub(string.gsub(value, "=", "=3D"), ",", "=2C"))
  end

  function client:client_first()
    self.bare = "n=" .. escape(self.user) .. ",r=" .. self.nonce
    self.client_first_bare = self.bare
    self.state = "sent_first"
    return self.gs2 .. self.bare
  end

  function client:client_final(server_first)
    if self.state ~= "sent_first" then return nil, "client_final before client_first" end
    local fields = {}
    for key, value in string.gmatch(server_first or "", "([%a]+)=([^,]+)") do
      fields[key] = value
    end
    if not fields.r or not fields.s or not fields.i then
      self.error = "malformed server-first message: " .. tostring(server_first)
      return nil, self.error
    end
    if string.sub(fields.r, 1, #self.nonce) ~= self.nonce then
      self.error = "server nonce does not extend the client nonce"
      return nil, self.error
    end
    local salt = M.base64_decode(fields.s)
    local iterations = tonumber(fields.i)
    if not salt or not iterations then
      self.error = "unreadable salt or iteration count"
      return nil, self.error
    end
    self.salt, self.iterations, self.server_nonce = salt, iterations, fields.r
    local salted = M.pbkdf2(self.hash, self.password, salt, iterations, self.hash.LENGTH)
    local client_key = M.hmac(self.hash, salted, "Client Key")
    local stored_key = self.hash.f(client_key)
    local channel = M.base64_encode(self.gs2)
    self.client_final_no_proof = "c=" .. channel .. ",r=" .. fields.r
    local auth_message = self.client_first_bare .. "," .. server_first .. "," .. self.client_final_no_proof
    local client_signature = M.hmac(self.hash, stored_key, auth_message)
    local xored = {}
    for i = 1, #client_key do
      xored[i] = CHAR(bxor32(BYTE(client_key, i), BYTE(client_signature, i)))
    end
    local proof = M.base64_encode(table.concat(xored))
    local server_key = M.hmac(self.hash, salted, "Server Key")
    self.expected_server_signature = M.base64_encode(M.hmac(self.hash, server_key, auth_message))
    self.state = "sent_final"
    return self.client_final_no_proof .. ",p=" .. proof
  end

  function client:verify(server_final)
    local value = string.match(server_final or "", "v=([^,]+)")
    if not value then
      local err = string.match(server_final or "", "e=([^,]+)")
      return false, "broker rejected the proof: " .. tostring(err or server_final)
    end
    if not self.expected_server_signature then return false, "no proof was sent" end
    if value ~= self.expected_server_signature then
      return false, "server signature mismatch"
    end
    return true
  end

  return client
end

-- Full PLAIN exchange: handshake, authenticate, and a verdict that says
-- whether the credential was accepted, refused, or whether the broker does not
-- offer the mechanism at all.
function M.sasl_auth_plain(conn, user, password, opts)
  local handshake = M.sasl_handshake(conn, "PLAIN", opts)
  if not handshake.ok then return handshake end
  local out = { ok = true, mechanism = "PLAIN", handshake = handshake,
    offered = false, authenticated = false }
  for _, name in ipairs(handshake.mechanisms) do
    if name == "PLAIN" then out.offered = true end
  end
  if not out.offered and handshake.error_code ~= 0 then
    out.status = "mechanism-not-offered"
    return out
  end
  local auth = M.sasl_authenticate(conn, M.sasl.plain_token(user, password), opts)
  out.authenticate = auth
  if auth.ok and auth.authenticated then
    out.status = "accepted"
  elseif auth.ok then
    out.status = "refused"
  else
    out.status = "error"
    out.error = auth.error
  end
  return out
end

-- Full SCRAM exchange. The client proof is computed locally, so a success here
-- means the password really is the account's password.
function M.sasl_auth_scram(conn, mechanism, user, password, opts)
  opts = opts or {}
  local handshake = M.sasl_handshake(conn, mechanism, opts)
  if not handshake.ok then return handshake end
  local out = { ok = true, mechanism = mechanism, handshake = handshake, offered = false }
  for _, name in ipairs(handshake.mechanisms) do
    if name == mechanism then out.offered = true end
  end
  if not out.offered then
    out.status = "mechanism-not-offered"
    return out
  end
  local client = M.sasl.scram(string.match(mechanism, "SHA%-512") and "SHA-512" or "SHA-256", user, password, opts)
  local first = client:client_first()
  local step1 = M.sasl_authenticate(conn, first, opts)
  out.first = step1
  if not step1.ok then
    out.status = "error"; out.error = step1.error; return out
  end
  if not step1.authenticated then
    out.status = "refused"; return out
  end
  local final, ferr = client:client_final(step1.auth_bytes)
  if not final then
    out.status = "malformed-server-first"; out.error = ferr; return out
  end
  local step2 = M.sasl_authenticate(conn, final, opts)
  out.second = step2
  if not step2.ok then
    out.status = "error"; out.error = step2.error; return out
  end
  if not step2.authenticated then
    out.status = "refused"
    return out
  end
  local verified, verr = client:verify(step2.auth_bytes)
  out.server_signature_verified = verified
  out.server_signature_error = verr
  out.status = verified and "accepted" or "accepted-unverified-signature"
  out.iterations = client.iterations
  out.salt = client.salt and M.base64_encode(client.salt) or nil
  return out
end

----------------------------------------------------------------------------
-- 16. Access verdicts
----------------------------------------------------------------------------
--
-- The distinction that matters in the report: an anonymous request that
-- succeeds proves access, one that fails with an authorization error proves
-- that ACLs exist and are being enforced, and anything else (an unsupported
-- version, a timeout, a malformed reply) proves nothing at all. Collapsing
-- those three into "failed" is how scanners end up reporting a hardened
-- cluster as a vulnerable one.

function M.verdict_from_error(error_code)
  if error_code == nil then return "unknown", "no error code in the response" end
  if error_code == 0 then return "access-granted", "the broker answered without an authorization error" end
  if M.is_authz_error(error_code) then
    return "access-denied", "ACLs are enforced for this principal: " .. M.error_name(error_code)
  end
  if error_code == 35 then return "unsupported-version", "the broker rejected the API version" end
  if error_code == 33 or error_code == 34 or error_code == 58 then
    return "auth-required", "the broker requires SASL authentication: " .. M.error_name(error_code)
  end
  if error_code == 3 or error_code == 91 or error_code == 100 then
    return "unknown-resource", "the resource does not exist, but the request was authorized"
  end
  if error_code == 36 or error_code == 92 then
    return "already-exists", "the resource already exists"
  end
  local class = M.error_class(error_code)
  if class == "transient" then
    return "transient", "the broker reported a transient condition: " .. M.error_name(error_code)
  end
  return "other-error", M.error_text(error_code)
end

function M.summarise_errors(rows)
  local counts = {}
  for _, row in ipairs(rows or {}) do
    local name = row.error_name or M.error_name(row.error_code or 0)
    counts[name] = (counts[name] or 0) + 1
  end
  local names = {}
  for name in pairs(counts) do names[#names + 1] = name end
  table.sort(names)
  local parts = {}
  for _, name in ipairs(names) do
    parts[#parts + 1] = name .. " x" .. M.int(counts[name])
  end
  return table.concat(parts, ", ")
end

----------------------------------------------------------------------------
-- 17. Reporting helpers
----------------------------------------------------------------------------

M.SEVERITY_ORDER = { CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0 }

function M.new_report(name)
  return {
    name = name,
    findings = {},
    evidence = {},
    limits = {},
    prerequisites = {},
  }
end

function M.add_finding(report, severity, id, title, detail, evidence)
  report.findings[#report.findings + 1] = {
    severity = severity, id = id, title = title, detail = detail,
    evidence = evidence, order = M.SEVERITY_ORDER[severity] or 0,
  }
  if #report.findings > 1 then
    table.sort(report.findings, function(a, b) return a.order > b.order end)
  end
  return report.findings[#report.findings]
end

function M.add_evidence(report, line)
  report.evidence[#report.evidence + 1] = line
end

-- Emit the findings into a stdnse output table under stable field names, so a
-- test can assert on report lines the way a user reads them.
function M.emit(report, out, opts)
  opts = opts or {}
  if #report.findings > 0 then
    out["Findings"] = {}
    out["Severity"] = {}
    local highest = nil
    for _, f in ipairs(report.findings) do
      out["Findings"][#out["Findings"] + 1] = f.title .. " (" .. f.id .. ")"
      out["Severity"][#out["Severity"] + 1] = f.severity .. ": " .. f.detail
      if not highest or (M.SEVERITY_ORDER[f.severity] or 0) > (M.SEVERITY_ORDER[highest] or 0) then
        highest = f.severity
      end
    end
    out["Risk Level"] = highest
  else
    out["Risk Level"] = opts.clean_label or "NONE"
    out["Findings"] = "no findings"
  end
  if #report.evidence > 0 then out["Evidence"] = report.evidence end
  if #report.limits > 0 then out["Method limits"] = report.limits end
  if #report.prerequisites > 0 then out["Prerequisites for abuse"] = report.prerequisites end
  return out
end

M.build_request = M.build_request
M.exchange = M.exchange
M.hash = M.hash

return M
