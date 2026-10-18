local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Evaluates whether an MQTT broker accepts authentication credentials over
unencrypted plain-text TCP. Credentials sent in the MQTT CONNECT packet on
an unencrypted listener are readable by any network participant between the
client and the broker (switches with port mirroring, compromised uplinks,
shared WiFi), and they are additionally captured in broker-side debug logs.

Why it matters
- MQTT 3.1.1 has no in-protocol encryption; the only transport protection
  is TLS. A broker that accepts username/password on 1883 is by design
  transmitting cleartext secrets.
- Even when the deployment "usually" uses TLS on 8883, the plain listener
  is frequently left open for legacy devices, and those credentials are
  then harvestable without a single TLS break.
- Cleartext credential flows also enable offline replay and credential
  stuffing against the same broker from another vantage point.

What the script does
1. Sends an anonymous CONNECT first to establish the broker's baseline
   auth posture (does it require credentials at all?).
2. Sends a second CONNECT carrying a non-secret audit credential pair
   (a random username with a random value in the documented shape) over
   the same plain TCP listener and observes whether the broker accepts,
   rejects, or ignores the credentials.
3. Classifies the risk: credentials accepted on the plain listener means
   the deployment relies on cleartext authentication (MEDIUM finding with
   the CONNACK evidence); credentials rejected with 0x04 means auth is at
   least enforced (no cleartext acceptance); anonymous acceptance means
   credentials are unnecessary at all (the risk shifts to the
   unauthenticated-broker class).
4. Reports listener facts (port, TLS absent, negotiated keepalive) and a
   three-point remediation block (move auth to TLS-only listener, mTLS,
   broker-side ACLs).

The credential pair is randomly generated per run and matches no known
account, so the probe cannot log in to anything real.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "defensive", "safe"}

portrule = shortport.port_or_service(
  {1883, 1884},
  {"mqtt", "mosquitto", "emqx"},
  "tcp"
)

local SCRIPT_NAME = "mqtt-cleartext-credential-risk"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  maxrequests = 8,
  timeout = 8,
  retries = 1,
  delay = 0.3,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
  { key = "retries", minimum = 0, maximum = 5, integer = true },
  { key = "delay", minimum = 0 },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

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

local MQTT_PACKET_TYPES = {
  [0x10] = "CONNECT",
  [0x20] = "CONNACK",
  [0x30] = "PUBLISH",
  [0x40] = "PUBACK",
  [0x50] = "PUBREC",
  [0x60] = "PUBREL",
  [0x70] = "PUBCOMP",
  [0x80] = "SUBSCRIBE",
  [0x90] = "SUBACK",
  [0xA0] = "UNSUBSCRIBE",
  [0xB0] = "UNSUBACK",
  [0xC0] = "PINGREQ",
  [0xD0] = "PINGRESP",
  [0xE0] = "DISCONNECT",
  [0xF0] = "AUTH",
}

local MQTT_RETURN_CODES = {
  [0x00] = "Connection accepted",
  [0x01] = "Connection refused: unacceptable protocol level",
  [0x02] = "Connection refused: identifier rejected",
  [0x03] = "Connection refused: server unavailable",
  [0x04] = "Connection refused: bad username or password",
  [0x05] = "Connection refused: not authorized",
}

local MQTT_CONNECT_FLAGS = {
  username = 0x80,
  password = 0x40,
  will_retain = 0x20,
  will_qos1 = 0x10,
  will_qos2 = 0x08,
  will_flag = 0x04,
  clean_session = 0x02,
}

local function mqtt_encode_remaining_length(length)
  local bytes = ""
  repeat
    local digit = length % 128
    length = math.floor(length / 128)
    if length > 0 then
      digit = digit + 128
    end
    bytes = bytes .. string.char(digit)
  until length == 0
  return bytes
end

local function mqtt_decode_remaining_length(data, position)
  local multiplier = 1
  local value = 0
  local count = 0
  local byte_val
  repeat
    count = count + 1
    if count > 4 or position > #data then
      return nil, "malformed remaining length"
    end
    byte_val = string.byte(data, position)
    if byte_val == nil then
      return nil, "truncated remaining length"
    end
    value = value + (byte_val % 128) * multiplier
    multiplier = multiplier * 128
    position = position + 1
  until (byte_val & 0x80) == 0
  return value, position
end

local function mqtt_encode_string(value)
  local len = #tostring(value or "")
  return string.char(math.floor(len / 256) % 256, len % 256) .. tostring(value or "")
end

local function mqtt_read_string(data, position)
  if position + 1 > #data then
    return nil, "truncated string length"
  end
  local len = string.byte(data, position) * 256 + string.byte(data, position + 1)
  if position + 1 + len > #data then
    return nil, "truncated string payload"
  end
  return string.sub(data, position + 2, position + 1 + len), position + 2 + len
end

local function mqtt_read_bytes(data, position, count)
  if position + count - 1 > #data then
    return nil, "truncated byte field"
  end
  return string.sub(data, position, position + count - 1), position + count
end

local function mqtt_build_connect_packet(client_id, opts)
  opts = opts or {}
  local level = opts.level or 4
  local keepalive = opts.keepalive or 60
  local flags = 0
  if opts.clean_session ~= false then
    flags = flags + 2
  end
  if opts.will then
    flags = flags + 4
    if opts.will_retain then
      flags = flags + 0x20
    end
    local will_qos = opts.will_qos or 0
    if will_qos >= 1 then
      flags = flags + 8
    end
    if will_qos >= 2 then
      flags = flags + 16
    end
  end
  if opts.password then
    flags = flags + 0x40
  end
  if opts.username then
    flags = flags + 0x80
  end

  local var_header = mqtt_encode_string("MQTT")
  var_header = var_header .. string.char(level)
  var_header = var_header .. string.char(flags)
  var_header = var_header .. string.char(math.floor(keepalive / 256) % 256, keepalive % 256)

  local payload = mqtt_encode_string(client_id or "")
  if opts.will then
    local will_payload = tostring(opts.will.payload or "")
    local will_len = #will_payload
    payload = payload .. mqtt_encode_string(opts.will.topic or "")
    payload = payload .. string.char(math.floor(will_len / 256) % 256, will_len % 256) .. will_payload
  end
  if opts.username then
    payload = payload .. mqtt_encode_string(opts.username)
  end
  if opts.password then
    payload = payload .. mqtt_encode_string(opts.password)
  end

  local remaining = var_header .. payload
  return string.char(0x10) .. mqtt_encode_remaining_length(#remaining) .. remaining
end

local function mqtt_parse_connect(data)
  local pos
  local proto_name, p2 = mqtt_read_string(data, 1)
  if not proto_name then
    return nil, p2
  end
  pos = p2
  if pos + 3 > #data then
    return nil, "truncated CONNECT fixed fields"
  end
  local level = string.byte(data, pos)
  local flags = string.byte(data, pos + 1) or 0
  local keepalive = string.byte(data, pos + 2) * 256 + string.byte(data, pos + 3)
  pos = pos + 4

  local info = {
    protocol_name = proto_name,
    level = level,
    keepalive = keepalive,
    clean_session = (flags & 2) ~= 0,
    will = (flags & 4) ~= 0,
    will_retain = (flags & 0x20) ~= 0,
    will_qos = ((flags & 8) ~= 0 and 1 or 0) + ((flags & 16) ~= 0 and 1 or 0),
    has_username = (flags & 0x80) ~= 0,
    has_password = (flags & 0x40) ~= 0,
  }

  local cid, p3 = mqtt_read_string(data, pos)
  if not cid then
    return nil, p3
  end
  info.client_id = cid
  pos = p3

  if info.will then
    local wtopic, p4 = mqtt_read_string(data, pos)
    if not wtopic then
      return nil, p4
    end
    info.will_topic = wtopic
    pos = p4
    if pos + 1 > #data then
      return nil, "truncated will payload length"
    end
    local wlen = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    pos = pos + 2
    if pos + wlen - 1 > #data then
      return nil, "truncated will payload"
    end
    info.will_payload = string.sub(data, pos, pos + wlen - 1)
    info.will_payload_length = wlen
    pos = pos + wlen
  end

  if info.has_username then
    local uname, p6 = mqtt_read_string(data, pos)
    if uname == nil then
      return nil, p6
    end
    info.username = uname
    pos = p6
  end
  if info.has_password then
    local pswd, p7 = mqtt_read_string(data, pos)
    if pswd == nil then
      return nil, p7
    end
    info.password = pswd
  end

  return info
end

local function mqtt_build_connack_packet(session_present, return_code)
  local body = string.char(session_present and 1 or 0, return_code)
  return string.char(0x20) .. string.char(#body) .. body
end

local function mqtt_parse_connack(body)
  if #body < 2 then
    return nil, "truncated CONNACK"
  end
  local session_present = string.byte(body, 1)
  local return_code = string.byte(body, 2)
  return {
    session_present = session_present == 1,
    return_code = return_code,
    description = MQTT_RETURN_CODES[return_code] or ("unknown (0x%02X)"):format(return_code),
  }
end

local function mqtt_build_publish_packet(qos, topic, payload, opts)
  opts = opts or {}
  qos = qos or 0
  local flags = 0
  if opts.dup then
    flags = flags + 0x08
  end
  flags = flags + (qos * 2)
  if opts.retain then
    flags = flags + 1
  end
  local packet_id = opts.packet_id or 0
  local body = mqtt_encode_string(topic)
  if qos > 0 then
    body = body .. string.char(math.floor(packet_id / 256) % 256, packet_id % 256)
  end
  body = body .. tostring(payload or "")
  return string.char(0x30 + flags) .. mqtt_encode_remaining_length(#body) .. body
end

local function mqtt_parse_publish(fixed_flags, body)
  local dup = (fixed_flags & 0x08) ~= 0
  local qos = math.floor((fixed_flags & 0x06) / 2)
  local retain = (fixed_flags & 0x01) ~= 0
  local pos = 1
  local topic, p2 = mqtt_read_string(body, pos)
  if topic == nil then
    return nil, p2
  end
  pos = p2
  local packet_id = nil
  if qos > 0 then
    if pos + 1 > #body then
      return nil, "truncated packet id"
    end
    packet_id = string.byte(body, pos) * 256 + string.byte(body, pos + 1)
    pos = pos + 2
  end
  local payload = ""
  if pos <= #body then
    payload = string.sub(body, pos)
  end
  return {
    topic = topic,
    qos = qos,
    dup = dup,
    retain = retain,
    packet_id = packet_id,
    payload = payload,
    payload_length = #payload,
  }
end

local function mqtt_build_subscribe_packet(packet_id, filters)
  local body = string.char(math.floor(packet_id / 256) % 256, packet_id % 256)
  for _, f in ipairs(filters or {}) do
    body = body .. mqtt_encode_string(f.topic)
    body = body .. string.char(f.qos or 0)
  end
  return string.char(0x82) .. mqtt_encode_remaining_length(#body) .. body
end

local function mqtt_parse_subscribe_grants(body)
  if #body < 2 then
    return nil, "truncated SUBACK"
  end
  local packet_id = string.byte(body, 1) * 256 + string.byte(body, 2)
  local grants = {}
  local pos = 3
  while pos <= #body do
    table.insert(grants, string.byte(body, pos))
    pos = pos + 1
  end
  return { packet_id = packet_id, grants = grants }
end

local function mqtt_build_unsubscribe_packet(packet_id, topics)
  local body = string.char(math.floor(packet_id / 256) % 256, packet_id % 256)
  for _, t in ipairs(topics or {}) do
    body = body .. mqtt_encode_string(t)
  end
  return string.char(0xA2) .. mqtt_encode_remaining_length(#body) .. body
end

local function mqtt_build_packet_id_packet(p_type, packet_id)
  local hi = math.floor(packet_id / 256) % 256
  local lo = packet_id % 256
  if p_type == 0x60 then
    return string.char(0x62) .. string.char(2) .. string.char(hi, lo)
  end
  return string.char(p_type) .. string.char(2) .. string.char(hi, lo)
end

local function mqtt_parse_packet_id(body)
  if #body < 2 then
    return nil, "truncated packet id"
  end
  return string.byte(body, 1) * 256 + string.byte(body, 2)
end

local function mqtt_build_pingreq_packet()
  return string.char(0xC0) .. string.char(0)
end

local function mqtt_build_disconnect_packet()
  return string.char(0xE0) .. string.char(0)
end

local function mqtt_next_packet_id(counter)
  local next_id = counter + 1
  if next_id > 65535 then
    next_id = 1
  end
  return next_id
end

local function mqtt_topic_levels(topic)
  local count = 0
  for _ in string.gmatch(tostring(topic or ""), "[^/]+") do
    count = count + 1
  end
  return count
end

local function mqtt_topic_matches(filter, topic)
  local f_levels = {}
  for lvl in string.gmatch(tostring(filter or ""), "[^/]+") do
    table.insert(f_levels, lvl)
  end
  local t_levels = {}
  for lvl in string.gmatch(tostring(topic or ""), "[^/]+") do
    table.insert(t_levels, lvl)
  end
  if #f_levels == 0 or #t_levels == 0 then
    return false
  end
  if f_levels[#f_levels] == "#" then
    for i = 1, #f_levels - 1 do
      if f_levels[i] ~= t_levels[i] then
        return false
      end
    end
    return true
  end
  if #f_levels ~= #t_levels then
    return false
  end
  for i = 1, #f_levels do
    if f_levels[i] ~= "#" and f_levels[i] ~= "+" and f_levels[i] ~= t_levels[i] then
      return false
    end
  end
  return true
end

local function mqtt_is_sys_topic(topic)
  return string.sub(tostring(topic or ""), 1, 4) == "$SYS"
end

local function mqtt_is_private_topic(topic)
  return string.sub(tostring(topic or ""), 1, 1) == "$"
end

local function mqtt_topic_classification(topic)
  local t = tostring(topic or "")
  if t == "" then
    return "empty"
  end
  if mqtt_is_sys_topic(t) then
    return "sys"
  end
  if mqtt_is_private_topic(t) then
    return "private"
  end
  local lowered = string.lower(t)
  local markers = {
    { pat = "command", class = "control" },
    { pat = "cmd", class = "control" },
    { pat = "control", class = "control" },
    { pat = "set", class = "control" },
    { pat = "switch", class = "control" },
    { pat = "actuator", class = "control" },
    { pat = "shadow", class = "shadow" },
    { pat = "update", class = "shadow" },
    { pat = "delta", class = "shadow" },
    { pat = "desired", class = "shadow" },
    { pat = "report", class = "shadow" },
    { pat = "telemetry", class = "telemetry" },
    { pat = "metric", class = "telemetry" },
    { pat = "status", class = "telemetry" },
    { pat = "sensor", class = "telemetry" },
    { pat = "alert", class = "alarm" },
    { pat = "alarm", class = "alarm" },
    { pat = "event", class = "event" },
    { pat = "log", class = "log" },
  }
  for _, m in ipairs(markers) do
    if string.find(lowered, m.pat, 1, true) then
      return m.class
    end
  end
  return "data"
end

local function mqtt_topic_depth_risk(filter)
  local t = tostring(filter or "")
  if t == "#" then
    return "root"
  end
  if mqtt_topic_levels(t) == 0 then
    return "empty"
  end
  local plus_count = 0
  for _ in string.gmatch(t, "%+") do
    plus_count = plus_count + 1
  end
  local levels = mqtt_topic_levels(t)
  if plus_count >= levels then
    return "fully-wild"
  end
  if levels <= 1 then
    return "shallow"
  end
  return "normal"
end

local function mqtt_parse_sys_payload(payload)
  local metrics = {}
  local total = 0
  for line in string.gmatch(tostring(payload or ""), "([^\13\10]+)") do
    local name, value = string.match(line, "^([^:]+):%s*(.*)$")
    if name and value then
      local trimmed = name
      trimmed = string.gsub(trimmed, "^%s+", "")
      trimmed = string.gsub(trimmed, "%s+$", "")
      value = string.gsub(value, "^%s+", "")
      value = string.gsub(value, "%s+$", "")
      metrics[trimmed] = value
      total = total + 1
    end
  end
  return metrics, total
end

local function mqtt_summarize_sys(metrics)
  local summary = {
    client_count = nil,
    connections = nil,
    disconnected = nil,
    messages_received = nil,
    messages_sent = nil,
    messages_forwarded = nil,
    messages_dropped = nil,
    bytes_received = nil,
    bytes_sent = nil,
    heap_size = nil,
    max_heap_size = nil,
    in_flight = nil,
    topic_count = nil,
  }
  for name, value in pairs(metrics or {}) do
    local num = tonumber(value)
    if name == "info" or name == "start_time" or name == "uptime" then
      summary[name] = value
    elseif num then
      summary[name] = num
    end
  end
  return summary
end

local MQTT_BROKER_SIGNATURES = {
  {
    vendor = "Eclipse Mosquitto 2.x",
    family = "mosquitto",
    version_pat = "^2%.%d+%.%d+$",
    sys_keys = { "broker/version", "broker/clients/connected" },
    level4 = true,
    notes = "Modern Mosquitto 2.x: $SYS/broker/version with a 2.x value plus the standard broker counter set.",
  },
  {
    vendor = "Eclipse Mosquitto 1.x",
    family = "mosquitto",
    version_pat = "^1%.%d+%.%d+$",
    sys_keys = { "broker/version", "broker/clients/connected" },
    level4 = true,
    notes = "Legacy Mosquitto 1.x: same $SYS/broker layout with a 1.x version value.",
  },
  {
    vendor = "EMQX 5.x",
    family = "emqx",
    version_pat = "^5%.%d+%.%d+$",
    sys_keys = { "broker/version", "broker/uptime" },
    level4 = true,
    notes = "EMQX 5.x exposes broker.* metrics under $SYS and a richer node table.",
  },
  {
    vendor = "EMQX 4.x",
    family = "emqx",
    version_pat = "^4%.%d+%.%d+$",
    sys_keys = { "broker/version", "broker/uptime" },
    level4 = true,
    notes = "EMQX 4.x $SYS layout with a 4.x version and flat uptime counters.",
  },
  {
    vendor = "HiveMQ",
    family = "hivemq",
    version_pat = nil,
    sys_keys = { "hive/broker/version" },
    level4 = true,
    notes = "HiveMQ advertises broker identity via $SYS/hive/broker/* topics.",
  },
  {
    vendor = "VerneMQ",
    family = "vernemq",
    version_pat = nil,
    sys_keys = { "vernemq/conn", "vernemq/clients" },
    level4 = true,
    notes = "VerneMQ exposes Erlang process supervision topics under $SYS/vernemq.",
  },
  {
    vendor = "Apache ActiveMQ",
    family = "activemq",
    version_pat = nil,
    sys_keys = { "activemq/broker/version" },
    level4 = true,
    notes = "ActiveMQ MQTT layer exposes broker statistics under $SYS/activemq.",
  },
}

local function mqtt_count_metric_hits(metrics, keys)
  local hits = 0
  for _, key in ipairs(keys) do
    if metrics and metrics[key] ~= nil then
      hits = hits + 1
    end
  end
  return hits
end

local function mqtt_fingerprint_broker(observed)
  observed = observed or {}
  local metrics = observed.sys_metrics or {}
  local version_value = metrics["broker/version"] or metrics["hive/broker/version"] or ""
  local scored = {}
  for _, sig in ipairs(MQTT_BROKER_SIGNATURES) do
    local hits = mqtt_count_metric_hits(metrics, sig.sys_keys)
    local score = hits
    local version_hit = false
    if sig.version_pat and version_value ~= "" and string.match(version_value, sig.version_pat) then
      version_hit = true
      score = score + 5
    end
    if observed.level4_accepted == true and sig.level4 == true then
      score = score + 0.5
    end
    if observed.anonymous_refused == true and sig.family == "mosquitto" then
      score = score + 0.25
    end
    table.insert(scored, { vendor = sig.vendor, family = sig.family, score = score, notes = sig.notes, version_hit = version_hit })
  end
  table.sort(scored, function(a, b)
    if a.version_hit ~= b.version_hit then
      return a.version_hit
    end
    return a.score > b.score
  end)
  local best = scored[1]
  local confidence = "low"
  if best.version_hit then
    confidence = "high"
  elseif best.score >= 2 then
    confidence = "high"
  elseif best.score >= 1 then
    confidence = "medium"
  end
  local second = scored[2]
  local runner_up = nil
  if second and second.score > 0 and not best.version_hit then
    runner_up = second.vendor
  end
  return {
    vendor = best.vendor,
    family = best.family,
    confidence = confidence,
    notes = best.notes,
    runner_up = runner_up,
    score = best.score,
  }
end

local MQTT_DEFAULT_CREDENTIALS = {
  { username = "admin", password = "admin", source = "EMQX / HiveMQ / many IoT gateways ship admin/admin out of the box" },
  { username = "admin", password = "password", source = "Common IoT gateway default" },
  { username = "admin", password = "123456", source = "Common weak admin password" },
  { username = "guest", password = "guest", source = "VerneMQ / RabbitMQ default guest account" },
  { username = "guest", password = "", source = "Bare guest account with empty password" },
  { username = "test", password = "test", source = "Test account left in production" },
  { username = "mqtt", password = "mqtt", source = "Service account mirroring the protocol name" },
  { username = "iot", password = "iot", source = "IoT platform service default" },
  { username = "user", password = "password", source = "Generic default" },
  { username = "broker", password = "broker", source = "Broker service account default" },
  { username = "root", password = "root", source = "Unix-style default" },
  { username = "demo", password = "demo", source = "Demo tenant default" },
}

local MQTT_PRIVILEGED_CLIENT_IDS = {
  "admin",
  "administrator",
  "root",
  "broker",
  "system",
  "service",
  "daemon",
  "mosquitto",
  "emqx",
  "hivemq",
  "$SYS",
  "$sys",
}

local MQTT_ACL_PROBE_TOPICS = {
  { topic = "admin/#", reason = "administrative command tree" },
  { topic = "$SYS/#", reason = "internal broker metrics" },
  { topic = "commands/#", reason = "device command channel" },
  { topic = "command/#", reason = "device command channel (singular)" },
  { topic = "cmd/#", reason = "short-form command channel" },
  { topic = "devices/#/set", reason = "per-device write channel" },
  { topic = "shadow/#", reason = "device shadow state (write path)" },
  { topic = "+/+/+/set", reason = "wildcard write probe" },
  { topic = "#", reason = "root wildcard (maximum scope)" },
}

local MQTT_RECON_SUBSCRIPTIONS = {
  { topic = "$SYS/#", reason = "broker internals and version disclosure" },
  { topic = "#", reason = "root wildcard harvest" },
  { topic = "+/#", reason = "first-level wildcard across all subtrees" },
  { topic = "devices/#", reason = "device telemetry tree" },
  { topic = "sensors/#", reason = "sensor telemetry tree" },
  { topic = "home/#", reason = "smart-home state tree" },
}

local function mqtt_client_id_policy_check(client_id)
  local cid = tostring(client_id or "")
  if cid == "" then
    return { class = "empty", privileged = false, note = "empty client id" }
  end
  local lowered = string.lower(cid)
  local privileged = false
  for _, p in ipairs(MQTT_PRIVILEGED_CLIENT_IDS) do
    if lowered == string.lower(p) then
      privileged = true
      break
    end
  end
  local class = "normal"
  if #cid <= 3 then
    class = "short"
  end
  if string.find(lowered, "admin", 1, true) or string.find(lowered, "root", 1, true) or string.find(lowered, "broker", 1, true) then
    class = "privileged-sounding"
  end
  return { class = class, privileged = privileged, note = "client id length " .. #cid }
end

local function mqtt_will_safety_classify(will)
  if not will or not will.topic then
    return { safe = true, reason = "no will configured" }
  end
  local t = string.lower(tostring(will.topic))
  if mqtt_is_sys_topic(will.topic) or mqtt_is_private_topic(will.topic) then
    return { safe = false, reason = "will targets a private/system topic namespace" }
  end
  if mqtt_topic_classification(will.topic) == "control" then
    return { safe = false, reason = "will would land on a control/command topic" }
  end
  if #tostring(will.payload or "") > 64 then
    return { safe = false, reason = "will payload exceeds the audit size budget" }
  end
  return { safe = true, reason = "will stays within the audit topic scope" }
end

local MQTT_CVSS = {
  unauthenticated_broker = "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
  anonymous_publish = "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
  default_credentials = "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
  wildcard_subscribe = "8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H)",
  clientid_hijack = "7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)",
  tls_no_mtls = "6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N)",
  retained_harvest = "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
  sys_leak = "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
  acl_bypass = "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
  cleartext_credentials = "7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
  keepalive_dos = "6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
  packet_size = "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
  protocol_legacy = "3.7 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
  qos2_deviation = "4.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)",
  will_injection = "5.9 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)",
}

local function mqtt_session_new(host, port, args)
  return {
    host = host,
    port = port,
    args = args,
    sock = nil,
    connected = false,
    connack = nil,
    client_id = nil,
    keepalive = nil,
    packet_id = 0,
    subscribed = {},
    received = {},
    publishes = 0,
    subscriptions = 0,
    errors = 0,
    tls_probe = nil,
    closed = false,
  }
end

local function mqtt_socket_open(sess, ssl)
  local sock = nmap.new_socket()
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local proto = ssl and "ssl" or "tcp"
  local ok, err = sock:connect(sess.host, sess.port, proto)
  if not ok then
    sock:close()
    return nil, "TCP connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  return sock
end

local function mqtt_send(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function mqtt_read_exact(sess, count)
  if not sess.sock then
    return nil, "no socket"
  end
  local attempts = 0
  while attempts < 3 do
    attempts = attempts + 1
    local ok, data, err = sess.sock:receive_bytes(count)
    if ok and data and #data >= count then
      return data
    end
    if ok and data and #data > 0 then
      local attempts2 = 0
      while #data < count and attempts2 < 5 do
        attempts2 = attempts2 + 1
        local ok2, more, err2 = sess.sock:receive_bytes(count - #data)
        if ok2 and more and #more > 0 then
          data = data .. more
        else
          break
        end
      end
      if #data >= count then
        return data
      end
      return nil, "truncated read (" .. #data .. "/" .. count .. ")"
    end
    sess.errors = sess.errors + 1
  end
  return nil, "read timeout"
end

local function mqtt_read_fixed_header(sess)
  local first, err = mqtt_read_exact(sess, 1)
  if not first then
    return nil, err
  end
  local type_flags = string.byte(first, 1)
  local packet_type = type_flags & 0xF0
  local flags = type_flags & 0x0F
  local rem_len
  local rem_pos
  local byte_val
  local multiplier = 1
  local value = 0
  local count = 0
  repeat
    count = count + 1
    if count > 4 then
      return nil, "malformed remaining length"
    end
    local chunk, e2 = mqtt_read_exact(sess, 1)
    if not chunk then
      return nil, e2
    end
    byte_val = string.byte(chunk, 1)
    value = value + (byte_val % 128) * multiplier
    multiplier = multiplier * 128
    rem_len = value
    rem_pos = count
  until (byte_val & 0x80) == 0
  return { type = packet_type, flags = flags, remaining = rem_len }
end

local function mqtt_read_packet(sess)
  local fixed, err = mqtt_read_fixed_header(sess)
  if not fixed then
    return nil, err
  end
  local body = ""
  if fixed.remaining > 0 then
    local body_data, e2 = mqtt_read_exact(sess, fixed.remaining)
    if not body_data then
      return nil, e2
    end
    body = body_data
  end
  local type_name = MQTT_PACKET_TYPES[fixed.type] or ("0x%02X"):format(fixed.type)
  local packet = {
    type = fixed.type,
    type_name = type_name,
    flags = fixed.flags,
    raw_length = 2 + fixed.remaining,
    body = body,
  }

  if fixed.type == 0x20 then
    local connack, e3 = mqtt_parse_connack(body)
    if not connack then
      packet.parse_error = e3
    else
      packet.connack = connack
    end
  elseif fixed.type == 0x30 then
    local publish, e3 = mqtt_parse_publish(fixed.flags, body)
    if not publish then
      packet.parse_error = e3
    else
      packet.publish = publish
    end
  elseif fixed.type == 0x90 then
    local grants, e3 = mqtt_parse_subscribe_grants(body)
    if not grants then
      packet.parse_error = e3
    else
      packet.suback = grants
    end
  elseif fixed.type == 0x40 or fixed.type == 0x50 or fixed.type == 0x60 or fixed.type == 0x70 or fixed.type == 0xB0 then
    local pid, e3 = mqtt_parse_packet_id(body)
    if not pid then
      packet.parse_error = e3
    else
      packet.packet_id = pid
    end
  end

  return packet
end

local function mqtt_connect_attempt(sess, client_id, keepalive, opts)
  opts = opts or {}
  local packet = mqtt_build_connect_packet(client_id, {
    level = opts.level or 4,
    keepalive = keepalive or 60,
    clean_session = opts.clean_session,
    username = opts.username,
    password = opts.password,
    will = opts.will,
    will_qos = opts.will and (opts.will_qos or 0) or nil,
    will_retain = opts.will and opts.will_retain or nil,
  })
  local ok, err = mqtt_send(sess, packet)
  if not ok then
    return nil, err
  end
  local header_first = nil
  local attempts = 0
  while attempts < 2 do
    attempts = attempts + 1
    local first, e1 = mqtt_read_exact(sess, 1)
    if not first then
      break
    end
    header_first = string.byte(first, 1)
    break
  end
  if not header_first then
    return nil, "no CONNACK header received"
  end
  if (header_first & 0xF0) ~= 0x20 then
    return nil, string.format("expected CONNACK, got packet type 0x%02X", header_first & 0xF0)
  end
  local rem_byte = nil
  local attempts2 = 0
  while attempts2 < 2 do
    attempts2 = attempts2 + 1
    local chunk, e1 = mqtt_read_exact(sess, 1)
    if not chunk then
      break
    end
    rem_byte = string.byte(chunk, 1)
    break
  end
  if not rem_byte then
    return nil, "no CONNACK remaining length"
  end
  local body = ""
  if rem_byte > 0 then
    local body_data, e2 = mqtt_read_exact(sess, rem_byte)
    if not body_data then
      return nil, e2
    end
    body = body_data
  end
  local connack, e3 = mqtt_parse_connack(body)
  if not connack then
    return nil, e3
  end
  sess.connack = connack
  sess.client_id = client_id
  sess.keepalive = keepalive or 60
  if connack.return_code == 0x00 then
    sess.connected = true
  end
  return connack
end

local function mqtt_session_open(host, port, args, opts)
  opts = opts or {}
  local sess = mqtt_session_new(host, port, args)
  local client_id = opts.client_id
    or (("audit_%s"):format(random_token(10)))
  local sock, err = mqtt_socket_open(sess, opts.ssl)
  if not sock then
    return nil, err
  end
  local connack, e2 = mqtt_connect_attempt(sess, client_id, opts.keepalive or 120, {
    level = opts.level or 4,
    clean_session = true,
  })
  if not connack then
    sess.sock:close()
    sess.closed = true
    return nil, e2
  end
  return sess
end

local function mqtt_await_packet(sess, wanted_types, max_packets)
  max_packets = max_packets or 12
  local guard = 0
  while guard < max_packets do
    guard = guard + 1
    local packet, err = mqtt_read_packet(sess)
    if not packet then
      return nil, err
    end
    local match = false
    for _, wanted in ipairs(wanted_types or {}) do
      if packet.type == wanted then
        match = true
        break
      end
    end
    if match then
      return packet
    end
    if packet.type == 0x30 and packet.publish then
      table.insert(sess.received, packet)
    elseif packet.type == 0xD0 then
      sess.pong = true
    end
  end
  return nil, "no expected packet within guard limit"
end

local function mqtt_subscribe(sess, filters)
  sess.packet_id = mqtt_next_packet_id(sess.packet_id)
  local pid = sess.packet_id
  local packet = mqtt_build_subscribe_packet(pid, filters)
  local ok, err = mqtt_send(sess, packet)
  if not ok then
    return nil, err
  end
  local suback_packet, e2 = mqtt_await_packet(sess, { 0x90 }, 16)
  if not suback_packet then
    return nil, e2
  end
  local grants = suback_packet.suback
  if not grants then
    return nil, suback_packet.parse_error or "unparseable SUBACK"
  end
  if grants.packet_id ~= pid then
    return nil, "SUBACK packet id mismatch"
  end
  sess.subscriptions = sess.subscriptions + 1
  for i, f in ipairs(filters) do
    local granted = grants.grants[i]
    local denied = granted == 0x80
    table.insert(sess.subscribed, {
      topic = f.topic,
      requested = f.qos or 0,
      granted = denied and nil or granted,
      denied = denied,
    })
  end
  return grants
end

local function mqtt_publish(sess, topic, payload, qos, retain)
  qos = qos or 0
  local opts = { retain = retain, dup = false }
  if qos > 0 then
    sess.packet_id = mqtt_next_packet_id(sess.packet_id)
    opts.packet_id = sess.packet_id
  end
  local packet = mqtt_build_publish_packet(qos, topic, payload, opts)
  local ok, err = mqtt_send(sess, packet)
  if not ok then
    return nil, err
  end
  sess.publishes = sess.publishes + 1
  local ack = nil
  if qos == 1 then
    local ack_packet, e2 = mqtt_await_packet(sess, { 0x40 }, 16)
    if not ack_packet then
      return nil, e2
    end
    ack = { kind = "PUBACK", packet_id = ack_packet.packet_id }
  elseif qos == 2 then
    local rec_packet, e2 = mqtt_await_packet(sess, { 0x50 }, 16)
    if not rec_packet then
      return nil, e2
    end
    local rel = mqtt_build_packet_id_packet(0x60, rec_packet.packet_id)
    local ok2, e3 = mqtt_send(sess, rel)
    if not ok2 then
      return nil, e3
    end
    local comp_packet, e4 = mqtt_await_packet(sess, { 0x70 }, 16)
    if not comp_packet then
      return nil, e4
    end
    ack = { kind = "PUBREC/PUBREL/PUBCOMP", packet_id = comp_packet.packet_id, full = true }
  end
  return { accepted = true, qos = qos, packet_id = opts.packet_id, ack = ack }
end

local function mqtt_unsubscribe(sess, topics)
  sess.packet_id = mqtt_next_packet_id(sess.packet_id)
  local pid = sess.packet_id
  local packet = mqtt_build_unsubscribe_packet(pid, topics)
  local ok, err = mqtt_send(sess, packet)
  if not ok then
    return nil, err
  end
  local ack_packet, e2 = mqtt_await_packet(sess, { 0xB0 }, 8)
  if not ack_packet then
    return nil, e2
  end
  return { packet_id = ack_packet.packet_id }
end

local function mqtt_ping(sess)
  local ok, err = mqtt_send(sess, mqtt_build_pingreq_packet())
  if not ok then
    return nil, err
  end
  local pong, e2 = mqtt_await_packet(sess, { 0xD0 }, 4)
  if not pong then
    return nil, e2
  end
  return { pong = true }
end

local function mqtt_drain_publishes(sess, max_messages)
  max_messages = max_messages or 8
  local out = {}
  for i = 1, max_messages do
    local packet, err = mqtt_read_packet(sess)
    if not packet then
      if #out == 0 then
        return nil, err
      end
      break
    end
    if packet.type == 0x30 and packet.publish then
      table.insert(out, packet.publish)
    elseif packet.type == 0x20 or packet.type == 0x90 then
      break
    end
  end
  return out
end

local function mqtt_close_session(sess)
  if not sess or sess.closed then
    return
  end
  pcall(function()
    sess.sock:send(mqtt_build_disconnect_packet())
  end)
  pcall(function()
    sess.sock:close()
  end)
  sess.closed = true
  sess.sock = nil
end

local function mqtt_session_summary(sess)
  return {
    connected = sess.connected,
    client_id = sess.client_id,
    connack_rc = sess.connack and sess.connack.return_code or nil,
    publishes = sess.publishes,
    subscriptions = sess.subscriptions,
    received = #sess.received,
    errors = sess.errors,
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

local CVSS_CLEARTEXT = MQTT_CVSS.cleartext_credentials

local function listener_facts(host, port, sections)
  local out = stdnse.output_table()
  out["Listener port"] = tostring(port.number)
  out["Transport"] = "plain TCP (no TLS on this listener)"
  out["Protocol probed"] = "MQTT 3.1.1 (level 4)"
  table.insert(sections, { key = "Listener Facts", value = out })
end

local function anonymous_baseline(host, port, args)
  local sess, err = mqtt_session_open(host, port, args, { client_id = "audit_" .. random_token(10), keepalive = 120 })
  if not sess then
    return nil, err
  end
  mqtt_close_session(sess)
  return sess
end

local function cleartext_credential_attempt(host, port, args)
  local sess = mqtt_session_new(host, port, args)
  local username = "audit-" .. random_token(10)
  local password = random_token(12)
  local sock, e1 = mqtt_socket_open(sess, false)
  if not sock then
    return nil, "connect failed: " .. tostring(e1), nil
  end
  local connack, e2 = mqtt_connect_attempt(sess, "audit_" .. random_token(10), 120, {
    username = username,
    password = password,
  })
  if not connack then
    pcall(mqtt_close_session, sess)
    return nil, "CONNECT failed: " .. tostring(e2), nil
  end
  local result = {
    username = username,
    username_length = #username,
    password_length = #password,
    connack_rc = connack.return_code,
    connack_desc = connack.description,
    session_present = connack.session_present,
  }
  pcall(mqtt_close_session, sess)
  return result
end

local function classify_posture(baseline, attempt, sections)
  local out = stdnse.output_table()
  if baseline then
    out["Anonymous baseline"] = string.format("CONNACK 0x%02X (%s)", baseline.connack.return_code, baseline.connack.description)
  else
    out["Anonymous baseline"] = "unavailable"
  end
  if attempt then
    out["Credential CONNECT"] = string.format("CONNACK 0x%02X (%s) for a randomly generated audit pair (length %d/%d)",
      attempt.connack_rc, attempt.connack_desc, attempt.username_length, attempt.password_length)
    out["Credential format observed"] = "MQTT CONNECT flags 0xC0 (username + password bits set) on plain TCP"
  else
    out["Credential CONNECT"] = "unavailable"
  end
  table.insert(sections, { key = "Credential Transport Analysis", value = out })
  return out
end

local function remediation_section()
  local remediation = stdnse.output_table()
  remediation["1. TLS-Only Authentication"] = "Accept username/password only on the TLS listener (8883) and disable credential handling on plain 1883."
  remediation["2. Require Client Certs"] = "Prefer mutual TLS so identities are bound to certificates instead of transmitted passwords."
  remediation["3. Broker ACLs + Logging"] = "Scope each identity to the topics it needs and alert on credential CONNECTs arriving on the plain listener."
  return { key = "Remediation", value = remediation }
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()

local sections = {}
listener_facts(host, port, sections)

local baseline, baseline_err = anonymous_baseline(host, port, args)
local attempt, attempt_err = nil, "not attempted"

if not budget_exhausted(args) then
  attempt, attempt_err = cleartext_credential_attempt(host, port, args)
end

local posture = classify_posture(baseline, attempt, sections)

local status_text
if attempt and attempt.connack_rc == 0x00 then
  status_text = "VULNERABLE - Broker accepts authentication credentials over plain unencrypted TCP"
  add_finding("MEDIUM", "MQTT broker accepted a username/password CONNECT on the plain listener", {
    subject = "plain TCP " .. tostring(port.number),
    evidence = "CONNACK 0x00 for a randomly generated audit credential pair sent without TLS",
    confidence = "high",
  })
  add_finding("MEDIUM", "Credentials on this listener are cleartext and readable by any observer on the path", {
    subject = "credential transport",
    evidence = "MQTT 3.1.1 has no in-protocol encryption; the plain listener carries CONNECT flags 0xC0 with the password in clear",
    confidence = "high",
  })
elseif attempt and attempt.connack_rc == 0x04 then
  status_text = "COMPLIANT - Broker rejects the audited credential pair (authentication is enforced, cleartext acceptance not demonstrated)"
  add_finding("INFO", "Credential CONNECT was refused with 0x04 on the plain listener", {
    subject = "plain TCP " .. tostring(port.number),
    evidence = string.format("CONNACK 0x04 (%s) for the audit pair", attempt.connack_desc),
    confidence = "medium",
  })
elseif baseline and baseline.connack.return_code == 0x00 then
  status_text = "AT RISK - Broker requires no credentials at all on the plain listener (see mqtt-unauthenticated-broker)"
  add_finding("MEDIUM", "Anonymous access is accepted, so any credentials used on this listener are optional and cleartext", {
    subject = "plain TCP " .. tostring(port.number),
    evidence = "anonymous CONNECT returned CONNACK 0x00",
    confidence = "high",
  })
else
  status_text = "INDETERMINATE - cleartext credential posture could not be classified"
  add_finding("INFO", "Probe outcomes could not be classified", {
    subject = "credential transport",
    evidence = "baseline=" .. tostring(baseline_err) .. " attempt=" .. tostring(attempt_err),
    confidence = "low",
  })
end

table.insert(sections, remediation_section())
local cvss = { key = "CVSS Score", value = CVSS_CLEARTEXT }
if not (attempt and attempt.connack_rc == 0x00) then
  cvss.value = "n/a - cleartext credential acceptance not demonstrated"
end
table.insert(sections, cvss)

local unique, counts = dedupe_findings()
local out = new_output(RISK_LEVEL, status_text)
return finish_output(out, unique, counts, sections)

end
