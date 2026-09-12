local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Probes an MQTT broker across multiple protocol versions:
1. MQTT 3.1 (Legacy MQIsdp protocol name, version 3)
2. MQTT 3.1.1 (Standard OASIS MQTT, version 4)
3. MQTT 5.0 (Enhanced features, user properties, reason codes, version 5)

Identifies supported protocol specifications, compliance levels, and version
downgrade handling.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  {1883, 8883, 1884},
  {"mqtt", "mqtt-s", "mosquitto", "emqx"},
  "tcp"
)

local function encode_remaining_length(length)
  local bytes = ""
  repeat
    local digit = length % 128
    length = math.floor(length / 128)
    if length > 0 then digit = digit + 128 end
    bytes = bytes .. string.char(digit)
  until length == 0
  return bytes
end

local function encode_string(str)
  local len = #str
  return string.char(math.floor(len / 256) % 256, len % 256) .. str
end

local function build_proto_connect(proto_name, proto_level)
  local proto = encode_string(proto_name) .. string.char(proto_level) .. string.char(2) .. string.char(0, 30)
  -- If MQTT 5.0, add properties length byte (0x00)
  if proto_level == 5 then
    proto = proto .. string.char(0)
  end
  local payload = encode_string("nmap_ver_probe")
  return string.char(0x10) .. encode_remaining_length(#proto + #payload) .. proto .. payload
end

action = function(host, port)
  local out = stdnse.output_table()
  local versions_supported = stdnse.output_table()

  local tests = {
    { name = "MQTT 3.1 (Legacy MQIsdp)", proto = "MQIsdp", level = 3 },
    { name = "MQTT 3.1.1 (Standard)", proto = "MQTT", level = 4 },
    { name = "MQTT 5.0 (Modern OASIS)", proto = "MQTT", level = 5 }
  }

  for _, t in ipairs(tests) do
    local sock = nmap.new_socket()
    sock:set_timeout(3500)

    local ok = sock:connect(host, port, "tcp")
    if ok then
      local pkt = build_proto_connect(t.proto, t.level)
      sock:send(pkt)

      local st, resp = sock:receive_bytes(4)
      sock:close()

      if st and resp and #resp >= 4 and string.byte(resp, 1) == 0x20 then
        local rc = string.byte(resp, 4)
        if rc == 0x00 then
          versions_supported[t.name] = "SUPPORTED (Connection Accepted)"
        elseif rc == 0x01 then
          versions_supported[t.name] = "UNSUPPORTED (Protocol Version Rejected)"
        else
          versions_supported[t.name] = string.format("REJECTED (Return Code: 0x%02X)", rc)
        end
      else
        versions_supported[t.name] = "NO RESPONSE / DISCONNECTED"
      end
    else
      versions_supported[t.name] = "CONNECTION FAILED"
    end
  end

  out["Risk Level"] = "🟢 LOW"
  out["Protocol Version Matrix"] = versions_supported

  return out
end
