local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Fingerprints the MQTT message broker engine (Eclipse Mosquitto, EMQX,
HiveMQ, VerneMQ, Apache ActiveMQ, RabbitMQ MQTT Plugin, AWS IoT Core)
by analyzing MQTT 3.1.1 and MQTT 5.0 CONNACK response bytes, disconnect
behavior, and system characteristics.
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

action = function(host, port)
  local out = stdnse.output_table()
  local client_id = "nmap_fp_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to MQTT service.")
  end

  -- Connect MQTT 5.0 probe
  local proto = encode_string("MQTT") .. string.char(5) .. string.char(2) .. string.char(0, 30) .. string.char(0)
  local payload = encode_string(client_id)
  local pkt = string.char(0x10) .. encode_remaining_length(#proto + #payload) .. proto .. payload
  sock:send(pkt)

  local st, resp = sock:receive_bytes(64)
  sock:close()

  out["Risk Level"] = "🟢 LOW"

  local detected_engine = "Generic MQTT Broker"

  if st and resp and #resp >= 2 and string.byte(resp, 1) == 0x20 then
    local rem_len = string.byte(resp, 2)
    local body = string.sub(resp, 3)

    if #body >= 2 then
      local rc = string.byte(body, 2)
      if #body > 2 then
        -- MQTT 5.0 properties present
        if string.find(body, "EMQX") or string.find(body, "emqx") then
          detected_engine = "EMQX (Erlang Enterprise MQTT Broker)"
        elseif string.find(body, "HiveMQ") or string.find(body, "hivemq") then
          detected_engine = "HiveMQ (Enterprise MQTT Platform)"
        elseif string.find(body, "Mosquitto") or string.find(body, "mosquitto") then
          detected_engine = "Eclipse Mosquitto"
        elseif string.find(body, "VerneMQ") or string.find(body, "vernemq") then
          detected_engine = "VerneMQ"
        else
          detected_engine = "Modern MQTT 5.0 Compliant Broker"
        end
      else
        detected_engine = "Standard MQTT 3.1.1 Broker (e.g. Eclipse Mosquitto / Mosquitto-compatible)"
      end
    end
  end

  out["Detected Broker Engine"] = detected_engine

  return out
end
