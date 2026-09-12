local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Connects to an accessible MQTT broker and harvests retained messages
(messages with RETAIN flag set). Retained messages persist indefinitely in broker
memory and disk storage, and are immediately delivered to any new subscriber.
Audits retained message contents for sensitive credentials, configuration payloads,
API keys, and network topology data.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

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

local function build_connect(client_id)
  local proto = encode_string("MQTT") .. string.char(4) .. string.char(2) .. string.char(0, 30)
  local payload = encode_string(client_id)
  return string.char(0x10) .. encode_remaining_length(#proto + #payload) .. proto .. payload
end

local function build_subscribe(packet_id, topic)
  local var_header = string.char(math.floor(packet_id / 256) % 256, packet_id % 256)
  local payload = encode_string(topic) .. string.char(0)
  return string.char(0x82) .. encode_remaining_length(#var_header + #payload) .. var_header .. payload
end

action = function(host, port)
  local out = stdnse.output_table()
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 4
  local max_retained = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_retained")) or 15
  local client_id = "nmap_ret_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to MQTT service.")
  end

  sock:send(build_connect(client_id))
  local st, resp = sock:receive_bytes(4)
  if not st or #resp < 4 or string.byte(resp, 1) ~= 0x20 or string.byte(resp, 4) ~= 0x00 then
    sock:close()
    return stdnse.format_output(false, "Broker refused connection.")
  end

  sock:send(build_subscribe(1, "#"))
  local st2, suback = sock:receive_bytes(5)
  if not st2 or #suback < 2 or string.byte(suback, 1) ~= 0x90 then
    sock:close()
    return stdnse.format_output(false, "Broker rejected subscription.")
  end

  sock:set_timeout(timeout * 1000)
  local retained_messages = {}
  local start_time = nmap.clock_ms()

  while #retained_messages < max_retained and (nmap.clock_ms() - start_time) < (timeout * 1000) do
    local s, fixed_hdr = sock:receive_bytes(1)
    if not s or not fixed_hdr or #fixed_hdr == 0 then break end

    local byte1 = string.byte(fixed_hdr, 1)
    local ptype = math.floor(byte1 / 16)
    local is_retained = (byte1 % 2 == 1)

    if ptype == 3 then
      local multiplier = 1
      local rem_len = 0
      repeat
        local _, b = sock:receive_bytes(1)
        if not b or #b == 0 then break end
        local digit = string.byte(b)
        rem_len = rem_len + (digit % 128) * multiplier
        multiplier = multiplier * 128
      until digit < 128

      if rem_len > 0 then
        local _, pbody = sock:receive_bytes(rem_len)
        if pbody and #pbody >= 2 and is_retained then
          local topic_len = string.byte(pbody, 1) * 256 + string.byte(pbody, 2)
          local topic_name = string.sub(pbody, 3, 2 + topic_len)
          local payload_data = string.sub(pbody, 3 + topic_len)
          if #payload_data > 50 then payload_data = string.sub(payload_data, 1, 47) .. "..." end
          payload_data = string.gsub(payload_data, "[\r\n]", "")

          table.insert(retained_messages, string.format("Topic: '%s' | Data: '%s'", topic_name, payload_data))
        end
      end
    end
  end

  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"
  out["Total Retained Messages Captured"] = #retained_messages

  if #retained_messages > 0 then
    out["Status"] = string.format("DISCOVERED - %d retained message(s) extracted from broker storage", #retained_messages)
    out["Retained Messages"] = retained_messages
    out["Remediation"] = "Publish empty retained payloads (payload='') with retain=true to purge lingering retained messages containing sensitive configurations or credentials."
  else
    out["Status"] = "SECURE / CLEAN - No retained messages found on broker."
  end

  return out
end
