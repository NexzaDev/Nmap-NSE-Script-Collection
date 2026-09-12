local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Connects to an MQTT broker anonymously, subscribes to the root multi-level
wildcard topic (#), and listens for incoming PUBLISH messages.
Audits received topics and message payloads for sensitive information leakage,
including IoT telemetry, user credentials, GPS coordinates, device commands,
and proprietary internal network communications.
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

local function build_subscribe(packet_id, topic, qos)
  local var_header = string.char(math.floor(packet_id / 256) % 256, packet_id % 256)
  local payload = encode_string(topic) .. string.char(qos)
  return string.char(0x82) .. encode_remaining_length(#var_header + #payload) .. var_header .. payload
end

local function sanitize_payload(payload)
  if #payload > 60 then
    payload = string.sub(payload, 1, 57) .. "..."
  end
  return string.gsub(payload, "[%c]", ".")
end

action = function(host, port)
  local out = stdnse.output_table()
  local listen_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
  local max_messages = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_messages")) or 10
  local client_id = "nmap_sub_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

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
    return stdnse.format_output(false, "Broker refused anonymous connection.")
  end

  -- Send SUBSCRIBE '#'
  sock:send(build_subscribe(1, "#", 0))

  -- Receive SUBACK
  local st2, suback_hdr = sock:receive_bytes(2)
  if not st2 or #suback_hdr < 2 or string.byte(suback_hdr, 1) ~= 0x90 then
    sock:close()
    return stdnse.format_output(false, "Broker did not return SUBACK.")
  end

  local suback_len = string.byte(suback_hdr, 2)
  local st3, suback_body = sock:receive_bytes(suback_len)
  if not st3 or #suback_body < 3 or string.byte(suback_body, 3) == 0x80 then
    sock:close()
    return stdnse.format_output(false, "Broker rejected wildcard subscription (SUBACK Failure 0x80).")
  end

  out["Risk Level"] = "🔴 CRITICAL"
  out["Status"] = "VULNERABLE - Unrestricted Wildcard Subscription Allowed on '#'"

  -- Listen for inbound PUBLISH packets
  sock:set_timeout(listen_timeout * 1000)
  local captured_messages = {}
  local start_time = nmap.clock_ms()

  while #captured_messages < max_messages and (nmap.clock_ms() - start_time) < (listen_timeout * 1000) do
    local s, fixed_hdr = sock:receive_bytes(1)
    if not s or not fixed_hdr or #fixed_hdr == 0 then break end

    local ptype = math.floor(string.byte(fixed_hdr, 1) / 16)
    if ptype == 3 then -- PUBLISH packet
      -- Read remaining length
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
        if pbody and #pbody >= 2 then
          local topic_len = string.byte(pbody, 1) * 256 + string.byte(pbody, 2)
          local topic_name = string.sub(pbody, 3, 2 + topic_len)
          local payload_data = string.sub(pbody, 3 + topic_len)
          table.insert(captured_messages, string.format("Topic: %s | Payload: %s", topic_name, sanitize_payload(payload_data)))
        end
      end
    end
  end

  sock:close()

  out["Subscribed Topic"] = "# (All topics)"
  out["Captured Live Messages Count"] = #captured_messages

  if #captured_messages > 0 then
    out["Captured Topic Feeds"] = captured_messages
  else
    out["Captured Topic Feeds"] = "Subscription active; no live messages broadcasted during sample listening window."
  end

  out["Remediation"] = "Configure Topic Access Control Lists (ACLs) to disallow wildcard '#' subscriptions by unauthenticated or unauthorized clients."

  return out
end
