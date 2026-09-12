local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Subscribes to the MQTT broker internal system topic hierarchy ($SYS/#)
and harvests operational metrics and infrastructure details, including:
1. Broker software name and version ($SYS/broker/version)
2. Broker uptime ($SYS/broker/uptime)
3. Active connected client counts ($SYS/broker/clients/connected)
4. Memory usage and active subscriptions ($SYS/broker/subscriptions/count)
5. Total messages and network traffic statistics ($SYS/broker/bytes/received)

These system topics expose internal broker topology and workload characteristics.
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
  local listen_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 4
  local client_id = "nmap_sys_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

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

  sock:send(build_subscribe(1, "$SYS/#"))
  local st2, suback = sock:receive_bytes(5)
  if not st2 or #suback < 2 or string.byte(suback, 1) ~= 0x90 then
    sock:close()
    return stdnse.format_output(false, "Broker did not return SUBACK.")
  end

  sock:set_timeout(listen_timeout * 1000)
  local sys_metrics = stdnse.output_table()
  local metrics_count = 0
  local start_time = nmap.clock_ms()

  while metrics_count < 20 and (nmap.clock_ms() - start_time) < (listen_timeout * 1000) do
    local s, fixed_hdr = sock:receive_bytes(1)
    if not s or not fixed_hdr or #fixed_hdr == 0 then break end

    local ptype = math.floor(string.byte(fixed_hdr, 1) / 16)
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
        if pbody and #pbody >= 2 then
          local topic_len = string.byte(pbody, 1) * 256 + string.byte(pbody, 2)
          local topic_name = string.sub(pbody, 3, 2 + topic_len)
          local payload_data = string.sub(pbody, 3 + topic_len)
          payload_data = string.gsub(payload_data, "[\r\n]", "")

          local clean_key = string.gsub(topic_name, "^%$SYS/", "")
          sys_metrics[clean_key] = payload_data
          metrics_count = metrics_count + 1
        end
      end
    end
  end

  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"

  if metrics_count > 0 then
    out["Status"] = string.format("VULNERABLE - $SYS Hierarchy Accessible (%d metrics retrieved)", metrics_count)
    out["Disclosed $SYS Metrics"] = sys_metrics
    out["Remediation"] = "Configure ACL rules to restrict access to $SYS topics (e.g., in Mosquitto set 'topic read $SYS/#' only for authorized administrative accounts)."
  else
    out["Status"] = "SECURE - $SYS topics are restricted or returned no retained values."
  end

  return out
end
