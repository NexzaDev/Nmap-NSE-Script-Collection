local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Audits Topic Access Control List (ACL) enforcement on an MQTT broker.
Connects anonymously and attempts to subscribe to commonly protected or
administrative topic paths (admin/#, system/#, control/#, config/#, secrets/#,
internal/#, telemetry/#).
Checks SUBACK return codes (0x00/0x01/0x02 vs 0x80 Failure) to detect broken or
missing topic authorization restrictions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "auth", "safe"}

portrule = shortport.port_or_service(
  {1883, 8883, 1884},
  {"mqtt", "mqtt-s", "mosquitto", "emqx"},
  "tcp"
)

local RESTRICTED_TOPICS = {
  "admin/#", "system/#", "control/#", "config/#", "internal/#",
  "devices/+/config", "users/#", "auth/#", "ota/#", "firmware/#"
}

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
  local client_id = "nmap_acl_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

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

  local allowed_topics = {}
  local pid = 1

  for _, topic in ipairs(RESTRICTED_TOPICS) do
    sock:send(build_subscribe(pid, topic))
    pid = pid + 1

    local st2, suback_hdr = sock:receive_bytes(2)
    if st2 and suback_hdr and #suback_hdr >= 2 and string.byte(suback_hdr, 1) == 0x90 then
      local len = string.byte(suback_hdr, 2)
      local st3, suback_body = sock:receive_bytes(len)
      if st3 and suback_body and #suback_body >= 3 then
        local return_code = string.byte(suback_body, 3)
        if return_code ~= 0x80 then -- 0x80 = Failure / Denied
          table.insert(allowed_topics, string.format("Topic: '%s' (SUBACK: 0x%02X Granted)", topic, return_code))
        end
      end
    end
  end

  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"
  out["Total Sensitive Topics Tested"] = #RESTRICTED_TOPICS

  if #allowed_topics > 0 then
    out["Status"] = string.format("VULNERABLE - %d sensitive topic paths granted subscription without ACL restriction", #allowed_topics)
    out["Unrestricted Sensitive Topics"] = allowed_topics
    out["Remediation"] = "Implement granular topic-level ACLs (e.g. acl_file in Mosquitto or EMQX ACL rules) to strictly restrict read access to administrative and control topics."
  else
    out["Status"] = "SECURE - All tested sensitive topic paths were rejected by broker ACLs (SUBACK 0x80)."
  end

  return out
end
