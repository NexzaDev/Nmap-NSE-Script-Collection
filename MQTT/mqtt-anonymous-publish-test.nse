local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Evaluates whether an MQTT broker allows unauthenticated clients to publish
messages (write/inject data) to topics. Connects anonymously and sends a
safe diagnostic PUBLISH packet with QoS 1 to an auditing topic (audit/nmap/write-check).
If the broker returns a valid PUBACK acknowledgment without disconnecting the client,
it confirms unauthenticated write and command injection permissions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "auth", "safe"}

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

local function build_publish_qos1(packet_id, topic, payload)
  local topic_bytes = encode_string(topic)
  local pid_bytes = string.char(math.floor(packet_id / 256) % 256, packet_id % 256)
  local var_header = topic_bytes .. pid_bytes
  -- Fixed header: 0x32 = PUBLISH with QoS 1
  return string.char(0x32) .. encode_remaining_length(#var_header + #payload) .. var_header .. payload
end

action = function(host, port)
  local out = stdnse.output_table()
  local test_topic = stdnse.get_script_args(SCRIPT_NAME .. ".topic") or "audit/nmap/write-check"
  local client_id = "nmap_pub_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

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

  -- Send QoS 1 Publish
  local test_msg = "nmap-nse-audit-probe-" .. stdnse.generate_random_string(8)
  local pub_pkt = build_publish_qos1(10, test_topic, test_msg)
  sock:send(pub_pkt)

  -- Await PUBACK (0x40, 0x02, PacketID)
  local st2, puback = sock:receive_bytes(4)
  sock:close()

  out["Risk Level"] = "🔴 CRITICAL"
  out["Tested Topic"] = test_topic

  if st2 and puback and #puback >= 4 and string.byte(puback, 1) == 0x40 then
    out["Status"] = "VULNERABLE - Anonymous Clients Permitted to PUBLISH Messages (PUBACK Received)"
    out["PUBACK Status"] = "Acknowledged by Broker (Write access confirmed)"
    out["Assessment"] = "The broker allows anonymous users to publish arbitrary messages. Attackers can inject fake sensor readings, issue fraudulent actuator commands, or trigger malicious firmware update routines."
    out["Remediation"] = "Enforce write ACLs on all topics. Deny write permissions to anonymous users or disallow anonymous connections completely."
  else
    out["Status"] = "SECURE / RESTRICTED - Broker rejected anonymous publish or disconnected client without PUBACK."
  end

  return out
end
