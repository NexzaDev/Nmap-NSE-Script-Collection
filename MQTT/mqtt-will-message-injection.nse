local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Evaluates whether an MQTT broker permits anonymous clients to register
arbitrary Last Will and Testament (LWT) messages on sensitive topic paths
(such as system/status, alerts/emergency, or devices/offline).
An LWT message is published automatically by the broker when a client disconnects
unexpectedly. If unauthenticated clients can register arbitrary LWT messages,
attackers can trigger false offline alerts or spoof device failure notifications.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

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

local function build_lwt_connect(client_id, will_topic, will_msg)
  local proto = encode_string("MQTT") .. string.char(4)
  -- Connect Flags: Will Flag (bit 2 = 0x04) + CleanSession (bit 1 = 0x02) = 0x06
  local flags = string.char(0x06)
  local keepalive = string.char(0, 30)

  local var_header = proto .. flags .. keepalive
  local payload = encode_string(client_id) .. encode_string(will_topic) .. encode_string(will_msg)

  return string.char(0x10) .. encode_remaining_length(#var_header + #payload) .. var_header .. payload
end

action = function(host, port)
  local out = stdnse.output_table()
  local will_topic = stdnse.get_script_args(SCRIPT_NAME .. ".topic") or "system/status/audit_lwt_check"
  local will_msg = "OFFLINE_AUDIT_PROBE"
  local client_id = "nmap_lwt_" .. string.sub(stdnse.generate_random_string(6), 1, 6)

  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to MQTT service.")
  end

  local pkt = build_lwt_connect(client_id, will_topic, will_msg)
  sock:send(pkt)

  local st, resp = sock:receive_bytes(4)
  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"
  out["Tested Will Topic"] = will_topic

  if st and resp and #resp >= 4 and string.byte(resp, 1) == 0x20 then
    local rc = string.byte(resp, 4)
    if rc == 0x00 then
      out["Status"] = "VULNERABLE - Arbitrary Last Will & Testament Registration Permitted"
      out["Assessment"] = "The broker accepted connection with custom LWT topic and payload without checking publisher ACLs during CONNECT phase."
      out["Remediation"] = "Enforce write ACL checks on Last Will topics during connection negotiation."
    else
      out["Status"] = string.format("SECURE - Broker rejected LWT connection with Return Code 0x%02X", rc)
    end
  else
    out["Status"] = "AUDITED - Broker disconnected connection attempt."
  end

  return out
end
