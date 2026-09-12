local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Detects unauthenticated MQTT message brokers (typically listening on TCP
ports 1883 or 8883). Connects using an unauthenticated MQTT 3.1.1 CONNECT packet
with no credentials and evaluates the broker's CONNACK response.
If the broker returns Return Code 0x00 (Connection Accepted), it allows any
client on the network to subscribe to all topics, intercept sensitive IoT
telemetry, and publish arbitrary control messages to connected hardware devices.
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
    if length > 0 then
      digit = digit + 128
    end
    bytes = bytes .. string.char(digit)
  until length == 0
  return bytes
end

local function encode_string(str)
  local len = #str
  return string.char(math.floor(len / 256) % 256, len % 256) .. str
end

local function build_connect_packet(client_id, clean_session, keepalive)
  -- Protocol Name: "MQTT"
  local proto_name = encode_string("MQTT")
  local proto_level = string.char(4) -- MQTT 3.1.1
  local flags = string.char(clean_session and 2 or 0)
  local keep_alive_bytes = string.char(math.floor(keepalive / 256) % 256, keepalive % 256)

  local var_header = proto_name .. proto_level .. flags .. keep_alive_bytes
  local payload = encode_string(client_id)

  local var_len = #var_header + #payload
  local fixed_header = string.char(0x10) .. encode_remaining_length(var_len)

  return fixed_header .. var_header .. payload
end

action = function(host, port)
  local out = stdnse.output_table()
  local client_id = stdnse.get_script_args(SCRIPT_NAME .. ".client_id") or ("nmap_audit_" .. string.sub(stdnse.generate_random_string(8), 1, 8))

  local sock = nmap.new_socket()
  sock:set_timeout(5000)

  local ok, err = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not establish TCP connection to MQTT service: " .. (err or "unknown"))
  end

  local connect_pkt = build_connect_packet(client_id, true, 30)
  local sent = sock:send(connect_pkt)
  if not sent then
    sock:close()
    return stdnse.format_output(false, "Failed to send MQTT CONNECT packet.")
  end

  -- Receive CONNACK fixed header (2 bytes min)
  local status, header_data = sock:receive_bytes(2)
  if not status or not header_data or #header_data < 2 then
    sock:close()
    return stdnse.format_output(false, "No response or invalid response from MQTT broker.")
  end

  local pkt_type = string.byte(header_data, 1)
  local rem_len = string.byte(header_data, 2)

  if pkt_type ~= 0x20 then
    sock:close()
    return stdnse.format_output(false, string.format("Unexpected response header: 0x%02X (expected CONNACK 0x20)", pkt_type))
  end

  local status2, body_data = sock:receive_bytes(rem_len)
  sock:close()

  if not status2 or not body_data or #body_data < 2 then
    return stdnse.format_output(false, "Truncated CONNACK payload received.")
  end

  local session_present = string.byte(body_data, 1)
  local return_code = string.byte(body_data, 2)

  local rc_meanings = {
    [0x00] = "Connection Accepted (No authentication required)",
    [0x01] = "Connection Refused: Unacceptable protocol version",
    [0x02] = "Connection Refused: Identifier rejected",
    [0x03] = "Connection Refused: Server unavailable",
    [0x04] = "Connection Refused: Bad username or password",
    [0x05] = "Connection Refused: Not authorized"
  }

  local rc_desc = rc_meanings[return_code] or string.format("Unknown Return Code (0x%02X)", return_code)

  out["Protocol"] = "MQTT 3.1.1"
  out["CONNACK Return Code"] = string.format("0x%02X (%s)", return_code, rc_desc)
  out["Session Present Flag"] = tostring(session_present == 1)

  if return_code == 0x00 then
    out["Status"] = "VULNERABLE - Unauthenticated Anonymous MQTT Broker Access Permitted"
    out["Risk Level"] = "🔴 CRITICAL"
    out["CVSS Score"] = "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
    out["Assessment"] = "The MQTT broker accepted an anonymous connection with no credentials. Any network actor can subscribe to all topics, intercept sensor data, and publish malicious commands to connected IoT hardware."
    out["Remediation"] = "Disable anonymous broker access. In Mosquitto set 'allow_anonymous false' and configure password_file; in EMQX enable authentication plugins; enforce TLS mutual authentication (mTLS)."
  elseif return_code == 0x04 or return_code == 0x05 then
    out["Status"] = "SECURE - MQTT Broker strictly requires authentication (Connection Refused: Not Authorized)"
    out["Risk Level"] = "🟢 LOW"
  else
    out["Status"] = "INFORMATIONAL - Connection refused by broker: " .. rc_desc
  end

  return out
end
