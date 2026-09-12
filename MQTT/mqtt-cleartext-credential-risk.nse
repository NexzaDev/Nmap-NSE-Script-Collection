local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Evaluates whether an MQTT broker accepts authentication credentials over
unencrypted plain-text TCP connections (typically port 1883).
Transmitting MQTT usernames and passwords in cleartext allows passive network
eavesdroppers, rogue Wi-Fi access points, and compromised network switches
to capture IoT credentials and gain full unauthorized broker access.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "defensive", "safe"}

portrule = shortport.port_or_service(
  {1883, 1884},
  {"mqtt", "mosquitto", "emqx"},
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

local function build_auth_connect(client_id, user, pass)
  local proto = encode_string("MQTT") .. string.char(4) .. string.char(0xC2) .. string.char(0, 30)
  local payload = encode_string(client_id) .. encode_string(user) .. encode_string(pass)
  return string.char(0x10) .. encode_remaining_length(#proto + #payload) .. proto .. payload
end

action = function(host, port)
  local out = stdnse.output_table()

  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to MQTT service.")
  end

  local dummy_user = "audit_probe_user"
  local dummy_pass = "audit_probe_pass"
  local pkt = build_auth_connect("nmap_cleartext_audit", dummy_user, dummy_pass)
  sock:send(pkt)

  local st, resp = sock:receive_bytes(4)
  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"
  out["Transport Layer Security"] = "NONE (Plaintext TCP Port " .. port.number .. ")"

  if st and resp and #resp >= 4 and string.byte(resp, 1) == 0x20 then
    local rc = string.byte(resp, 4)
    -- RC 0x04 = Bad username/pwd, RC 0x05 = Not authorized, RC 0x00 = Accepted
    -- All these indicate broker processed credentials over cleartext TCP
    out["Status"] = "VULNERABLE - MQTT Broker Processes Cleartext Credentials over Plain TCP"
    out["CONNACK Return Code"] = string.format("0x%02X", rc)
    out["Assessment"] = "The broker evaluated credentials submitted over an unencrypted channel. Client credentials are vulnerable to interception via network packet sniffing."
    out["Remediation"] = "Enforce MQTT over TLS (MQTTS on port 8883) and disable plain TCP port 1883 or restrict 1883 to localhost loopback only."
  else
    out["Status"] = "SECURE / NOT APPLICABLE - Broker disconnected or did not process cleartext authentication packet."
  end

  return out
end
