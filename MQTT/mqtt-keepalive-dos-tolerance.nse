local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Evaluates how an MQTT broker handles extreme KeepAlive values (KeepAlive = 0
disabling timeout, and KeepAlive = 65535s).
According to the MQTT standard, a KeepAlive value of 0 instructs the broker to
never disconnect the client due to inactivity. If the broker accepts KeepAlive=0
without imposing server-side maximum keepalive ceilings (Server Keep Alive in MQTT 5),
attackers can open thousands of idle zombie connections, exhausting broker file
descriptors and connection tables (Slowloris-style MQTT DoS).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "defensive", "safe"}

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

local function build_connect_keepalive(client_id, keepalive_val)
  local proto = encode_string("MQTT") .. string.char(4) .. string.char(2)
  local keep_bytes = string.char(math.floor(keepalive_val / 256) % 256, keepalive_val % 256)
  local payload = encode_string(client_id)
  return string.char(0x10) .. encode_remaining_length(#proto + #keep_bytes + #payload) .. proto .. keep_bytes .. payload
end

action = function(host, port)
  local out = stdnse.output_table()

  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to MQTT service.")
  end

  local client_id = "nmap_ka_" .. string.sub(stdnse.generate_random_string(6), 1, 6)
  -- Send CONNECT with KeepAlive = 0 (infinite timeout)
  local pkt = build_connect_keepalive(client_id, 0)
  sock:send(pkt)

  local st, resp = sock:receive_bytes(4)
  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"
  out["KeepAlive Tested"] = "0 seconds (Infinite Inactivity Allowed)"

  if st and resp and #resp >= 4 and string.byte(resp, 1) == 0x20 and string.byte(resp, 4) == 0x00 then
    out["Status"] = "VULNERABLE - Broker Accepts KeepAlive=0 (Infinite Idle Timeout Allowed)"
    out["Assessment"] = "The broker accepted a zero keepalive connection without overriding it. An attacker can initiate large volumes of idle TCP connections without sending ping requests, exhausting server connection limits and file descriptors."
    out["Remediation"] = "Enforce a maximum server keepalive interval (e.g. max_keepalive in Mosquitto or zone.external.server_keepalive in EMQX) to enforce client eviction after inactivity."
  else
    out["Status"] = "SECURE - Broker rejected KeepAlive=0 or enforced server keepalive restrictions."
  end

  return out
end
