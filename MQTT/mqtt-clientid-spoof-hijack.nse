local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Tests whether an MQTT broker permits connecting with arbitrary, fixed, or
privileged Client IDs (e.g. gateway, bridge, admin, master) without enforcing
Client-ID-to-Certificate bindings or token ACL restrictions.
According to the MQTT specification, connecting with an existing Client ID causes
the broker to terminate (kick) the existing connection (Session Takeover / DoS).
If unauthorized clients can claim arbitrary Client IDs, an attacker can continuously
disconnect critical IoT gateways and sensors.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  {1883, 8883, 1884},
  {"mqtt", "mqtt-s", "mosquitto", "emqx"},
  "tcp"
)

local TARGET_CLIENT_IDS = {
  "gateway", "bridge", "admin", "master", "collector", "sensor_01"
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

action = function(host, port)
  local out = stdnse.output_table()
  local accepted_client_ids = {}

  for _, cid in ipairs(TARGET_CLIENT_IDS) do
    local sock = nmap.new_socket()
    sock:set_timeout(3500)

    local ok = sock:connect(host, port, "tcp")
    if ok then
      sock:send(build_connect(cid))
      local st, resp = sock:receive_bytes(4)
      sock:close()

      if st and resp and #resp >= 4 and string.byte(resp, 1) == 0x20 and string.byte(resp, 4) == 0x00 then
        table.insert(accepted_client_ids, cid)
      end
    end
  end

  out["Risk Level"] = "🟠 HIGH"

  if #accepted_client_ids > 0 then
    out["Status"] = string.format("VULNERABLE - %d fixed/privileged Client ID(s) accepted anonymously", #accepted_client_ids)
    out["Accepted Client IDs"] = accepted_client_ids
    out["Assessment"] = "The broker allows arbitrary anonymous clients to connect using predictable static Client IDs. An attacker can hijack existing sessions and repeatedly disconnect legitimate IoT devices (Client ID Collision DoS)."
    out["Remediation"] = "Enforce Client ID prefix validation, bind Client IDs to TLS client certificate Common Names (use_identity_as_username), or restrict Client ID assignment."
  else
    out["Status"] = "SECURE - Broker rejected arbitrary static Client IDs."
  end

  return out
end
