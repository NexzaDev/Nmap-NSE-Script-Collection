local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Attempts authentication against an MQTT broker using a curated set of
common default and weak IoT/industrial credentials (admin/admin, root/root,
mosquitto/mosquitto, emqx/public, hivemq/hivemq, user/password, test/test, iot/iot).
Validates whether the broker accepts default administrative accounts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "auth", "safe"}

portrule = shortport.port_or_service(
  {1883, 8883, 1884},
  {"mqtt", "mqtt-s", "mosquitto", "emqx"},
  "tcp"
)

local DEFAULT_CREDENTIALS = {
  { user = "admin", pass = "admin" },
  { user = "admin", pass = "password" },
  { user = "admin", pass = "123456" },
  { user = "root", pass = "root" },
  { user = "mosquitto", pass = "mosquitto" },
  { user = "emqx", pass = "public" },
  { user = "hivemq", pass = "hivemq" },
  { user = "user", pass = "user" },
  { user = "user", pass = "password" },
  { user = "iot", pass = "iot" },
  { user = "device", pass = "device" },
  { user = "test", pass = "test" },
  { user = "guest", pass = "guest" }
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

local function build_auth_connect(client_id, user, pass)
  local proto = encode_string("MQTT") .. string.char(4)
  -- Connect flags: Username (0x80) + Password (0x40) + CleanSession (0x02) = 0xC2
  local flags = string.char(0xC2)
  local keepalive = string.char(0, 30)

  local var_header = proto .. flags .. keepalive
  local payload = encode_string(client_id) .. encode_string(user) .. encode_string(pass)

  return string.char(0x10) .. encode_remaining_length(#var_header + #payload) .. var_header .. payload
end

action = function(host, port)
  local out = stdnse.output_table()
  local valid_creds = {}

  for _, cred in ipairs(DEFAULT_CREDENTIALS) do
    local sock = nmap.new_socket()
    sock:set_timeout(3500)

    local ok = sock:connect(host, port, "tcp")
    if ok then
      local cid = "audit_" .. string.sub(stdnse.generate_random_string(6), 1, 6)
      local pkt = build_auth_connect(cid, cred.user, cred.pass)
      sock:send(pkt)

      local st, resp = sock:receive_bytes(4)
      sock:close()

      if st and resp and #resp >= 4 then
        local ptype = string.byte(resp, 1)
        local rc = string.byte(resp, 4)
        if ptype == 0x20 and rc == 0x00 then
          table.insert(valid_creds, string.format("Username: '%s' | Password: '%s'", cred.user, cred.pass))
        end
      end
    end
  end

  out["Risk Level"] = "🔴 CRITICAL"

  if #valid_creds > 0 then
    out["Status"] = string.format("VULNERABLE - %d default credential pair(s) accepted by MQTT broker", #valid_creds)
    out["Valid Default Credentials"] = valid_creds
    out["Assessment"] = "The MQTT broker accepted login with known factory/default credentials, permitting unauthorized administrative access."
    out["Remediation"] = "Change all default credentials immediately, enforce strong unique passwords, and consider certificate-based mTLS authentication."
  else
    out["Status"] = "SECURE - None of the tested common default credential pairs were accepted."
  end

  return out
end
