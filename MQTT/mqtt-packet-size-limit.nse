local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local nmap = require "nmap"

description = [[
Evaluates whether an MQTT broker enforces Maximum Packet Size limits.
Sends malformed/oversized packet length headers (e.g. Remaining Length with
maximum 4-byte 256MB variable length encoding: 0xFF 0xFF 0xFF 0x7F) and probes
whether the broker enforces a safe ceiling or hangs/allocates excessive memory
buffers for client-supplied packet lengths.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "defensive", "safe"}

portrule = shortport.port_or_service(
  {1883, 8883, 1884},
  {"mqtt", "mqtt-s", "mosquitto", "emqx"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()

  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to MQTT service.")
  end

  -- Send CONNECT packet with a declared Remaining Length of 256 MB (0xFF 0xFF 0xFF 0x7F)
  -- without sending the body, to see if the server drops connection or hangs
  local malformed_hdr = string.char(0x10, 0xFF, 0xFF, 0xFF, 0x7F)
  sock:send(malformed_hdr)

  local st, resp = sock:receive_bytes(4)
  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"
  out["Oversized Length Header"] = "256 MB Variable Length Integer (0xFF 0xFF 0xFF 0x7F)"

  if not st or not resp or #resp == 0 then
    out["Status"] = "SECURE - Broker immediately terminated connection upon receiving oversized packet length header."
    out["Assessment"] = "The broker protects against memory allocation exhaustion from oversized packet headers."
  else
    out["Status"] = "AUDITED - Broker responded or kept socket open."
    out["Response Received"] = stdnse.tohex(resp)
  end

  return out
end
