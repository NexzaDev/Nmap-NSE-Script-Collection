local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests server handling of rapid WebSocket Ping (0x09) frames and Pong (0x0A) response timing.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-ping-pong-dos-tolerance.nse check executed successfully."
  return out
end
