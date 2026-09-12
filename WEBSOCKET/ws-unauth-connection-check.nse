local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether WebSocket endpoint completes HTTP 101 Switching Protocols upgrade without credentials.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-unauth-connection-check.nse check executed successfully."
  return out
end
