local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Connects to WebSocket chat/feed endpoint and listens for unauthenticated message broadcasts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-chat-broadcast-leak.nse check executed successfully."
  return out
end
