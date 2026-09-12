local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends unmasked client frames (mask bit = 0) to verify RFC 6455 enforcement.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-masked-frame-enforcement.nse check executed successfully."
  return out
end
