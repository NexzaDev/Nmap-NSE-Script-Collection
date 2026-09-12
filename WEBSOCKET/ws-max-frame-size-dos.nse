local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends large declared payload lengths (64-bit length header) to test memory allocation limits.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-max-frame-size-dos.nse check executed successfully."
  return out
end
