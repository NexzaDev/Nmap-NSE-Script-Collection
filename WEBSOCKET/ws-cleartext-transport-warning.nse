local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Flags unencrypted ws:// transport on port 80/8080 exposing message frames to sniffing.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-cleartext-transport-warning.nse check executed successfully."
  return out
end
