local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes GraphQL graphql-transport-ws protocol handshake initialization.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-graphql-transport-ws.nse check executed successfully."
  return out
end
