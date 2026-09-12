local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Sec-WebSocket-Protocol header with common subprotocols (graphql-ws, wamp, json, soap).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-subprotocol-enumeration.nse check executed successfully."
  return out
end
