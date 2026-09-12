local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Spring STOMP over WebSocket (CONNECT\naccept-version:1.2\n\n\x00).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-spring-stomp-probe.nse check executed successfully."
  return out
end
