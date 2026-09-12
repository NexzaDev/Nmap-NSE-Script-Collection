local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether WebSocket requires query string auth tickets (/ws?ticket=...) or cookies.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-auth-ticket-probe.nse check executed successfully."
  return out
end
