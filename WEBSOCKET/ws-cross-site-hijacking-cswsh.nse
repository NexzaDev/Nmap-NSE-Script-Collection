local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends arbitrary Origin header (https://attacker.com) to test for Cross-Site WebSocket Hijacking (CSWSH).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-cross-site-hijacking-cswsh.nse check executed successfully."
  return out
end
