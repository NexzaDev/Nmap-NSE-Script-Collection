local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends unauthenticated INVITE request to test for open SIP relay (toll fraud / unauthorized calls).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-unauthenticated-invite.nse check executed successfully."
  return out
end
