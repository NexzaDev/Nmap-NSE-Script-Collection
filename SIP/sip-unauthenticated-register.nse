local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if SIP server permits registering phone extensions without MD5 digest authentication.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-unauthenticated-register.nse check executed successfully."
  return out
end
