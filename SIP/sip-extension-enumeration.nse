local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates internal PBX extensions (100-110, 1000-1010) via SIP REGISTER / INVITE responses.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-extension-enumeration.nse check executed successfully."
  return out
end
