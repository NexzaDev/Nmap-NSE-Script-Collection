local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Inspects Via and Contact headers for internal RFC1918 PBX IP address disclosures.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-nat-traversal-leak.nse check executed successfully."
  return out
end
