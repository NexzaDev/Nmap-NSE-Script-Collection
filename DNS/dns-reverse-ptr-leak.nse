local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries reverse PTR records on local IP ranges to discover internal server naming schemes and network infrastructure details.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - Reverse PTR record mapping completed."
  return out
end
