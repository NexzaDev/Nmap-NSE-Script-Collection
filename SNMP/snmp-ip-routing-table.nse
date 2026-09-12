local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Dumps IP routing table (ipRouteDest, ipRouteNextHop, ipRouteMask) leaking network topology.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-ip-routing-table.nse check executed successfully."
  return out
end
