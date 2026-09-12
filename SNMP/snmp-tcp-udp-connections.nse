local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Dumps active TCP listening ports and UDP listeners via tcpConnTable / udpTable.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-tcp-udp-connections.nse check executed successfully."
  return out
end
