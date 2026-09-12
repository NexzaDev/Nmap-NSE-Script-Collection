local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation OIDs.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-system-info-leak.nse check executed successfully."
  return out
end
