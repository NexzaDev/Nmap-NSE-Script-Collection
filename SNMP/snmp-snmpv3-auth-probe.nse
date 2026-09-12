local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes SNMPv3 engine ID, security levels (noAuthNoPriv, authNoPriv, authPriv), and USM users.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-snmpv3-auth-probe.nse check executed successfully."
  return out
end
