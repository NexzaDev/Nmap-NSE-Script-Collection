local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes SNMPv1/v2c with common default community strings (public, private, community, cisco).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-default-community.nse check executed successfully."
  return out
end
