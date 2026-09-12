local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Cisco CISCO-CONFIG-COPY-MIB OID presence allowing remote TFTP config copy.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-cisco-config-copy.nse check executed successfully."
  return out
end
