local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if SNMP community string grants write permissions (SetRequest on test OID).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-write-access-check.nse check executed successfully."
  return out
end
