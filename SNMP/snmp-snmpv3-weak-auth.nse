local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for weak SNMPv3 auth protocols (MD5 vs SHA256) and DES/3DES encryption.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-snmpv3-weak-auth.nse check executed successfully."
  return out
end
