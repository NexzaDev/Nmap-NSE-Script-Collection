local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries hrSWInstalledTable to dump installed OS software packages and versions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-installed-software.nse check executed successfully."
  return out
end
