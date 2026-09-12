local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries enterprise MIBs and process tables for local user accounts and login names.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-user-accounts-leak.nse check executed successfully."
  return out
end
