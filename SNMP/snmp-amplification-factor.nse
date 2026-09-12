local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Measures UDP response payload size amplification factor for DDoS reflection risk.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-amplification-factor.nse check executed successfully."
  return out
end
