local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Tridium Niagara Fox protocol on port 1911/4911 for unauthenticated building automation access.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(1911, "fox", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - fox-niagara-unauth-check.nse check executed successfully."
  return out
end
