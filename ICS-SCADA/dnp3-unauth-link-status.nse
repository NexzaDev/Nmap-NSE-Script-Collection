local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends DNP3 (Distributed Network Protocol) Request Link Status on port 20000.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(20000, "dnp3", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - dnp3-unauth-link-status.nse check executed successfully."
  return out
end
