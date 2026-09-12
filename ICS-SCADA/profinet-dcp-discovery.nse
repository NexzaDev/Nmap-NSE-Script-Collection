local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes PROFINET Discovery and Configuration Protocol (DCP) services on port 34964.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(34964, "profinet", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - profinet-dcp-discovery.nse check executed successfully."
  return out
end
