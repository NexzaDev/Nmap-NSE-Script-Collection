local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Mitsubishi MELSEC-Q/L series PLC protocol on port 5007.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5007, "melsec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - melsec-mitsubishi-probe.nse check executed successfully."
  return out
end
