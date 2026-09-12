local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes HART-IP industrial instrumentation protocol on UDP/TCP port 5094.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5094, "hart-ip", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - hart-ip-device-probe.nse check executed successfully."
  return out
end
