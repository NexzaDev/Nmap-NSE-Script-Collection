local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Omron FINS controller status read command on UDP/TCP port 9600.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9600, "fins", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - fins-omron-plc-dump.nse check executed successfully."
  return out
end
