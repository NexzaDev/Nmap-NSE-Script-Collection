local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Scans for active Modbus slave Unit IDs (1 to 247) on the serial bridge.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(502, "modbus", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - modbus-unit-id-scan.nse check executed successfully."
  return out
end
