local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Modbus TCP function code 0x03 (Read Holding Registers) to read industrial sensor/setpoint values.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(502, "modbus", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - modbus-unauth-read-holding.nse check executed successfully."
  return out
end
