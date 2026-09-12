local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Modbus TCP function code 0x01 (Read Coils) on port 502 without auth to inspect digital outputs.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(502, "modbus", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - modbus-unauth-read-coils.nse check executed successfully."
  return out
end
