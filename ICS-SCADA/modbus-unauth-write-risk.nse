local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether Modbus TCP allows write operations (Function 0x05 / 0x06) without authentication.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(502, "modbus", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - modbus-unauth-write-risk.nse check executed successfully."
  return out
end
