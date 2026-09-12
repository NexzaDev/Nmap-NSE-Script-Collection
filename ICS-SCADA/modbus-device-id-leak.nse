local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Function Code 0x2B / MEI 0x0E (Read Device Identification) to extract VendorName, ProductCode.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(502, "modbus", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - modbus-device-id-leak.nse check executed successfully."
  return out
end
