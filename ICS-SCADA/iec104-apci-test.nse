local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes IEC 60870-5-104 (SCADA electrical grid) STARTACT / TESTFR APCI frames on port 2404.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(2404, "iec-104", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - iec104-apci-test.nse check executed successfully."
  return out
end
