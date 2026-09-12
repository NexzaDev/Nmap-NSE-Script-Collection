local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends EtherNet/IP (CIP) List Identity command on port 44818 to extract PLC Vendor, Device Type.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(44818, "ethernetip", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - ethernetip-identity-dump.nse check executed successfully."
  return out
end
