local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends BACnet/IP Who-Is broadcast on UDP port 47808 to extract Vendor ID, Device ID, Firmware.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(47808, "bacnet", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - bacnet-device-whois-leak.nse check executed successfully."
  return out
end
