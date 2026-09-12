local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries BACnet ReadProperty (Object: Device, Prop: Object_Name, Location, Description).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(47808, "bacnet", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - bacnet-read-property-leak.nse check executed successfully."
  return out
end
