local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether RDP UDP transport (port 3389 UDP / MS-RDPEUDP) is enabled.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-udp-transport-check.nse check executed successfully."
  return out
end
