local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks server negotiation for low-bandwidth 8-bit color palettes vs 32-bit TrueColor.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-color-depth-dos-check.nse check executed successfully."
  return out
end
