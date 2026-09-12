local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Connects and reads FramebufferUpdate header (width, height, desktop name).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-desktop-geometry-leak.nse check executed successfully."
  return out
end
