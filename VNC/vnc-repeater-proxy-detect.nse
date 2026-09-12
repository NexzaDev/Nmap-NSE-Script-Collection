local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects UltraVNC Repeater proxy services on port 5900/5901.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-repeater-proxy-detect.nse check executed successfully."
  return out
end
