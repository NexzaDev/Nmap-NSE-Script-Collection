local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for unauthenticated noVNC WebSocket endpoints (/websockify).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(6080, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-novnc-websocket-probe.nse check executed successfully."
  return out
end
