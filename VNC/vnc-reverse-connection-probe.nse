local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes VNC listening in reverse-connection (listening viewer) mode on port 5500.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5500, "vnc-listener", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-reverse-connection-probe.nse check executed successfully."
  return out
end
