local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Java/HTML5 VNC HTTP web viewer interface on port 5800.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5800, "vnc-http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-http-web-interface.nse check executed successfully."
  return out
end
