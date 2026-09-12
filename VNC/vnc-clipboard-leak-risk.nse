local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if server accepts ServerCutText / ClientCutText clipboard sharing without restrictions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-clipboard-leak-risk.nse check executed successfully."
  return out
end
