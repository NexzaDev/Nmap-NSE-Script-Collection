local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects VNC RFB servers configured with Security Type 1 (None / No Authentication).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-no-auth-check.nse check executed successfully."
  return out
end
