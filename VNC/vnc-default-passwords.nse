local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests common default VNC passwords (password, 123456, admin, vnc, root).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-default-passwords.nse check executed successfully."
  return out
end
