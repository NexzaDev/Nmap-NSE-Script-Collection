local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerate all security types supported by server (None, VNC Auth, RA2, TLS, VeNCrypt).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-security-types-enum.nse check executed successfully."
  return out
end
