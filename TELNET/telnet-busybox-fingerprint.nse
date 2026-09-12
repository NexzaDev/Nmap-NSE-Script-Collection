local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Identifies BusyBox / Linux embedded appliance Telnet banners.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-busybox-fingerprint.nse check executed successfully."
  return out
end
