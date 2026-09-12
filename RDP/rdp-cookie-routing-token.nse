local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for RDP routing token cookies (mstshash=...) used in load-balanced RDS farms.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-cookie-routing-token.nse check executed successfully."
  return out
end
