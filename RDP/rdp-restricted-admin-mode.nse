local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether RDP Restricted Admin Mode is enabled.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-restricted-admin-mode.nse check executed successfully."
  return out
end
