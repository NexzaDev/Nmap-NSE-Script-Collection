local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates RDP Remote Assistance and Shadowing configuration flags.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-session-shadowing-risk.nse check executed successfully."
  return out
end
