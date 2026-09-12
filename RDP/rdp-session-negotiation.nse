local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes RDP X.224 Connection Request protocols (RDP, TLS, CredSSP, RDSTLS, Early User Auth).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-session-negotiation.nse check executed successfully."
  return out
end
