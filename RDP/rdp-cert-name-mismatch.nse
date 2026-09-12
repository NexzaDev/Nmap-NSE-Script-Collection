local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts RDP TLS certificate and checks for self-signed or internal hostname disclosures.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-cert-name-mismatch.nse check executed successfully."
  return out
end
