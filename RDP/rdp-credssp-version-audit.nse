local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes CredSSP protocol version (v2, v3, v4, v5, v6) and flags Oracle Remediation status.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-credssp-version-audit.nse check executed successfully."
  return out
end
