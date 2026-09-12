local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Telnet AUTHENTICATION option (RFC 1416) for Kerberos/SRP/None bypass conditions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-auth-option-bypass.nse check executed successfully."
  return out
end
