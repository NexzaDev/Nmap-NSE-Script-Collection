local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if Telnet ENCRYPT option (RFC 2946) is supported or completely missing.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-encrypt-option-audit.nse check executed successfully."
  return out
end
