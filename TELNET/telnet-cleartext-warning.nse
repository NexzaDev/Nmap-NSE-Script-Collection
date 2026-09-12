local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Flags unencrypted cleartext terminal transport on port 23 and passive credential sniffing risk.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-cleartext-warning.nse check executed successfully."
  return out
end
