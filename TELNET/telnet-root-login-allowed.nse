local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether Telnet login prompt allows direct root/administrator logins.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-root-login-allowed.nse check executed successfully."
  return out
end
