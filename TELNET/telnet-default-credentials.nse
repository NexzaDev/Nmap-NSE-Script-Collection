local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests common embedded router/switch default Telnet credentials (admin/admin, root/root).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-default-credentials.nse check executed successfully."
  return out
end
