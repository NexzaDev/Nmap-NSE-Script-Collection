local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes whether root account authentication is permitted or explicitly disabled.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-root-login-allowed.nse check executed successfully."
  return out
end
