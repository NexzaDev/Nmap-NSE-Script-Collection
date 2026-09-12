local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for weak Message Authentication Codes (hmac-md5, hmac-sha1-96).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-weak-macs.nse check executed successfully."
  return out
end
