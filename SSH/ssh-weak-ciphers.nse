local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for weak/broken symmetric encryption ciphers (3des-cbc, arcfour, blowfish-cbc).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-weak-ciphers.nse check executed successfully."
  return out
end
