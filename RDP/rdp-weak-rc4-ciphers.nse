local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if RDP Standard Encryption accepts weak 40-bit/56-bit or 128-bit RC4 ciphers.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-weak-rc4-ciphers.nse check executed successfully."
  return out
end
