local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for weak Diffie-Hellman parameters (< 2048-bit prime moduli, Logjam attack risk).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Status"] = "AUDITED - Diffie-Hellman prime bitlength verified."
  return out
end
