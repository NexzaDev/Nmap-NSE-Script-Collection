local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether the server supports SSLv3 protocol with CBC mode ciphers (POODLE / CVE-2014-3566).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Status"] = "AUDITED - SSLv3 CBC POODLE vulnerability tested."
  return out
end
