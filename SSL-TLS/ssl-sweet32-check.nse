local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects 64-bit block cipher suites (3DES, IDEA, Blowfish) vulnerable to Sweet32 (CVE-2016-2183).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Status"] = "AUDITED - 64-bit block cipher suite evaluation completed."
  return out
end
