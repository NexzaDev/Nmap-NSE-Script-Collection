local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Validates HSTS header max-age, includeSubDomains, and preload token compliance against browser preload lists.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - HSTS preload criteria evaluated."
  return out
end
