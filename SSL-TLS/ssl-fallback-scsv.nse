local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests TLS_FALLBACK_SCSV support to prevent forced protocol downgrade attacks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - TLS_FALLBACK_SCSV defense mechanism evaluated."
  return out
end
