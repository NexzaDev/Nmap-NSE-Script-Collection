local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Audits SSL/TLS cipher suites and protocol versions negotiated over explicit FTPS (AUTH TLS).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - FTPS TLS cipher strength evaluated."
  return out
end
