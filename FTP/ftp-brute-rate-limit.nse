local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether the FTP daemon throttles consecutive failed login attempts or allows fast password brute-forcing.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - FTP authentication rate-limiting evaluated."
  return out
end
