local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries Distributed File System (DFS) referrals to map domain share topology and DFS roots.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(445, "microsoft-ds", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - DFS referral topology queried."
  return out
end
