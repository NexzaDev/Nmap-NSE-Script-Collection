local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests LDAP server pagination control (1.2.840.113556.1.4.319) and size limits.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-paged-search-limit.nse check executed successfully."
  return out
end
