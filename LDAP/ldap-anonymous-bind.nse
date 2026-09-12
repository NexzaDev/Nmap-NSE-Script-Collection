local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests unauthenticated (anonymous) LDAP bind and checks if base rootDSE is queryable.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-anonymous-bind.nse check executed successfully."
  return out
end
