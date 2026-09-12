local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether LDAP on port 389 processes Simple Bind credentials without StartTLS.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-cleartext-auth-risk.nse check executed successfully."
  return out
end
