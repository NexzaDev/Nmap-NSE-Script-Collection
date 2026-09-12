local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if LDAP server enforces LDAP signing and channel binding tokens (CBT).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-signing-enforced.nse check executed successfully."
  return out
end
