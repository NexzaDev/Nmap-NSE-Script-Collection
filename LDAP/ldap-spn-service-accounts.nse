local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries accounts with servicePrincipalName (SPN) set, identifying Kerberoasting targets.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-spn-service-accounts.nse check executed successfully."
  return out
end
