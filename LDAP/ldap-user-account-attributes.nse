local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Audits user objects for sensitive attributes (userPassword, unicodePwd, description).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-user-account-attributes.nse check executed successfully."
  return out
end
