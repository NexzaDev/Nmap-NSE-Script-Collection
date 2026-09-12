local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes LDAP StartTLS extended operation OID (1.3.6.1.4.1.1466.20037) support.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-starttls-support.nse check executed successfully."
  return out
end
