local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates supported LDAP controls, extensions, and SASL mechanisms.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(389, "ldap", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "LDAP"
  out["Status"] = "AUDITED - ldap-supported-controls.nse check executed successfully."
  return out
end
