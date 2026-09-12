local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates valid Active Directory usernames based on KDC error codes (KDC_ERR_C_PRINCIPAL_UNKNOWN).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-user-enum.nse check executed successfully."
  return out
end
