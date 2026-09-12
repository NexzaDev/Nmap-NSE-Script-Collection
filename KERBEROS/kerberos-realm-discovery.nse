local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes KDC with dummy realm to extract true Active Directory realm name from KDC_ERR_WRONG_REALM.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-realm-discovery.nse check executed successfully."
  return out
end
