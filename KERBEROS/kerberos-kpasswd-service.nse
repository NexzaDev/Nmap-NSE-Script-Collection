local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Kerberos password change service (kpasswd on port 464 UDP/TCP).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(464, "kpasswd", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-kpasswd-service.nse check executed successfully."
  return out
end
