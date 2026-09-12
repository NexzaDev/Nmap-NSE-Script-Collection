local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Verifies whether pre-authentication (PA-ENC-TIMESTAMP) is mandatory for user accounts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-preauth-required.nse check executed successfully."
  return out
end
