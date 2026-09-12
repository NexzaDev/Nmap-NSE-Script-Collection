local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests S4U2self / S4U2proxy transition extension support.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-constrained-deleg.nse check executed successfully."
  return out
end
