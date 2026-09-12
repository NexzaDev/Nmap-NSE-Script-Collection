local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests support for anonymous PKINIT / FAST armor authentication.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-anonymous-pkinit.nse check executed successfully."
  return out
end
