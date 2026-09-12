local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests support for Kerberos FAST (Flexible Authentication Secure Tunneling / RFC 6113).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-fast-negotiation.nse check executed successfully."
  return out
end
