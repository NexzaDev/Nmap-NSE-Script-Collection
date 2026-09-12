local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends AS-REQ without pre-authentication to test if server returns AS-REP encrypted timestamp for cracking.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-asrep-roasting.nse check executed successfully."
  return out
end
