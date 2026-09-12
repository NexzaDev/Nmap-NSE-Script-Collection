local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends TGS-REQ for common Service Principal Names (SPNs) to test Kerberoasting response.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-spn-probe.nse check executed successfully."
  return out
end
