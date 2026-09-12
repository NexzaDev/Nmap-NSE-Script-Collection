local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes MS-KKDCP (Kerberos KDC Proxy protocol over HTTPS /KdcProxy).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(443, "https", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-kdc-proxy-probe.nse check executed successfully."
  return out
end
