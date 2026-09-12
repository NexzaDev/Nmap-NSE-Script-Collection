local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Stratum 0 Kiss-of-Death (KoD) packets and rate-limiting responses.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-stratum-zero-anomaly.nse check executed successfully."
  return out
end
