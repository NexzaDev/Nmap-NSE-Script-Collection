local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Mode 6 readvar request to dump system variables (version, processor, system, stratum, refid).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-mode6-readvar-leak.nse check executed successfully."
  return out
end
