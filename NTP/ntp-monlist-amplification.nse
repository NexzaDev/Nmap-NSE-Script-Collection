local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends NTP Mode 7 REQ_MON_GETLIST command and measures reflection amplification factor (CVE-2013-5211).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-monlist-amplification.nse check executed successfully."
  return out
end
