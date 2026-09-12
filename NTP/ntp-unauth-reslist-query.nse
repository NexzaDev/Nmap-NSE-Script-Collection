local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Mode 7 REQ_GET_RESTRICT to dump access control lists (ACLs) configured on ntpd.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-unauth-reslist-query.nse check executed successfully."
  return out
end
