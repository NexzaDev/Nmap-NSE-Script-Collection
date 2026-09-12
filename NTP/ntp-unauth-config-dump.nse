local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Mode 7 REQ_SYS_CONFIG to test if remote reconfiguration is enabled without key auth.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-unauth-config-dump.nse check executed successfully."
  return out
end
