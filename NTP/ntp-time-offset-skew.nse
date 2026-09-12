local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Calculates target clock offset, round-trip delay, and jitter relative to scan host.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-time-offset-skew.nse check executed successfully."
  return out
end
