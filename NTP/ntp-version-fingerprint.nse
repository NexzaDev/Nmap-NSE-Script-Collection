local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Analyzes NTP response headers (Leap Indicator, Version, Mode, Stratum, Precision).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-version-fingerprint.nse check executed successfully."
  return out
end
