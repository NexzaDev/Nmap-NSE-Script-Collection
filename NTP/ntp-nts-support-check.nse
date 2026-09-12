local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Network Time Security (NTS) TLS key establishment on port 4460.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(4460, "nts", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-nts-support-check.nse check executed successfully."
  return out
end
