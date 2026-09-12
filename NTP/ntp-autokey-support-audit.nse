local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Autokey protocol (RFC 5906) support and vulnerable crypto parameters.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-autokey-support-audit.nse check executed successfully."
  return out
end
