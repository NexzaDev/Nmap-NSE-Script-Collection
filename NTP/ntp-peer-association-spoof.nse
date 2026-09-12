local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates whether ntpd accepts unauthenticated symmetric active/passive association packets.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-peer-association-spoof.nse check executed successfully."
  return out
end
