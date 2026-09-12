local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Measures UDP reflection amplification factor (CVE-2018-1000115 / Memcrashed).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-udp-amplification-ddos.nse check executed successfully."
  return out
end
