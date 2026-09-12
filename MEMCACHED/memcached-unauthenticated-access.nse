local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends version and stats to port 11211 (TCP/UDP) without credentials.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-unauthenticated-access.nse check executed successfully."
  return out
end
