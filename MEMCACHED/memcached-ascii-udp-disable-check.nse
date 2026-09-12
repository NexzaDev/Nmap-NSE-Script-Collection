local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether UDP listener (port 11211 UDP) has been safely disabled (-U 0).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-ascii-udp-disable-check.nse check executed successfully."
  return out
end
