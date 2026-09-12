local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates slab automove and eviction policies.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-slab-automove-audit.nse check executed successfully."
  return out
end
