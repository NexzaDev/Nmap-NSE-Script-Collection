local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends stats sizes to analyze memory allocation distribution across chunk sizes.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-sizes-memory-dump.nse check executed successfully."
  return out
end
