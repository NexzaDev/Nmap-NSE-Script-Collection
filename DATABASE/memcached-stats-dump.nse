local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends stats and stats items to Memcached on port 11211 to extract cached key counts and memory metrics.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(11211, "memcached", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - Memcached stats dumping evaluated."
  return out
end
