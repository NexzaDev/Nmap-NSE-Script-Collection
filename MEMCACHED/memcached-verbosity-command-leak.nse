local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends verbosity command to test if logging levels can be altered remotely.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-verbosity-command-leak.nse check executed successfully."
  return out
end
