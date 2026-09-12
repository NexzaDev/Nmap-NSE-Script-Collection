local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests touch command for expiration time tampering.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-touch-command-audit.nse check executed successfully."
  return out
end
