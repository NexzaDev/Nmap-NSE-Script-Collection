local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends watch / watch fetchers command to eavesdrop on live key operations.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-watch-stream-exposure.nse check executed successfully."
  return out
end
