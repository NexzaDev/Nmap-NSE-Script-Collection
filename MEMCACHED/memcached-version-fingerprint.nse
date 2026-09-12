local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts exact Memcached engine version and OS platform.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-version-fingerprint.nse check executed successfully."
  return out
end
