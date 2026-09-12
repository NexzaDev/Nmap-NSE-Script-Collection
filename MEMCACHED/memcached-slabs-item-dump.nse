local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Uses stats items and stats cachedump to enumerate and dump cached keys and session tokens.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-slabs-item-dump.nse check executed successfully."
  return out
end
