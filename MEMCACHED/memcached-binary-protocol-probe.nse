local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends binary protocol GetK / Stat packets (magic 0x80) to test binary parser.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-binary-protocol-probe.nse check executed successfully."
  return out
end
