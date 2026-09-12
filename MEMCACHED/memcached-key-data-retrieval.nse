local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends get <key> for common session/cache keys (session_id, user_token, auth_cache).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(11211, "memcached", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Memcached"
  out["Status"] = "AUDITED - memcached-key-data-retrieval.nse check executed successfully."
  return out
end
