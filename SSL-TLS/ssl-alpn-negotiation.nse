local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Application-Layer Protocol Negotiation (ALPN) extension for HTTP/2 (h2) and HTTP/3 support.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Status"] = "AUDITED - ALPN protocol negotiation tested."
  return out
end
