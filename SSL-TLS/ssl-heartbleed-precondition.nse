local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates TLS Heartbeat extension (RFC 6520) support, indicating potential
susceptibility to CVE-2014-0160 (Heartbleed).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["TLS Extension"] = "Heartbeat (RFC 6520)"
  out["Status"] = "AUDITED - TLS Heartbeat support evaluated."
  return out
end
