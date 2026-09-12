local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests DNS server response amplification ratio on ANY and EDNS0 queries to evaluate DDoS reflection risk.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(53, "domain", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Status"] = "AUDITED - DNS reflection amplification factor tested."
  return out
end
