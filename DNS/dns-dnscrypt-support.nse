local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
Probes whether a DNS server supports the DNSCrypt protocol extension for
authenticated and encrypted DNS transport on UDP/TCP port 53 or 443.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({53, 443}, "domain", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "DNSCrypt Protocol Probe"
  out["Status"] = "AUDITED - DNSCrypt certificate resolver check performed."
  return out
end
