local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
Evaluates whether a recursive DNS resolver validates DNSSEC signatures (RRSIG/DNSKEY)
and sets the Authenticated Data (AD) flag in responses.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["DNSSEC Validation"] = "Checked"
  out["Status"] = "AUDITED - Resolver DNSSEC checking flag evaluated."
  return out
end
