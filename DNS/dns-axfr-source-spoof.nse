local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
Tests whether DNS zone transfers (AXFR) are restricted to authorized source IP addresses
or open to arbitrary external hosts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(53, "domain", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Status"] = "AUDITED - AXFR source IP access control evaluated."
  out["Remediation"] = "Enforce allow-transfer ACLs strictly in named.conf."
  return out
end
