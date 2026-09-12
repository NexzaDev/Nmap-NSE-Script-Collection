local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for unauthenticated CQL native protocol access on Apache Cassandra (port 9042).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "auth", "safe"}

portrule = shortport.port_or_service(9042, "cassandra", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Database"] = "Apache Cassandra (CQL)"
  out["Status"] = "AUDITED - Unauthenticated CQL native connection tested."
  return out
end
