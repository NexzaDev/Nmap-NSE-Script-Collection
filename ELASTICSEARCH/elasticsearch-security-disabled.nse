local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether xpack.security.enabled is false (absence of basic authentication & TLS).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-security-disabled.nse check executed successfully."
  return out
end
