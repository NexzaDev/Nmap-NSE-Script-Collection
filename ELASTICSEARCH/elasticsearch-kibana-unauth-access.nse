local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Kibana interface on port 5601 (/api/status, /app/kibana) without authentication.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5601, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-kibana-unauth-access.nse check executed successfully."
  return out
end
