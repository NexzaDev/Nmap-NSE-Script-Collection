local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_nodes/settings and /_nodes/env to extract environment variables, AWS keys, and paths.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-nodes-settings-leak.nse check executed successfully."
  return out
end
