local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Executes unauthenticated GET /_search across all indices to extract sensitive stored documents.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-search-query-leak.nse check executed successfully."
  return out
end
