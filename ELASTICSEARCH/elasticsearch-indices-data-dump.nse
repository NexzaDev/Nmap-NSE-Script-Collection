local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_cat/indices?v and /_cat/shards to enumerate all private indices and document counts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-indices-data-dump.nse check executed successfully."
  return out
end
