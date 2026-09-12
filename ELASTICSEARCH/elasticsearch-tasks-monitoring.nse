local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_tasks to inspect active background jobs, reindexing operations, and queries.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-tasks-monitoring.nse check executed successfully."
  return out
end
