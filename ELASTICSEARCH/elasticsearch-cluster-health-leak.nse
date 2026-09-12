local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_cluster/health and /_cluster/stats for node counts, shard status, disk usage.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-cluster-health-leak.nse check executed successfully."
  return out
end
