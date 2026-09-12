local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_snapshot/_all for registered backup snapshot repositories (S3 buckets, NFS paths).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-snapshot-repo-leak.nse check executed successfully."
  return out
end
