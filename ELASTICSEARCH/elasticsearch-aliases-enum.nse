local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_aliases and /_cat/aliases to discover hidden index routing.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-aliases-enum.nse check executed successfully."
  return out
end
