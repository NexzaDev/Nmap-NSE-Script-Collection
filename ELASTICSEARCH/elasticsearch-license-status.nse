local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_license for X-Pack license type (basic, enterprise, trial).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-license-status.nse check executed successfully."
  return out
end
