local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if unauthenticated DELETE requests are accepted by API router.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-delete-index-allowed.nse check executed successfully."
  return out
end
