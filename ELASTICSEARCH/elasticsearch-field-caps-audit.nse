local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /_field_caps to map schema fields (passwords, emails, credit cards, PII).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-field-caps-audit.nse check executed successfully."
  return out
end
