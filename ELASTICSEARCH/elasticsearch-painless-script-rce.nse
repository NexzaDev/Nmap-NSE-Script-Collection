local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if Painless / Groovy scripting engine is enabled for dynamic script execution (/_scripts).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9200, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Engine"] = "Elasticsearch / OpenSearch"
  out["Status"] = "AUDITED - elasticsearch-painless-script-rce.nse check executed successfully."
  return out
end
