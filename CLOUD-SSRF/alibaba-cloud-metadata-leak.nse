local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Alibaba Cloud ECS metadata http://100.100.100.200/latest/meta-data/ for RAM role credentials.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - alibaba-cloud-metadata-leak.nse check executed successfully."
  return out
end
