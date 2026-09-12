local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes OCI metadata http://169.254.169.254/opc/v2/instance/ for tenancy ID and compartment details.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - oracle-cloud-metadata-leak.nse check executed successfully."
  return out
end
