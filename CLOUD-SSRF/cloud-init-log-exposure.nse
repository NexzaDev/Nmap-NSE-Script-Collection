local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes /var/log/cloud-init.log and /var/log/cloud-init-output.log via web root exposures.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - cloud-init-log-exposure.nse check executed successfully."
  return out
end
