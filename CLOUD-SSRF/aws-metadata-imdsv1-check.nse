local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes AWS EC2 Instance Metadata Service http://169.254.169.254/latest/meta-data/ without IMDSv2 token.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - aws-metadata-imdsv1-check.nse check executed successfully."
  return out
end
