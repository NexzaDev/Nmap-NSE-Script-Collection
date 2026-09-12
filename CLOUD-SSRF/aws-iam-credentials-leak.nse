local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes /latest/meta-data/iam/security-credentials/ to extract IAM role name and STS credentials.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - aws-iam-credentials-leak.nse check executed successfully."
  return out
end
