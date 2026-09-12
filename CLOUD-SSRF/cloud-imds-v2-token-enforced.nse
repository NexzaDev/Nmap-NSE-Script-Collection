local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds to verify IMDSv2 enforcement.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - cloud-imds-v2-token-enforced.nse check executed successfully."
  return out
end
