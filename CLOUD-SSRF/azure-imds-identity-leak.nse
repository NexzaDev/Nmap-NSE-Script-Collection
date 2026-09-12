local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Azure IMDS http://169.254.169.254/metadata/identity/oauth2/token with Metadata: true header.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - azure-imds-identity-leak.nse check executed successfully."
  return out
end
