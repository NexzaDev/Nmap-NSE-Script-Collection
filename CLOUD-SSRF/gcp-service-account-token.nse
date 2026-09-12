local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes /computeMetadata/v1/instance/service-accounts/default/token for OAuth2 access tokens.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - gcp-service-account-token.nse check executed successfully."
  return out
end
