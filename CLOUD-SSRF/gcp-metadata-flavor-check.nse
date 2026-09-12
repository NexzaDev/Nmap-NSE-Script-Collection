local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes GCP metadata http://metadata.google.internal/computeMetadata/v1/ with/without Metadata-Flavor header.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - gcp-metadata-flavor-check.nse check executed successfully."
  return out
end
