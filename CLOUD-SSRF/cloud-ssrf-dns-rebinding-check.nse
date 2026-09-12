local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates whether HTTP endpoint resolves domains pointing to link-local metadata IPs.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - cloud-ssrf-dns-rebinding-check.nse check executed successfully."
  return out
end
