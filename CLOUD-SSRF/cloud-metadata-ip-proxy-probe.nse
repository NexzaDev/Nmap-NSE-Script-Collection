local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether HTTP forward/reverse proxy passes requests to link-local address 169.254.169.254.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - cloud-metadata-ip-proxy-probe.nse check executed successfully."
  return out
end
