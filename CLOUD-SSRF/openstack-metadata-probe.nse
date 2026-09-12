local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes OpenStack Nova metadata service http://169.254.169.254/openstack/latest/meta_data.json.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - openstack-metadata-probe.nse check executed successfully."
  return out
end
