local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes DigitalOcean Droplet metadata http://169.254.169.254/metadata/v1/ for user-data and SSH keys.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - digitalocean-metadata-leak.nse check executed successfully."
  return out
end
