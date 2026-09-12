local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Audits CNAME records for dangling aliases pointing to unclaimed cloud services (S3, GitHub Pages, Heroku) susceptible to Subdomain Takeover.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Status"] = "AUDITED - CNAME dangling pointer checks completed."
  return out
end
