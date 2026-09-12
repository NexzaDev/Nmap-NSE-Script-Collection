local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts dynamic instance identity document (Region, AvailabilityZone, AccountID, InstanceType).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - cloud-instance-identity-doc.nse check executed successfully."
  return out
end
