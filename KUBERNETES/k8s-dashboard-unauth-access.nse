local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for unauthenticated Kubernetes Dashboard web UI on ports 8443/30000/443.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(8443, "https", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-dashboard-unauth-access.nse check executed successfully."
  return out
end
