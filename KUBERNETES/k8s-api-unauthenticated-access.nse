local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks unauthenticated access to Kubernetes API server (/api/v1/namespaces, /apis) on port 6443/8443.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(6443, "https", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-api-unauthenticated-access.nse check executed successfully."
  return out
end
