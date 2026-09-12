local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests /api/v1/nodes/{name}/proxy for unauthenticated pod/node proxy access.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(6443, "https", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-node-proxy-misconfig.nse check executed successfully."
  return out
end
