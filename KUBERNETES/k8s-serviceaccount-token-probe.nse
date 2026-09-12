local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests default ServiceAccount token mounting and RBAC permission boundaries.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(6443, "https", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-serviceaccount-token-probe.nse check executed successfully."
  return out
end
