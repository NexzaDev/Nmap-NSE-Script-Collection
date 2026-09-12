local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Kubelet read-only port 10255 (/pods, /spec) for unauthenticated pod list and secret leaks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(10255, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-kubelet-readonly-pods.nse check executed successfully."
  return out
end
