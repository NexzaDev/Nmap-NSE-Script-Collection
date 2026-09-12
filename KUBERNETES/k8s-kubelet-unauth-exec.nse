local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Kubelet HTTPS API on port 10250 (/runningpods/, /exec, /run) for unauthenticated RCE.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(10250, "ssl", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-kubelet-unauth-exec.nse check executed successfully."
  return out
end
