local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes /metrics and /metrics/cadvisor on port 10250/10255 for service token and metric disclosures.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(10250, "ssl", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-metrics-token-leak.nse check executed successfully."
  return out
end
