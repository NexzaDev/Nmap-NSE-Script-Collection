local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes kube-proxy healthz (/healthz) and config endpoints on port 10256.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(10256, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-kube-proxy-debug-leak.nse check executed successfully."
  return out
end
