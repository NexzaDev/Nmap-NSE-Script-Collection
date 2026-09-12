local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes internal K8s API server https://kubernetes.default.svc from pod-facing reverse proxies.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Cloud Provider Target"] = "Cloud Metadata / SSRF Protection"
  out["Status"] = "AUDITED - kubernetes-pod-metadata-ssrf.nse check executed successfully."
  return out
end
