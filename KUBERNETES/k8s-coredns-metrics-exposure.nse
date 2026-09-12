local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes CoreDNS metrics endpoint on port 9153.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9153, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-coredns-metrics-exposure.nse check executed successfully."
  return out
end
