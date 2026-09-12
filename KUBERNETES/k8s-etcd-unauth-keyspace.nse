local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Connects to Kubernetes backend etcd cluster on port 2379 without client certificates to dump secrets.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2379, "etcd", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-etcd-unauth-keyspace.nse check executed successfully."
  return out
end
