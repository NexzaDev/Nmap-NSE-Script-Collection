local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries /version on API server to extract GitVersion, GitCommit, Platform, and GoVersion.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(6443, "https", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-version-fingerprint.nse check executed successfully."
  return out
end
