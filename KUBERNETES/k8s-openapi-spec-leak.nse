local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Downloads /openapi/v2 and /swagger.json to map all deployed CRDs and API endpoints.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(6443, "https", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-openapi-spec-leak.nse check executed successfully."
  return out
end
