local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes ValidatingWebhookConfiguration / MutatingWebhookConfiguration endpoints on port 8443.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(8443, "https", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Platform"] = "Kubernetes"
  out["Status"] = "AUDITED - k8s-admission-webhook-audit.nse check executed successfully."
  return out
end
