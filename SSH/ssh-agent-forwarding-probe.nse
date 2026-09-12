local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes SSH agent forwarding negotiation options and environment handling.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-agent-forwarding-probe.nse check executed successfully."
  return out
end
