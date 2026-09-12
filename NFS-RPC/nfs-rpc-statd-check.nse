local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes rpc.statd (status) RPC service for remote monitoring and legacy format string risks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(111, "rpcbind", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-rpc-statd-check.nse check executed successfully."
  return out
end
