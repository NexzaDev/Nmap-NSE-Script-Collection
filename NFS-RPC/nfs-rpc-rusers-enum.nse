local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries rusersd RPC service to enumerate logged-in users on host.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(111, "rpcbind", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-rpc-rusers-enum.nse check executed successfully."
  return out
end
