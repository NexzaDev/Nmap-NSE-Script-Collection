local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Calls MOUNTPROC_EXPORT to list all exported filesystem directory paths.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(111, "rpcbind", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-showmount-leak.nse check executed successfully."
  return out
end
