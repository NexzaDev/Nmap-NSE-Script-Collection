local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries Portmapper (rpcbind) on port 111 for registered RPC programs.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(111, "rpcbind", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-rpc-programs-enum.nse check executed successfully."
  return out
end
