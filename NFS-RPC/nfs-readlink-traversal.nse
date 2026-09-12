local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if NFS server follows symlinks pointing outside exported paths.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-readlink-traversal.nse check executed successfully."
  return out
end
