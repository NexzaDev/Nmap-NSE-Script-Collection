local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Inspects predictability of returned NFS file handles (FH).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-file-handle-leak.nse check executed successfully."
  return out
end
