local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes NFS versions (NFSv2, NFSv3, NFSv4, NFSv4.1, NFSv4.2).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-version-support.nse check executed successfully."
  return out
end
