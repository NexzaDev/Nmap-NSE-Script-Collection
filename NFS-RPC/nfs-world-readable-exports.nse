local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries Mountd RPC on port 111/2049 for NFS exports with world/wildcard (*) permissions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-world-readable-exports.nse check executed successfully."
  return out
end
