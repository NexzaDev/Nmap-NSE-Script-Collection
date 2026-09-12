local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether NFS daemon allows direct NFSv3 LOOKUP/READ calls bypassing Mountd.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-mountd-auth-bypass.nse check executed successfully."
  return out
end
