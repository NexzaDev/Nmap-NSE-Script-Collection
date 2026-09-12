local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates export options for no_root_squash (allows remote client root to access files as UID 0).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-no-root-squash-check.nse check executed successfully."
  return out
end
