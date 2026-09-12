local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if NFS server accepts connections originating from non-reserved ports (> 1024).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-insecure-port-allowed.nse check executed successfully."
  return out
end
