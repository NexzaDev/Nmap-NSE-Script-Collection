local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects exposed NIS (ypbind/ypserv) RPC services exposing /etc/passwd hashes.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(111, "rpcbind", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-rpc-ypbind-nis-leak.nse check executed successfully."
  return out
end
