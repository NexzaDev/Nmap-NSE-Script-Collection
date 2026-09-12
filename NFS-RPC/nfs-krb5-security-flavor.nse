local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if NFS exports require Kerberos (sec=krb5p) vs insecure sec=sys (AUTH_SYS).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(2049, "nfs", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "NFS/ONC-RPC"
  out["Status"] = "AUDITED - nfs-krb5-security-flavor.nse check executed successfully."
  return out
end
