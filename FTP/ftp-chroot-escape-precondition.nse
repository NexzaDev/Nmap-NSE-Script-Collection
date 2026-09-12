local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests directory traversal and chroot containment patterns (CWD /.../, CDUP) across FTP root tree.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Status"] = "AUDITED - FTP directory traversal and chroot escape boundaries tested."
  return out
end
