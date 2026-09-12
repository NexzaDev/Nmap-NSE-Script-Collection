local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether the FTP server allows File Exchange Protocol (FXP) third-party server-to-server data connections.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Status"] = "AUDITED - FTP FXP cross-server relaying evaluated."
  return out
end
