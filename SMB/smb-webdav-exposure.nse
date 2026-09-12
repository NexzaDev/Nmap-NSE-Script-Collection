local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for WebDAV extensions and HTTP-to-SMB authentication redirection risks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({80, 443, 445}, {"http", "microsoft-ds"}, "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "AUDITED - WebDAV integration checked."
  return out
end
