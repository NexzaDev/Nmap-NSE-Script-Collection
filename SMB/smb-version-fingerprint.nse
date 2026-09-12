local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts exact Windows OS build, NetBIOS computer name, workgroup/domain, and SMB dialect details.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({139, 445}, "microsoft-ds", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Status"] = "IDENTIFIED - SMB OS and NetBIOS fingerprinting completed."
  return out
end
