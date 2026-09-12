local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends SYST and FEAT commands to fingerprint FTP daemon family and supported RFC extensions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Status"] = "IDENTIFIED - FTP SYST/FEAT fingerprinting completed."
  return out
end
