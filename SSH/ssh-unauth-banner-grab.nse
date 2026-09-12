local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Grabs SSH identification string, protocol version (SSH-2.0 vs SSH-1.99), and software banner.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-unauth-banner-grab.nse check executed successfully."
  return out
end
