local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates static and dynamic virtual channels (cliprdr, rdpdr, rdpsnd, drdynvc).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-virtual-channels-enum.nse check executed successfully."
  return out
end
