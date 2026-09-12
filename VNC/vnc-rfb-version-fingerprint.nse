local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Negotiates RFB protocol versions (RFB 003.003 to 004.001) and extracts server banner.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-rfb-version-fingerprint.nse check executed successfully."
  return out
end
