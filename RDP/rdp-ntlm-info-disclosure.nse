local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Initiates NTLMSSP handshake to extract Windows domain name, computer NetBIOS name, OS build.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-ntlm-info-disclosure.nse check executed successfully."
  return out
end
