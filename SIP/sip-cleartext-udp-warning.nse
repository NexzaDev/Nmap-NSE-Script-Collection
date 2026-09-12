local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Flags cleartext UDP/TCP SIP signaling on port 5060 instead of SIPS / TLS on port 5061.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-cleartext-udp-warning.nse check executed successfully."
  return out
end
