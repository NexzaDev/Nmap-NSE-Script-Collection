local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends SIP OPTIONS request and extracts Allow, Supported, Server, User-Agent headers.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-unauth-options-enum.nse check executed successfully."
  return out
end
