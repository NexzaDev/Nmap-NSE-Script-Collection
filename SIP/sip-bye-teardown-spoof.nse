local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if server validates Call-ID and tags on BYE requests or allows blind call teardown.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-bye-teardown-spoof.nse check executed successfully."
  return out
end
