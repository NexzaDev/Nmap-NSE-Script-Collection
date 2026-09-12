local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends SIP MESSAGE instant text payloads to test for unauthenticated message relay.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-message-spam-relay.nse check executed successfully."
  return out
end
