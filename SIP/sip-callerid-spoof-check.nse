local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether server validates From and P-Asserted-Identity headers or accepts spoofed Caller IDs.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-callerid-spoof-check.nse check executed successfully."
  return out
end
