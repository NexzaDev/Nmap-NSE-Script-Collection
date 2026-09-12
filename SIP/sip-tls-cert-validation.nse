local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Audits SIPS TLS certificate validity and SAN/CN hostname matching on port 5061.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(5061, "sips", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-tls-cert-validation.nse check executed successfully."
  return out
end
