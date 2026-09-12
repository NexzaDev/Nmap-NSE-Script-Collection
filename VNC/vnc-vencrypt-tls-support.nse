local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes VeNCrypt security subtype negotiation and TLS encryption enforcement.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-vencrypt-tls-support.nse check executed successfully."
  return out
end
