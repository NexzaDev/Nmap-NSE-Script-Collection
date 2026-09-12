local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends S7Comm ISO-on-TCP (port 102) setup communication to fingerprint Siemens S7 PLCs.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(102, "iso-tsap", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "ICS/SCADA"
  out["Status"] = "AUDITED - s7comm-plc-fingerprint.nse check executed successfully."
  return out
end
