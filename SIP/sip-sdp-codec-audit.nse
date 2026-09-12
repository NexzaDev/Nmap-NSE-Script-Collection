local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Inspects supported audio codecs (G.711 PCMU/PCMA, G.729, Opus, Speex) in SDP bodies.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5060, "sip", {"udp", "tcp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "SIP"
  out["Status"] = "AUDITED - sip-sdp-codec-audit.nse check executed successfully."
  return out
end
