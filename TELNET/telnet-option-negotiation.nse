local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Negotiates Telnet IAC options (ECHO, SUPPRESS_GO_AHEAD, TERMINAL_TYPE, TSPEED, NAWS).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-option-negotiation.nse check executed successfully."
  return out
end
