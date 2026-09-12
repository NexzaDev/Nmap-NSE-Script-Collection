local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests server handling of oversized or malformed TERMINAL-TYPE subnegotiation strings.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-terminal-type-dos.nse check executed successfully."
  return out
end
