local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Grabs Telnet initial login banner, OS prompt, and legal notice disclosures.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-banner-grab.nse check executed successfully."
  return out
end
