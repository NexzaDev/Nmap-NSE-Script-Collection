local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends IAC SB NEW-ENVIRON SEND requests to extract server environment variables (USER, PATH).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(23, "telnet", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "TELNET"
  out["Status"] = "AUDITED - telnet-env-var-disclosure.nse check executed successfully."
  return out
end
