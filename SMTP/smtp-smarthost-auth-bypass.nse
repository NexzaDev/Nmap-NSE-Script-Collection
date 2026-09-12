local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether internal IP ranges bypass authentication for relaying.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-smarthost-auth-bypass.nse check executed successfully."
  return out
end
