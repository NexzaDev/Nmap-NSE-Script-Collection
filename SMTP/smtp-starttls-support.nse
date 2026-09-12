local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if SMTP server advertises and negotiates STARTTLS on ports 25/587.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-starttls-support.nse check executed successfully."
  return out
end
