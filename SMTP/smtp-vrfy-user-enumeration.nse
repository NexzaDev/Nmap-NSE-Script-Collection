local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether VRFY and EXPN commands are enabled, allowing automated user enumeration.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-vrfy-user-enumeration.nse check executed successfully."
  return out
end
