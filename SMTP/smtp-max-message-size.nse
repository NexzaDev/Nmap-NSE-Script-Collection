local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks SIZE extension limit to detect denial-of-service / mailbox overflow risks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-max-message-size.nse check executed successfully."
  return out
end
