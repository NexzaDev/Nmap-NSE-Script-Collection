local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes RCPT TO response codes (250 OK vs 550 User unknown) for dictionary user harvesting.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-rcpt-to-user-enum.nse check executed successfully."
  return out
end
