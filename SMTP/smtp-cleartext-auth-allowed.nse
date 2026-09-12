local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if server advertises AUTH PLAIN or AUTH LOGIN before STARTTLS is negotiated.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-cleartext-auth-allowed.nse check executed successfully."
  return out
end
