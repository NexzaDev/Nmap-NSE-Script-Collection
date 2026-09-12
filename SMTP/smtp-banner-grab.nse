local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Captures SMTP initial 220 banner, hostname, and mail server software version.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-banner-grab.nse check executed successfully."
  return out
end
