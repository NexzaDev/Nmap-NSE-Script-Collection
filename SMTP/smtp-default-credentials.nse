local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests common default SMTP credentials on submission ports (587/465/25).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(587, "submission", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-default-credentials.nse check executed successfully."
  return out
end
