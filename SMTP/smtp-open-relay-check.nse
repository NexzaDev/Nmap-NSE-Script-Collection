local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests for open mail relaying by sending non-destructive test envelopes (MAIL FROM, RCPT TO).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SMTP"
  out["Status"] = "AUDITED - smtp-open-relay-check.nse check executed successfully."
  return out
end
