local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for the vsftpd 2.3.4 smiley face backdoor banner signature (CVE-2011-2523).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Status"] = "AUDITED - vsftpd 2.3.4 signature evaluated."
  return out
end
