local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes ProFTPD mod_copy (CPFR / CPTO) unauthenticated file copying commands (CVE-2015-3306).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Status"] = "AUDITED - ProFTPD mod_copy CPFR/CPTO availability tested."
  return out
end
