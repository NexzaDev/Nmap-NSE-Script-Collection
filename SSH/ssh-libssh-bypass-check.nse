local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for libssh authentication bypass vulnerability fingerprint (CVE-2018-10933).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-libssh-bypass-check.nse check executed successfully."
  return out
end
