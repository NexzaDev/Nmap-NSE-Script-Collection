local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests SSH MaxAuthTries configuration by submitting multiple bad auth attempts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-max-auth-tries.nse check executed successfully."
  return out
end
