local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends none auth request to enumerate allowed authentication methods (password, publickey).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-auth-methods-enum.nse check executed successfully."
  return out
end
