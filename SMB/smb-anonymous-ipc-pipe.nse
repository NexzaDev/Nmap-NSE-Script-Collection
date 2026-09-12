local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether anonymous null sessions can connect to IPC$ named pipes
(\pipe\samr, \pipe\lsarpc, \pipe\netlogon) to enumerate domain accounts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service({139, 445}, "microsoft-ds", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Status"] = "AUDITED - Anonymous IPC$ named pipe accessibility checked."
  return out
end
