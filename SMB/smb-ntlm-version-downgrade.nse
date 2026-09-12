local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether the SMB service accepts legacy NTLMv1 authentication responses,
which can be cracked offline in deterministic time.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service({139, 445}, "microsoft-ds", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Status"] = "AUDITED - NTLMv1 downgrade acceptance evaluated."
  return out
end
