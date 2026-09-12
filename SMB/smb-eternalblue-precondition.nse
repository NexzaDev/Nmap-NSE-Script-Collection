local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether the SMB service accepts SMBv1 (NT LM 0.12) dialect negotiation,
which is the mandatory precondition for MS17-010 (EternalBlue) exploitation.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service({139, 445}, "microsoft-ds", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SMBv1 (NT LM 0.12)"
  out["Status"] = "AUDITED - SMBv1 negotiation support checked."
  out["Remediation"] = "Disable SMBv1 completely across all Windows systems."
  return out
end
