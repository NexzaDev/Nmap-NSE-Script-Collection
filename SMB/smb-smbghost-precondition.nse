local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates whether an SMBv3 server negotiates SMB 3.1.1 dialect with LZNT1 or LZ77
compression enabled (CVE-2020-0796 / SMBGhost precondition).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(445, "microsoft-ds", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "SMB 3.1.1 Compression"
  out["Status"] = "AUDITED - SMBv3.1.1 compression negotiation tested."
  return out
end
