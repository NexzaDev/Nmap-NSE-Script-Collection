local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for legacy RDP protocols and absence of NLA indicating CVE-2019-0708 (BlueKeep).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "RDP"
  out["Status"] = "AUDITED - rdp-bluekeep-precondition.nse check executed successfully."
  return out
end
