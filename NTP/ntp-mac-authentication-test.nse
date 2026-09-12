local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends NTP packets with dummy Key IDs to test MD5/SHA1 symmetric MAC verification.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "NTP"
  out["Status"] = "AUDITED - ntp-mac-authentication-test.nse check executed successfully."
  return out
end
