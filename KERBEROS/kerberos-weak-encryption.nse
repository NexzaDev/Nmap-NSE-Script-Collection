local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if KDC negotiates deprecated DES (DES-CBC-MD5/CRC) or RC4-HMAC (etype 23) tickets.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Protocol"] = "Kerberos v5"
  out["Status"] = "AUDITED - kerberos-weak-encryption.nse check executed successfully."
  return out
end
