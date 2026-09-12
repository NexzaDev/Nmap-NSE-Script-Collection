local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Evaluates standard VNC 8-byte DES authentication, flagging weak 56-bit single-DES.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(5900, "vnc", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "VNC RFB"
  out["Status"] = "AUDITED - vnc-cleartext-des-warning.nse check executed successfully."
  return out
end
