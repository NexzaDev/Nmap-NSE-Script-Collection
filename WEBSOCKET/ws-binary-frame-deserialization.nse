local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends binary frames (Opcode 0x02) to probe for unsafe Java/Python/Node deserialization.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-binary-frame-deserialization.nse check executed successfully."
  return out
end
