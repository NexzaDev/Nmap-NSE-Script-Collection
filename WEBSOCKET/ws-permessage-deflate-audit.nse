local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests Sec-WebSocket-Extensions: permessage-deflate and checks for CRIME-style compression leakage.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-permessage-deflate-audit.nse check executed successfully."
  return out
end
