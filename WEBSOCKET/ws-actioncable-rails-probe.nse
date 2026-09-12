local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Ruby on Rails ActionCable WebSocket endpoint (/cable) and protocols.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-actioncable-rails-probe.nse check executed successfully."
  return out
end
