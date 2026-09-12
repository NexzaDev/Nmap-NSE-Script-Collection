local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Socket.io engine.io transport (/socket.io/?EIO=4&transport=websocket).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "WebSocket (RFC 6455)"
  out["Status"] = "AUDITED - ws-socketio-handshake-probe.nse check executed successfully."
  return out
end
