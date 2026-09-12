local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Evaluates whether a GraphQL WebSocket subscription endpoint (/graphql, /subscriptions, /ws)
accepts unauthenticated WebSocket upgrades using standard GraphQL subprotocols
(graphql-ws, subscriptions-transport-ws).
Unprotected subscription endpoints allow attackers to establish persistent WebSocket
connections, eavesdrop on real-time event streams, or exhaust server connection pools.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/subscriptions", "/ws/graphql", "/ws", "/api/graphql/subscriptions"
}

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_ws_path = nil
  local negotiated_protocol = nil

  for _, p in ipairs(paths_to_test) do
    local sock = nmap.new_socket()
    sock:set_timeout(5000)

    local ok, _ = sock:connect(host, port, "tcp")
    if ok then
      local handshake_req = string.format(
        "GET %s HTTP/1.1\r\n" ..
        "Host: %s\r\n" ..
        "Upgrade: websocket\r\n" ..
        "Connection: Upgrade\r\n" ..
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ..
        "Sec-WebSocket-Version: 13\r\n" ..
        "Sec-WebSocket-Protocol: graphql-ws, subscriptions-transport-ws\r\n\r\n",
        p, host.ip
      )

      sock:send(handshake_req)
      local status, response = sock:receive_lines(1)
      if status and response and (string.find(response, "101") or string.find(response, "Switching Protocols")) then
        active_ws_path = p
        -- Read subsequent response lines for protocol header
        for _ = 1, 15 do
          local s, line = sock:receive_lines(1)
          if not s or line == "\r\n" or line == "" then break end
          local proto = string.match(line, "Sec%-WebSocket%-Protocol:%s*([%w%-_]+)")
          if proto then negotiated_protocol = proto end
        end
        sock:close()
        break
      end
      sock:close()
    end
  end

  out["Risk Level"] = "🟡 MEDIUM"

  if active_ws_path then
    out["Status"] = "VULNERABLE - Unauthenticated GraphQL WebSocket Subscription Endpoint Exposed"
    out["WebSocket Endpoint"] = active_ws_path
    out["Negotiated Protocol"] = negotiated_protocol or "graphql-ws / subscriptions-transport-ws"
    out["Assessment"] = "The server accepted a raw WebSocket upgrade on the GraphQL subscription endpoint without requiring an authentication token during the HTTP handshake."
    out["Remediation"] = "Enforce authentication validation during the initial WebSocket HTTP upgrade request (e.g. onConnect hook in graphql-ws or verifyClient in ws)."
  else
    out["Status"] = "SECURE - No unauthenticated GraphQL WebSocket subscription endpoint identified."
  end

  return out
end
