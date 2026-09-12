local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Evaluates whether the Docker daemon /events streaming endpoint is accessible
without authentication. The Docker events API continuously streams real-time
system events (container creation, start, exec, die, destroy, image pull, volume
attach). Unauthorized access allows external observers to conduct passive
surveillance of container workloads, arguments, and cluster operations.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()

  -- Use raw socket with small timeout because /events is a long-polling streaming endpoint
  local sock = nmap.new_socket()
  sock:set_timeout(4000)

  local ok, err = sock:connect(host, port, "tcp")
  if not ok then
    return stdnse.format_output(false, "Could not connect to Docker port: " .. (err or "unknown"))
  end

  local req = string.format("GET /events?since=1 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host.ip)
  sock:send(req)

  local status, data = sock:receive_lines(1)
  local headers = {}
  local is_200 = false

  if status and data then
    if string.find(data, "200 OK") then
      is_200 = true
    end
    -- Read headers
    for _ = 1, 20 do
      local s, l = sock:receive_lines(1)
      if not s or l == "\r\n" or l == "" then break end
      table.insert(headers, l)
    end
  end

  sock:close()

  out["Risk Level"] = "🟡 MEDIUM"

  if is_200 then
    out["Status"] = "VULNERABLE - Unauthenticated Docker /events streaming API exposed"
    out["Assessment"] = "The Docker daemon accepted an unauthenticated connection to the real-time event stream. An attacker can eavesdrop on all container lifecycle events, exec commands, and volume mounts."
    out["Remediation"] = "Enforce TLS client certificate verification on Docker daemon ports (2375/2376)."
  else
    out["Status"] = "SECURE - /events endpoint is not accessible or requires authentication."
  end

  return out
end
