local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends PING and INFO commands to a Redis service without any AUTH
command and reports whether the server processes them, indicating
unauthenticated access is permitted. If INFO succeeds, extracts the
Redis version and a small set of notable configuration fields from
the response.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(6379, "redis")

local function read_line(socket)
  local status, line = socket:receive_lines(1)
  if not status then return nil end
  return line
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the Redis service."
  end

  socket:send("PING\r\n")
  local ping_resp = read_line(socket)

  if not ping_resp then
    socket:close()
    return "No response received to PING."
  end

  local requires_auth = string.find(ping_resp, "NOAUTH", 1, true) ~= nil

  out["PING response"] = string.gsub(ping_resp or "", "[\r\n]", "")
  out["Unauthenticated PING accepted"] = tostring(not requires_auth)

  if requires_auth then
    socket:close()
    out["Assessment"] = "Server requires authentication - unauthenticated access is not possible via this probe."
    return out
  end

  socket:send("INFO server\r\n")
  local info_header = read_line(socket)
  local bulk_len = tonumber(string.match(info_header or "", "^%$(%d+)"))

  local info_body = ""
  if bulk_len then
    while #info_body < bulk_len + 2 do
      local status, chunk = socket:receive()
      if not status then break end
      info_body = info_body .. chunk
    end
  end

  socket:close()

  if bulk_len and #info_body > 0 then
    out["Unauthenticated INFO accepted"] = "true"
    local version = string.match(info_body, "redis_version:([%d%.]+)")
    local os_field = string.match(info_body, "os:([^\r\n]+)")
    local mode = string.match(info_body, "redis_mode:([^\r\n]+)")

    if version then out["Redis version"] = version end
    if os_field then out["Reported OS"] = os_field end
    if mode then out["Redis mode"] = mode end

    out["Assessment"] = "VULNERABLE - Redis instance is fully accessible without authentication."
  else
    out["Unauthenticated INFO accepted"] = "false or empty response"
  end

  return out
end
