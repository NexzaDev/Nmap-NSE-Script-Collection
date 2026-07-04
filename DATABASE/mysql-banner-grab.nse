local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Connects to a MySQL/MariaDB service and parses the server's initial
handshake packet (Protocol::HandshakeV10) to extract the protocol
version, server version string, and negotiated capability flags,
without performing any authentication.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "version"}

portrule = shortport.port_or_service(3306, "mysql")

local function recv_atleast(socket, buf, n)
  while #buf < n do
    local status, data = socket:receive_bytes(n - #buf)
    if not status then
      return nil, buf
    end
    buf = buf .. data
  end
  return buf
end

local function read_packet(socket)
  local buf = ""
  local ok
  ok, buf = pcall(function() return recv_atleast(socket, buf, 4) end)
  if not ok or not buf or #buf < 4 then return nil end
  local len = string.byte(buf, 1) + string.byte(buf, 2) * 256 + string.byte(buf, 3) * 65536
  local ok2
  ok2, buf = pcall(function() return recv_atleast(socket, buf, 4 + len) end)
  if not ok2 or not buf or #buf < 4 + len then return nil end
  return string.sub(buf, 5, 4 + len)
end

local function read_cstring(data, pos)
  local nul = string.find(data, "\0", pos, true)
  if not nul then return nil, pos end
  return string.sub(data, pos, nul - 1), nul + 1
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the MySQL service."
  end

  local payload = read_packet(socket)
  socket:close()

  if not payload or #payload < 5 then
    return "No usable handshake packet received; this may not be a MySQL/MariaDB service."
  end

  local protocol_version = string.byte(payload, 1)
  local server_version, pos = read_cstring(payload, 2)

  out["Protocol version"] = tostring(protocol_version)
  out["Server version string"] = server_version or "unavailable"

  if server_version then
    local lversion = string.lower(server_version)
    if string.find(lversion, "mariadb") then
      out["Server family"] = "MariaDB"
    else
      out["Server family"] = "MySQL (Oracle) or compatible"
    end
  end

  if pos and #payload >= pos + 12 then
    local thread_id = string.byte(payload, pos) + string.byte(payload, pos + 1) * 256
      + string.byte(payload, pos + 2) * 65536 + string.byte(payload, pos + 3) * 16777216
    out["Connection thread id"] = tostring(thread_id)

    local cap_pos = pos + 8 + 1
    if #payload >= cap_pos + 1 then
      local cap_low = string.byte(payload, cap_pos) + string.byte(payload, cap_pos + 1) * 256
      out["Capability flags (lower 16 bits)"] = string.format("0x%04X", cap_low)
    end
  end

  return out
end
