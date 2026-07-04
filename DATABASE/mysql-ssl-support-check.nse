local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Parses the capability flags in the MySQL/MariaDB initial handshake
packet to determine whether the server advertises CLIENT_SSL support,
indicating that connections can optionally or must be encrypted.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(3306, "mysql")

local CLIENT_SSL = 0x00000800
local CLIENT_SECURE_CONNECTION = 0x00008000
local CLIENT_PROTOCOL_41 = 0x00000200
local CLIENT_PLUGIN_AUTH = 0x00080000

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

local function has_bit(value, mask)
  local a, b = value, mask
  local result = 0
  local bitval = 1
  while a > 0 or b > 0 do
    if (a % 2 == 1) and (b % 2 == 1) then
      result = result + bitval
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bitval = bitval * 2
  end
  return result > 0
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
    return "No usable handshake packet received."
  end

  local nul = string.find(payload, "\0", 2, true)
  if not nul then
    return "Could not parse server version string from handshake."
  end

  local pos = nul + 1 + 4 + 8 + 1

  if #payload < pos + 15 then
    return "Handshake packet too short to extract capability flags."
  end

  local cap_low = string.byte(payload, pos) + string.byte(payload, pos + 1) * 256
  local cap_high_pos = pos + 2 + 1 + 2
  local cap_high = 0
  if #payload >= cap_high_pos + 1 then
    cap_high = string.byte(payload, cap_high_pos) + string.byte(payload, cap_high_pos + 1) * 256
  end

  local capabilities = cap_low + (cap_high * 65536)

  out["Raw capability flags"] = string.format("0x%08X", capabilities)
  out["CLIENT_SSL advertised"] = tostring(has_bit(capabilities, CLIENT_SSL))
  out["CLIENT_PROTOCOL_41 advertised"] = tostring(has_bit(capabilities, CLIENT_PROTOCOL_41))
  out["CLIENT_SECURE_CONNECTION advertised"] = tostring(has_bit(capabilities, CLIENT_SECURE_CONNECTION))
  out["CLIENT_PLUGIN_AUTH advertised"] = tostring(has_bit(capabilities, CLIENT_PLUGIN_AUTH))

  if has_bit(capabilities, CLIENT_SSL) then
    out["Assessment"] = "Server supports SSL/TLS-wrapped connections. Confirm the application actually enforces it, since support does not imply enforcement."
  else
    out["Assessment"] = "Server did not advertise CLIENT_SSL - connections to this instance are limited to plaintext."
  end

  return out
end
