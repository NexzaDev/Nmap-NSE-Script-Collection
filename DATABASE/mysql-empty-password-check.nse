local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Attempts to authenticate as the "root" account with an empty password
using the MySQL Protocol::HandshakeResponse41 message and the
mysql_native_password plugin. Reports whether the server accepted the
login, which would indicate a critical misconfiguration.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(3306, "mysql")

local function u16le(n)
  return string.char(n % 256, math.floor(n / 256) % 256)
end

local function u32le(n)
  return string.char(
    n % 256,
    math.floor(n / 256) % 256,
    math.floor(n / 65536) % 256,
    math.floor(n / 16777216) % 256
  )
end

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
  local seq = string.byte(buf, 4)
  local ok2
  ok2, buf = pcall(function() return recv_atleast(socket, buf, 4 + len) end)
  if not ok2 or not buf or #buf < 4 + len then return nil end
  return string.sub(buf, 5, 4 + len), seq
end

local function write_packet(socket, payload, seq)
  local len = #payload
  local header = string.char(len % 256, math.floor(len / 256) % 256, math.floor(len / 65536) % 256, seq)
  return socket:send(header .. payload)
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

  local handshake = read_packet(socket)
  if not handshake or #handshake < 5 then
    socket:close()
    return "No usable handshake packet received; this may not be a MySQL/MariaDB service."
  end

  local client_flag = u32le(0x00000200 + 0x00008000 + 0x00080000)
  local max_packet_size = u32le(16777216)
  local charset = string.char(0x21)
  local reserved = string.rep("\0", 23)
  local username = "root\0"
  local auth_response = string.char(0)
  local plugin_name = "mysql_native_password\0"

  local response_payload = client_flag .. max_packet_size .. charset .. reserved
    .. username .. auth_response .. plugin_name

  local sent = write_packet(socket, response_payload, 1)
  if not sent then
    socket:close()
    return "Failed to send authentication attempt packet."
  end

  local result_payload = read_packet(socket)
  socket:close()

  if not result_payload or #result_payload == 0 then
    out["Result"] = "No response received to the authentication attempt."
    return out
  end

  local first_byte = string.byte(result_payload, 1)

  if first_byte == 0x00 then
    out["Login as root with empty password"] = "SUCCESS"
    out["Assessment"] = "CRITICAL - the root account accepts an empty password. This grants full database access to anyone."
  elseif first_byte == 0xFF then
    local err_code = string.byte(result_payload, 2) + string.byte(result_payload, 3) * 256
    out["Login as root with empty password"] = "rejected"
    out["Server error code"] = tostring(err_code)
    out["Assessment"] = "Root account with an empty password was rejected."
  elseif first_byte == 0xFE then
    out["Login as root with empty password"] = "inconclusive"
    out["Assessment"] = "Server requested an authentication plugin switch that this script does not follow; result could not be determined."
  else
    out["Login as root with empty password"] = "unknown response"
  end

  return out
end
