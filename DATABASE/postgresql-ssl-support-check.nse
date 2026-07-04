local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends a PostgreSQL SSLRequest packet and checks the single-byte
response ('S' for supported, 'N' for not supported) to determine
whether the server can negotiate an encrypted connection before the
startup/authentication phase begins.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5432, "postgresql")

local function u32be(n)
  return string.char(
    math.floor(n / 16777216) % 256,
    math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256,
    n % 256
  )
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the PostgreSQL service."
  end

  local ssl_request = u32be(8) .. u32be(80877103)
  local sent = socket:send(ssl_request)
  if not sent then
    socket:close()
    return "Failed to send SSLRequest packet."
  end

  local status, response = socket:receive_bytes(1)
  socket:close()

  if not status or not response or #response < 1 then
    return "No response received to SSLRequest."
  end

  local indicator = string.sub(response, 1, 1)

  if indicator == "S" then
    out["SSL/TLS negotiation supported"] = "YES"
    out["Assessment"] = "Server is willing to negotiate TLS before authentication. Confirm client configuration actually requires it (sslmode=require or stronger)."
  elseif indicator == "N" then
    out["SSL/TLS negotiation supported"] = "NO"
    out["Assessment"] = "Server explicitly refused SSL negotiation - this instance only supports plaintext connections."
  else
    out["SSL/TLS negotiation supported"] = "Unexpected response byte: " .. string.format("0x%02X", string.byte(indicator))
  end

  return out
end
