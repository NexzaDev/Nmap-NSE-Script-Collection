local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends a ClientHello advertising both NULL and DEFLATE compression
methods and inspects the ServerHello's chosen compression method.
If the server selects DEFLATE, the connection is potentially exposed
to CRIME-style compression side-channel attacks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.ssl

local function u16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function u24(n)
  return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function build_sni_extension(hostname)
  local entry = string.char(0) .. u16(#hostname) .. hostname
  local list = u16(#entry) .. entry
  return u16(0) .. u16(#list) .. list
end

local COMMON_CIPHERS = {
  0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D,
  0xC013, 0xC014, 0xC027, 0xC028, 0xC02F, 0xC030, 0x000A,
}

local function build_client_hello_with_compression(version_bytes, hostname)
  local random = string.rep("C", 32)
  local session_id = string.char(0)
  local cipher_body = ""
  for _, c in ipairs(COMMON_CIPHERS) do
    cipher_body = cipher_body .. u16(c)
  end
  local cipher_suites = u16(#cipher_body) .. cipher_body
  local compression = string.char(2, 1, 0)
  local extensions = build_sni_extension(hostname)

  local body = version_bytes .. random .. session_id .. cipher_suites .. compression
             .. u16(#extensions) .. extensions

  return string.char(1) .. u24(#body) .. body
end

local function wrap_record(record_version_bytes, payload)
  return string.char(22) .. record_version_bytes .. u16(#payload) .. payload
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

local function read_tls_record(socket)
  local buf = ""
  local ok
  ok, buf = pcall(function() return recv_atleast(socket, buf, 5) end)
  if not ok or not buf or #buf < 5 then
    return nil
  end
  local content_type = string.byte(buf, 1)
  local length = string.byte(buf, 4) * 256 + string.byte(buf, 5)
  local ok2
  ok2, buf = pcall(function() return recv_atleast(socket, buf, 5 + length) end)
  if not ok2 or not buf or #buf < 5 + length then
    return nil
  end
  local body = string.sub(buf, 6, 5 + length)
  return { content_type = content_type, body = body }
end

local function parse_compression_method(body)
  if #body < 4 then return nil end
  local hs_type = string.byte(body, 1)
  if hs_type ~= 2 then return nil end
  local hs_len = string.byte(body, 2) * 65536 + string.byte(body, 3) * 256 + string.byte(body, 4)
  local msg = string.sub(body, 5, 4 + hs_len)
  if #msg < 35 then return nil end
  local sid_len = string.byte(msg, 35)
  local pos = 36 + sid_len
  local comp_pos = pos + 2
  if #msg < comp_pos then return nil end
  return string.byte(msg, comp_pos)
end

action = function(host, port)
  local hostname = host.targetname or tostring(host.ip)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection for the handshake probe."
  end

  local version_bytes = string.char(3, 1)
  local hello = build_client_hello_with_compression(version_bytes, hostname)
  local record = wrap_record(version_bytes, hello)

  local sent = socket:send(record)
  if not sent then
    socket:close()
    return "Failed to send ClientHello."
  end

  local response = read_tls_record(socket)
  socket:close()

  if not response or response.content_type ~= 22 then
    return "Did not receive a usable ServerHello for this probe."
  end

  local method = parse_compression_method(response.body)
  if not method then
    return "Could not parse compression method from ServerHello."
  end

  if method == 0 then
    out["Compression method selected"] = "NULL (0x00) - no TLS-level compression in use"
    out["CRIME exposure"] = "Not exposed via TLS record compression."
  elseif method == 1 then
    out["Compression method selected"] = "DEFLATE (0x01)"
    out["CRIME exposure"] = "POTENTIALLY VULNERABLE - server accepted DEFLATE compression, which enables CRIME-style attacks."
  else
    out["Compression method selected"] = string.format("Unknown method 0x%02X", method)
  end

  return out
end
