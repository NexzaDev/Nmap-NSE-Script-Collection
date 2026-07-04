local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends a TDS PRELOGIN packet to a Microsoft SQL Server instance and
parses the VERSION and ENCRYPTION options from the response to report
the server's product version and whether TLS encryption is off,
requested, required, or unsupported. This is the most protocol-
intricate script in this collection and has not been validated
against a live instance; treat results as preliminary.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(1433, "ms-sql-s")

local ENCRYPTION_LABELS = {
  [0x00] = "ENCRYPT_OFF - encryption not requested by server",
  [0x01] = "ENCRYPT_ON - server will encrypt the login packet and can encrypt the full session",
  [0x02] = "ENCRYPT_NOT_SUP - server does not support encryption at all",
  [0x03] = "ENCRYPT_REQ - server requires the full session to be encrypted",
}

local function u16be(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
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

local function build_prelogin_packet()
  local version_data = string.char(0, 0, 0, 0, 0, 0)
  local encryption_data = string.char(0x00)
  local instopt_data = string.char(0x00)
  local threadid_data = string.char(0, 0, 0, 0)

  local options = {
    { token = 0x00, data = version_data },
    { token = 0x01, data = encryption_data },
    { token = 0x02, data = instopt_data },
    { token = 0x03, data = threadid_data },
  }

  local option_table_len = (#options * 5) + 1
  local offset = option_table_len

  local option_headers = ""
  local option_data = ""

  for _, opt in ipairs(options) do
    option_headers = option_headers .. string.char(opt.token) .. u16be(offset) .. u16be(#opt.data)
    option_data = option_data .. opt.data
    offset = offset + #opt.data
  end

  option_headers = option_headers .. string.char(0xFF)

  local payload = option_headers .. option_data
  local total_len = 8 + #payload

  local tds_header = string.char(0x12, 0x01) .. u16be(total_len) .. string.char(0, 0, 1, 0)

  return tds_header .. payload
end

local function parse_prelogin_response(data)
  local results = {}
  if #data < 8 then return results end
  local body = string.sub(data, 9)

  local pos = 1
  while pos <= #body do
    local token = string.byte(body, pos)
    if not token or token == 0xFF then break end
    local offset = string.byte(body, pos + 1) * 256 + string.byte(body, pos + 2)
    local length = string.byte(body, pos + 3) * 256 + string.byte(body, pos + 4)
    local option_value = string.sub(body, offset + 1, offset + length)
    results[token] = option_value
    pos = pos + 5
  end

  return results
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the MSSQL service."
  end

  local packet = build_prelogin_packet()
  local sent = socket:send(packet)
  if not sent then
    socket:close()
    return "Failed to send PRELOGIN packet."
  end

  local buf = ""
  local ok2
  ok2, buf = pcall(function() return recv_atleast(socket, buf, 8) end)
  if not ok2 or not buf or #buf < 8 then
    socket:close()
    return "No usable PRELOGIN response header received."
  end

  local resp_len = string.byte(buf, 3) * 256 + string.byte(buf, 4)

  local ok3
  ok3, buf = pcall(function() return recv_atleast(socket, buf, resp_len) end)
  socket:close()

  if not ok3 or not buf or #buf < resp_len then
    return "PRELOGIN response truncated before it could be fully parsed."
  end

  local options = parse_prelogin_response(buf)

  local version_opt = options[0x00]
  if version_opt and #version_opt >= 4 then
    local major = string.byte(version_opt, 1)
    local minor = string.byte(version_opt, 2)
    local build = string.byte(version_opt, 3) * 256 + string.byte(version_opt, 4)
    out["Server version (from PRELOGIN)"] = string.format("%d.%d build %d", major, minor, build)
  else
    out["Server version (from PRELOGIN)"] = "Not present in response."
  end

  local encryption_opt = options[0x01]
  if encryption_opt and #encryption_opt >= 1 then
    local enc_val = string.byte(encryption_opt, 1)
    out["Encryption setting"] = ENCRYPTION_LABELS[enc_val] or ("Unknown value 0x" .. string.format("%02X", enc_val))
  else
    out["Encryption setting"] = "Not present in response."
  end

  return out
end
