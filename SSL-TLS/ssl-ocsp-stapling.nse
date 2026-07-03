local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends a ClientHello including the status_request extension (RFC 6066)
requesting an OCSP response, then inspects the handshake messages
returned by the server for a CertificateStatus message, indicating
that OCSP stapling is supported and enabled.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.ssl

local STATUS_REQUEST_EXT_TYPE = 5

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

local function build_status_request_extension()
  local ext_data = string.char(1) .. u16(0) .. u16(0)
  return u16(STATUS_REQUEST_EXT_TYPE) .. u16(#ext_data) .. ext_data
end

local COMMON_CIPHERS = {
  0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D,
  0xC013, 0xC014, 0xC027, 0xC028, 0xC02F, 0xC030, 0x000A,
}

local function build_client_hello(version_bytes, hostname)
  local random = string.rep("E", 32)
  local session_id = string.char(0)
  local cipher_body = ""
  for _, c in ipairs(COMMON_CIPHERS) do
    cipher_body = cipher_body .. u16(c)
  end
  local cipher_suites = u16(#cipher_body) .. cipher_body
  local compression = string.char(1, 0)

  local extensions = build_sni_extension(hostname) .. build_status_request_extension()

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

local function extract_handshake_messages(body)
  local messages = {}
  local pos = 1
  while pos + 3 <= #body do
    local hs_type = string.byte(body, pos)
    local hs_len = string.byte(body, pos + 1) * 65536 + string.byte(body, pos + 2) * 256 + string.byte(body, pos + 3)
    if pos + 3 + hs_len > #body then
      break
    end
    table.insert(messages, hs_type)
    pos = pos + 4 + hs_len
  end
  return messages
end

local function parse_status_request_ack(body)
  if #body < 4 then return false end
  local hs_type = string.byte(body, 1)
  if hs_type ~= 2 then return false end
  local hs_len = string.byte(body, 2) * 65536 + string.byte(body, 3) * 256 + string.byte(body, 4)
  local msg = string.sub(body, 5, 4 + hs_len)
  if #msg < 35 then return false end
  local sid_len = string.byte(msg, 35)
  local pos = 36 + sid_len + 3
  local extensions_raw = string.sub(msg, pos)
  if #extensions_raw < 2 then return false end
  local total = string.byte(extensions_raw, 1) * 256 + string.byte(extensions_raw, 2)
  local epos = 3
  local remaining = total
  while remaining >= 4 and epos + 3 <= #extensions_raw do
    local etype = string.byte(extensions_raw, epos) * 256 + string.byte(extensions_raw, epos + 1)
    local elen = string.byte(extensions_raw, epos + 2) * 256 + string.byte(extensions_raw, epos + 3)
    if etype == STATUS_REQUEST_EXT_TYPE then
      return true
    end
    epos = epos + 4 + elen
    remaining = remaining - (4 + elen)
  end
  return false
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

  local version_bytes = string.char(3, 3)
  local hello = build_client_hello(version_bytes, hostname)
  local record = wrap_record(version_bytes, hello)

  local sent = socket:send(record)
  if not sent then
    socket:close()
    return "Failed to send ClientHello."
  end

  local first_response = read_tls_record(socket)
  if not first_response or first_response.content_type ~= 22 then
    socket:close()
    return "Did not receive a usable ServerHello for this probe."
  end

  local ack = parse_status_request_ack(first_response.body)

  if not ack then
    socket:close()
    out["status_request extension acknowledged"] = "NO - server did not echo the status_request extension in ServerHello."
    out["OCSP stapling"] = "Not indicated by this probe."
    return out
  end

  out["status_request extension acknowledged"] = "YES - server echoed status_request in ServerHello."

  local found_status = false
  for i = 1, 3 do
    local next_record = read_tls_record(socket)
    if not next_record then break end
    if next_record.content_type == 22 then
      local messages = extract_handshake_messages(next_record.body)
      for _, t in ipairs(messages) do
        if t == 22 then
          found_status = true
        end
      end
    end
    if found_status then break end
  end
  socket:close()

  if found_status then
    out["OCSP stapling"] = "SUPPORTED - a CertificateStatus message was observed in the handshake."
  else
    out["OCSP stapling"] = "Extension acknowledged but no CertificateStatus message observed in the messages read (server may staple only under certain conditions, or more records were needed)."
  end

  return out
end
