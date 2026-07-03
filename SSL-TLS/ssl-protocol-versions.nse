local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Attempts a minimal TLS handshake for each protocol version (SSLv3,
TLSv1.0, TLSv1.1, TLSv1.2, and a best-effort TLSv1.3 probe via the
supported_versions extension) and reports which versions the server
accepts. Flags SSLv3, TLSv1.0 and TLSv1.1 as deprecated if accepted.
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

local function build_supported_versions_extension(version_list)
  local body = ""
  for _, v in ipairs(version_list) do
    body = body .. v
  end
  local ext_data = string.char(#body) .. body
  return u16(43) .. u16(#ext_data) .. ext_data
end

local COMMON_CIPHERS = {
  0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D,
  0xC013, 0xC014, 0xC027, 0xC028, 0xC02F, 0xC030,
  0x1301, 0x1302, 0x1303, 0x000A,
}

local function build_cipher_list()
  local body = ""
  for _, c in ipairs(COMMON_CIPHERS) do
    body = body .. u16(c)
  end
  return body
end

local function build_client_hello(version_bytes, extra_extensions_bytes, hostname)
  local random = string.rep("A", 32)
  local session_id = string.char(0)
  local ciphers = build_cipher_list()
  local cipher_suites = u16(#ciphers) .. ciphers
  local compression = string.char(1, 0)

  local extensions = build_sni_extension(hostname)
  if extra_extensions_bytes then
    extensions = extensions .. extra_extensions_bytes
  end

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

local function parse_server_hello(body)
  if #body < 4 then return nil end
  local hs_type = string.byte(body, 1)
  if hs_type ~= 2 then return nil, hs_type end
  local hs_len = string.byte(body, 2) * 65536 + string.byte(body, 3) * 256 + string.byte(body, 4)
  local msg = string.sub(body, 5, 4 + hs_len)
  if #msg < 35 then return nil end
  local ver_major, ver_minor = string.byte(msg, 1), string.byte(msg, 2)
  local sid_len = string.byte(msg, 35)
  local pos = 36 + sid_len
  local extensions_raw = string.sub(msg, pos + 3)
  return { version = { ver_major, ver_minor }, extensions_raw = extensions_raw }
end

local function extension_present(extensions_raw, target_type)
  if not extensions_raw or #extensions_raw < 2 then return false end
  local total = string.byte(extensions_raw, 1) * 256 + string.byte(extensions_raw, 2)
  local pos = 3
  local remaining = total
  while remaining >= 4 and pos + 3 <= #extensions_raw do
    local etype = string.byte(extensions_raw, pos) * 256 + string.byte(extensions_raw, pos + 1)
    local elen = string.byte(extensions_raw, pos + 2) * 256 + string.byte(extensions_raw, pos + 3)
    if etype == target_type then
      return true, string.sub(extensions_raw, pos + 4, pos + 3 + elen)
    end
    pos = pos + 4 + elen
    remaining = remaining - (4 + elen)
  end
  return false
end

local function try_handshake(host, port, record_version, hostname, extra_ext)
  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return nil, "connect failed"
  end

  local hello = build_client_hello(record_version, extra_ext, hostname)
  local record = wrap_record(record_version, hello)

  local sent = socket:send(record)
  if not sent then
    socket:close()
    return nil, "send failed"
  end

  local response = read_tls_record(socket)
  socket:close()

  if not response then
    return nil, "no response"
  end

  if response.content_type == 21 then
    return nil, "alert (rejected)"
  end

  if response.content_type ~= 22 then
    return nil, "unexpected content type " .. tostring(response.content_type)
  end

  local hello_resp = parse_server_hello(response.body)
  if not hello_resp then
    return nil, "could not parse ServerHello"
  end

  return hello_resp, nil
end

local PROTOCOLS = {
  { label = "SSLv3", bytes = string.char(3, 0), deprecated = true },
  { label = "TLSv1.0", bytes = string.char(3, 1), deprecated = true },
  { label = "TLSv1.1", bytes = string.char(3, 2), deprecated = true },
  { label = "TLSv1.2", bytes = string.char(3, 3), deprecated = false },
}

action = function(host, port)
  local hostname = host.targetname or tostring(host.ip)
  local out = stdnse.output_table()
  local supported = {}
  local deprecated_found = {}

  for _, proto in ipairs(PROTOCOLS) do
    local hello_resp, err = try_handshake(host, port, proto.bytes, hostname, nil)
    if hello_resp then
      table.insert(supported, proto.label)
      if proto.deprecated then
        table.insert(deprecated_found, proto.label .. " is accepted and considered deprecated/insecure")
      end
    end
  end

  local tls13_ext = build_supported_versions_extension({ string.char(3, 4) })
  local tls13_resp = select(1, try_handshake(host, port, string.char(3, 3), hostname, tls13_ext))
  if tls13_resp then
    local present, data = extension_present(tls13_resp.extensions_raw, 43)
    if present and data and #data == 2 and string.byte(data, 1) == 3 and string.byte(data, 2) == 4 then
      table.insert(supported, "TLSv1.3 (best-effort probe)")
    elseif tls13_resp.version[1] == 3 and tls13_resp.version[2] == 4 then
      table.insert(supported, "TLSv1.3 (best-effort probe)")
    end
  end

  if #supported > 0 then
    out["Protocol versions accepted"] = supported
  else
    out["Protocol versions accepted"] = "No handshake succeeded for any tested protocol version."
  end

  if #deprecated_found > 0 then
    out["Deprecated protocols enabled"] = deprecated_found
  else
    out["Deprecated protocols enabled"] = "None of SSLv3/TLSv1.0/TLSv1.1 were accepted."
  end

  return out
end
