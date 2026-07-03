local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Advertises groups of known-weak TLS cipher suites (NULL ciphers,
export-grade ciphers, DES/3DES, RC4, and anonymous Diffie-Hellman)
in separate ClientHello attempts and reports which groups the server
is willing to negotiate.
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

local function build_client_hello(version_bytes, cipher_codes, hostname)
  local random = string.rep("B", 32)
  local session_id = string.char(0)
  local cipher_body = ""
  for _, c in ipairs(cipher_codes) do
    cipher_body = cipher_body .. u16(c)
  end
  local cipher_suites = u16(#cipher_body) .. cipher_body
  local compression = string.char(1, 0)
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

local function parse_server_hello_cipher(body)
  if #body < 4 then return nil end
  local hs_type = string.byte(body, 1)
  if hs_type ~= 2 then return nil end
  local hs_len = string.byte(body, 2) * 65536 + string.byte(body, 3) * 256 + string.byte(body, 4)
  local msg = string.sub(body, 5, 4 + hs_len)
  if #msg < 35 then return nil end
  local sid_len = string.byte(msg, 35)
  local pos = 36 + sid_len
  if #msg < pos + 1 then return nil end
  local cipher = string.byte(msg, pos) * 256 + string.byte(msg, pos + 1)
  return cipher
end

local function try_ciphers(host, port, cipher_codes, hostname)
  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return nil
  end

  local version_bytes = string.char(3, 1)
  local hello = build_client_hello(version_bytes, cipher_codes, hostname)
  local record = wrap_record(version_bytes, hello)

  local sent = socket:send(record)
  if not sent then
    socket:close()
    return nil
  end

  local response = read_tls_record(socket)
  socket:close()

  if not response or response.content_type ~= 22 then
    return nil
  end

  return parse_server_hello_cipher(response.body)
end

local CIPHER_GROUPS = {
  {
    label = "NULL ciphers (no encryption)",
    codes = { 0x0001, 0x0002 },
    names = { [0x0001] = "TLS_RSA_WITH_NULL_MD5", [0x0002] = "TLS_RSA_WITH_NULL_SHA" },
  },
  {
    label = "Export-grade ciphers",
    codes = { 0x0003, 0x0006, 0x0008, 0x0014, 0x0019 },
    names = {
      [0x0003] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
      [0x0006] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
      [0x0008] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
      [0x0014] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
      [0x0019] = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    },
  },
  {
    label = "DES / 3DES ciphers",
    codes = { 0x0009, 0x000A, 0x0016, 0x001B },
    names = {
      [0x0009] = "TLS_RSA_WITH_DES_CBC_SHA",
      [0x000A] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
      [0x0016] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
      [0x001B] = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    },
  },
  {
    label = "RC4 ciphers",
    codes = { 0x0004, 0x0005, 0xC007, 0xC011 },
    names = {
      [0x0004] = "TLS_RSA_WITH_RC4_128_MD5",
      [0x0005] = "TLS_RSA_WITH_RC4_128_SHA",
      [0xC007] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
      [0xC011] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    },
  },
  {
    label = "Anonymous Diffie-Hellman ciphers",
    codes = { 0x0018, 0x001B, 0x0034, 0x006C },
    names = {
      [0x0018] = "TLS_DH_anon_WITH_RC4_128_MD5",
      [0x001B] = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
      [0x0034] = "TLS_DH_anon_WITH_AES_128_CBC_SHA",
      [0x006C] = "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    },
  },
}

action = function(host, port)
  local hostname = host.targetname or tostring(host.ip)
  local out = stdnse.output_table()
  local accepted_groups = {}
  local rejected_groups = {}

  for _, group in ipairs(CIPHER_GROUPS) do
    local cipher = try_ciphers(host, port, group.codes, hostname)
    if cipher then
      local name = group.names[cipher] or string.format("0x%04X", cipher)
      table.insert(accepted_groups, string.format(
        "%s -> server negotiated %s", group.label, name
      ))
    else
      table.insert(rejected_groups, group.label)
    end
  end

  if #accepted_groups > 0 then
    out["Weak cipher groups ACCEPTED by server"] = accepted_groups
  else
    out["Weak cipher groups ACCEPTED by server"] = "None of the weak cipher groups were negotiated."
  end

  if #rejected_groups > 0 then
    out["Weak cipher groups rejected"] = rejected_groups
  end

  return out
end
