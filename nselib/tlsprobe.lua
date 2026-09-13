--[[
tlsprobe.lua - a minimal, real TLS handshake probe for NSE scripts
--------------------------------------------------------------------------
This module exists to answer one question honestly: is the listener in front of
me speaking TLS, or is it a plaintext protocol that happens to live on the same
port number?

The usual shortcut - "a TLS-only service closes the connection when it receives
plaintext" - is not evidence, because a plaintext service also produces a
surprising answer (a protocol error frame, a reset, or nothing at all). The only
answer that distinguishes the two is a real ClientHello: a TLS server replies
with a handshake record (or an alert that names the reason it refused), and a
plaintext server cannot produce either. This module therefore builds an actual
TLS 1.3/1.2 ClientHello, parses the reply as far as a scanner legitimately can
without a key exchange, and reports what it saw.

What the module deliberately does not do: complete a handshake, validate a
certificate, or claim the negotiated parameters. A ServerHello proves the peer
speaks TLS; the selected version and cipher suite are recorded because they are
in the clear, and everything else is left to a TLS scanner.
]]

local nmap = require "nmap"
local string = require "string"
local table = require "table"
local math = require "math"

local M = {}

----------------------------------------------------------------------------
-- 1. Cipher suites and alerts
----------------------------------------------------------------------------

-- The suites this module offers, and what each one means when it is chosen. A
-- probe that offers only strong suites cannot tell whether a server supports a
-- weak one, so the list carries both and the answer is reported as it came.
M.CIPHER_SUITES = {
  { id = 0x1301, name = "TLS_AES_128_GCM_SHA256", tls13 = true, strength = "strong", note = "AEAD, TLS 1.3 only" },
  { id = 0x1302, name = "TLS_AES_256_GCM_SHA384", tls13 = true, strength = "strong", note = "AEAD, TLS 1.3 only" },
  { id = 0x1303, name = "TLS_CHACHA20_POLY1305_SHA256", tls13 = true, strength = "strong", note = "AEAD, TLS 1.3 only" },
  { id = 0xC02B, name = "ECDHE_ECDSA_AES128_GCM_SHA256", strength = "strong", note = "forward secret" },
  { id = 0xC02F, name = "ECDHE_RSA_AES128_GCM_SHA256", strength = "strong", note = "forward secret" },
  { id = 0xC030, name = "ECDHE_RSA_AES256_GCM_SHA384", strength = "strong", note = "forward secret" },
  { id = 0xC027, name = "ECDHE_RSA_AES128_CBC_SHA256", strength = "acceptable", note = "CBC, no AEAD" },
  { id = 0xC013, name = "ECDHE_RSA_AES128_CBC_SHA", strength = "acceptable", note = "CBC with SHA-1 MAC" },
  { id = 0x009C, name = "RSA_AES128_GCM_SHA256", strength = "acceptable", note = "no forward secrecy" },
  { id = 0x009D, name = "RSA_AES256_GCM_SHA384", strength = "acceptable", note = "no forward secrecy" },
  { id = 0x002F, name = "RSA_AES128_CBC_SHA", strength = "weak", note = "no forward secrecy, CBC" },
  { id = 0x0035, name = "RSA_AES256_CBC_SHA", strength = "weak", note = "no forward secrecy, CBC" },
  { id = 0x000A, name = "RSA_3DES_EDE_CBC_SHA", strength = "weak", note = "64-bit block cipher" },
  { id = 0x0005, name = "RSA_RC4_128_SHA", strength = "broken", note = "RC4" },
  { id = 0x0004, name = "RSA_RC4_128_MD5", strength = "broken", note = "RC4 with MD5" },
}

M.SUITE_BY_ID = {}
for _, suite in ipairs(M.CIPHER_SUITES) do M.SUITE_BY_ID[suite.id] = suite end

-- Alert descriptions (RFC 8446 section 6). An alert is the most useful answer a
-- probe can receive: it says the listener speaks TLS and why it refused.
M.ALERTS = {
  [0] = "close_notify", [10] = "unexpected_message", [20] = "bad_record_mac",
  [21] = "decryption_failed", [22] = "record_overflow", [30] = "decompression_failure",
  [40] = "handshake_failure", [41] = "no_certificate", [42] = "bad_certificate",
  [43] = "unsupported_certificate", [44] = "certificate_revoked", [45] = "certificate_expired",
  [46] = "certificate_unknown", [47] = "illegal_parameter", [48] = "unknown_ca",
  [49] = "access_denied", [50] = "decode_error", [51] = "decrypt_error",
  [60] = "export_restriction", [70] = "protocol_version", [71] = "insufficient_security",
  [80] = "internal_error", [86] = "inappropriate_fallback", [90] = "user_canceled",
  [100] = "no_renegotiation", [109] = "missing_extension", [110] = "unsupported_extension",
  [111] = "certificate_unobtainable", [112] = "unrecognized_name",
  [113] = "bad_certificate_status_response", [115] = "unknown_psk_identity",
  [116] = "certificate_required", [120] = "no_application_protocol",
}

M.RECORD_TYPES = {
  [20] = "change_cipher_spec", [21] = "alert", [22] = "handshake", [23] = "application_data",
}

M.HANDSHAKE_TYPES = {
  [0] = "hello_request", [1] = "client_hello", [2] = "server_hello", [4] = "new_session_ticket",
  [8] = "encrypted_extensions", [11] = "certificate", [12] = "server_key_exchange",
  [13] = "certificate_request", [14] = "server_hello_done", [15] = "certificate_verify",
  [20] = "finished",
}

----------------------------------------------------------------------------
-- 2. Encoding helpers
----------------------------------------------------------------------------

local function u8(value) return string.char(value % 256) end

local function u16(value)
  return string.char(math.floor(value / 256) % 256, value % 256)
end

local function u24(value)
  return string.char(math.floor(value / 65536) % 256, math.floor(value / 256) % 256, value % 256)
end

local function extension(kind, body)
  return u16(kind) .. u16(#body) .. body
end

-- The random field must not be predictable across probes, but it also must not
-- pretend to be a secure nonce: it goes into the clear and is never used for a
-- key. It is seeded from the clock and the target so two runs differ.
local function client_random(seed)
  local bytes = {}
  local state = math.floor((os.time() or 0) * 1000) + (#seed * 7919)
  for index = 1, 32 do
    state = (state * 1103515245 + 12345) % 2147483648
    bytes[index] = u8(math.floor(state / 65536) % 256)
  end
  return table.concat(bytes)
end

----------------------------------------------------------------------------
-- 3. ClientHello
----------------------------------------------------------------------------

-- A complete TLS record: a ClientHello that offers TLS 1.3 and 1.2, the suites
-- listed above, and the extensions a real client sends (SNI, supported groups,
-- signature algorithms, ALPN optional, supported versions, key share).
function M.client_hello(opts)
  opts = opts or {}
  local hostname = opts.hostname
  local alpn = opts.alpn

  local suites = {}
  for _, suite in ipairs(M.CIPHER_SUITES) do
    if not suite.tls13 or opts.include_tls13 ~= false then suites[#suites + 1] = u16(suite.id) end
  end
  -- The cipher suite list is a u16 byte length followed by the suites.
  local cipher_block = u16(#suites * 2) .. table.concat(suites)

  local extensions = {}
  if hostname and #hostname > 0 then
    -- SNI: list length, then one entry of {type=0 (host_name), u16 length, name}.
    extensions[#extensions + 1] = extension(0, u16(#hostname + 3) .. u8(0) .. u16(#hostname) .. hostname)
  end
  -- supported_groups: x25519, secp256r1, secp384r1, ffdhe2048
  extensions[#extensions + 1] = extension(10, u16(8) .. u16(0x001d) .. u16(0x0017) .. u16(0x0018) .. u16(0x0100))
  -- ec_point_formats: uncompressed only
  extensions[#extensions + 1] = extension(11, u8(1) .. u8(0))
  -- signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ed25519
  extensions[#extensions + 1] = extension(13, u16(8) .. u16(0x0403) .. u16(0x0804) .. u16(0x0401) .. u16(0x0807))
  -- extended_master_secret
  extensions[#extensions + 1] = extension(23, "")
  -- session_ticket: empty, which asks the server for a new ticket
  extensions[#extensions + 1] = extension(35, "")
  -- supported_versions: TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
  extensions[#extensions + 1] = extension(43, u8(4) .. u16(0x0304) .. u16(0x0303))
  -- psk_key_exchange_modes: psk_dhe_ke
  extensions[#extensions + 1] = extension(45, u8(1) .. u8(1))
  -- key_share: one x25519 share of 32 bytes
  local share = string.rep("\0", 32)
  local shares = u16(#share + 4) .. u16(0x001d) .. u16(#share) .. share
  extensions[#extensions + 1] = extension(51, shares)
  if alpn and #alpn > 0 then
    local protocols = {}
    for _, name in ipairs(alpn) do protocols[#protocols + 1] = u8(#name) .. name end
    local list = table.concat(protocols)
    extensions[#extensions + 1] = extension(16, u16(#list) .. list)
  end

  local extension_block = table.concat(extensions)
  local body = u16(0x0303)                      -- legacy_version: TLS 1.2
    .. client_random(hostname or "nmap")
    .. u8(0)                                    -- session id length
    .. cipher_block
    .. u8(1) .. u8(0)                           -- compression: null
    .. u16(#extension_block) .. extension_block
  local handshake = u8(1) .. u24(#body) .. body  -- client_hello
  return u8(22) .. u16(0x0301) .. u16(#handshake) .. handshake
end

----------------------------------------------------------------------------
-- 4. Decoding the answer
----------------------------------------------------------------------------

local function read_u16(data, offset)
  if offset + 1 > #data then return nil end
  return string.byte(data, offset) * 256 + string.byte(data, offset + 1)
end

local function read_u24(data, offset)
  if offset + 2 > #data then return nil end
  return string.byte(data, offset) * 65536 + string.byte(data, offset + 1) * 256
    + string.byte(data, offset + 2)
end

-- Parse the first record the peer sent. Anything that is not a TLS record is
-- reported as such, with the first bytes quoted, because the caller may be a
-- plaintext protocol that deserves its own classification.
function M.parse_reply(data)
  local out = { bytes = data and #data or 0 }
  if not data or #data == 0 then
    out.kind = "empty"
    out.summary = "the peer closed without sending a byte"
    return out
  end
  local first = string.byte(data, 1)
  out.first_byte = first
  out.preview = string.sub(data, 1, 8)
  if first < 20 or first > 23 or #data < 5 then
    out.kind = "not-tls"
    out.summary = string.format("first byte 0x%02x is not a TLS record type", first)
    return out
  end
  out.kind = "tls-record"
  out.record_type = first
  out.record_type_name = M.RECORD_TYPES[first] or ("type " .. tostring(first))
  out.record_version = read_u16(data, 2)
  out.record_version_text = out.record_version
    and string.format("0x%04x", out.record_version) or "unknown"
  out.record_length = read_u16(data, 4)
  if out.record_length and out.record_length > #data - 5 then
    out.truncated = true
    out.summary = string.format("the record announces %d byte(s) but only %d arrived",
      out.record_length, #data - 5)
  end
  if first == 21 and #data >= 7 then
    local level, description = string.byte(data, 6), string.byte(data, 7)
    out.kind = "tls-alert"
    out.alert_level = level
    out.alert_level_name = level == 1 and "warning" or (level == 2 and "fatal" or "unknown")
    out.alert_description = description
    out.alert_name = M.ALERTS[description] or ("alert " .. tostring(description))
    out.summary = string.format("TLS alert %s (%s): the listener speaks TLS and refused the hello",
      out.alert_name, out.alert_level_name)
    return out
  end
  if first == 22 and #data >= 9 then
    local handshake_type = string.byte(data, 6)
    out.handshake_type = handshake_type
    out.handshake_name = M.HANDSHAKE_TYPES[handshake_type] or ("type " .. tostring(handshake_type))
    local handshake_length = read_u24(data, 7)
    out.handshake_length = handshake_length
    if handshake_type == 2 and #data >= 9 + 2 + 32 + 1 then
      -- The record header is five bytes and the handshake header four, so the
      -- ServerHello body starts at byte ten.
      local offset = 10
      out.server_version = read_u16(data, offset)
      offset = offset + 2
      out.server_random = string.sub(data, offset, offset + 31)
      offset = offset + 32
      local session_length = string.byte(data, offset) or 0
      out.session_id_length = session_length
      offset = offset + 1 + session_length
      out.cipher_suite = read_u16(data, offset)
      out.cipher_suite_name = out.cipher_suite and M.SUITE_BY_ID[out.cipher_suite]
        and M.SUITE_BY_ID[out.cipher_suite].name
        or (out.cipher_suite and string.format("0x%04x", out.cipher_suite) or nil)
      local suite = out.cipher_suite and M.SUITE_BY_ID[out.cipher_suite]
      out.cipher_strength = suite and suite.strength or "unknown"
      out.cipher_note = suite and suite.note or nil
      offset = offset + 2
      out.compression = string.byte(data, offset)
      offset = offset + 1
      local extension_length = read_u16(data, offset)
      out.extension_length = extension_length
      offset = offset + 2
      local negotiated_version, alpn_protocol
      local finish = math.min(#data, offset + (extension_length or 0) - 1)
      while offset + 3 <= finish do
        local kind = read_u16(data, offset)
        local length = read_u16(data, offset + 2)
        offset = offset + 4
        if kind == nil or length == nil or offset + length - 1 > #data then break end
        if kind == 43 and length >= 2 then
          negotiated_version = read_u16(data, offset)
        elseif kind == 16 and length >= 3 then
          local name_length = string.byte(data, offset + 2)
          alpn_protocol = string.sub(data, offset + 3, offset + 2 + (name_length or 0))
        elseif kind == 51 and length >= 4 then
          out.key_share_group = read_u16(data, offset)
        end
        offset = offset + length
      end
      out.negotiated_version = negotiated_version
      out.negotiated_version_text = negotiated_version
        and ({ [0x0304] = "TLS 1.3", [0x0303] = "TLS 1.2", [0x0302] = "TLS 1.1",
               [0x0301] = "TLS 1.0" })[negotiated_version]
        or (negotiated_version and string.format("0x%04x", negotiated_version) or nil)
      out.alpn = alpn_protocol
      out.kind = "tls-server-hello"
      out.summary = string.format("TLS ServerHello: %s with %s", out.negotiated_version_text
        or out.record_version_text, out.cipher_suite_name or "an unknown suite")
    else
      out.summary = string.format("TLS handshake record of type %s", out.handshake_name)
    end
    return out
  end
  out.summary = string.format("TLS record type %s of %d byte(s)", out.record_type_name, out.record_length or 0)
  return out
end

----------------------------------------------------------------------------
-- 5. The probe
----------------------------------------------------------------------------

-- Open a socket, send the hello, and read whatever comes back. The socket is
-- always closed here: the caller gets a classification, not a connection, since
-- a TLS listener cannot answer the plaintext protocol the script is auditing.
function M.probe(host, port, opts)
  opts = opts or {}
  local timeout = opts.timeout_ms or 4000
  local out = { target = string.format("%s:%d", tostring(host), tonumber(port) or 0) }
  local socket, err = nmap.new_socket("tcp")
  if not socket then
    out.kind = "socket-error"
    out.summary = "socket creation failed: " .. tostring(err)
    return out
  end
  socket:set_timeout(timeout)
  local connected, connect_error = socket:connect(tostring(host), tonumber(port))
  if not connected then
    socket:close()
    out.kind = "connect-failed"
    out.summary = "connect failed: " .. tostring(connect_error)
    return out
  end
  local hello = M.client_hello({ hostname = opts.hostname, alpn = opts.alpn,
    include_tls13 = opts.include_tls13 })
  out.hello_bytes = #hello
  local sent, send_error = socket:send(hello)
  if not sent then
    socket:close()
    out.kind = "send-failed"
    out.summary = "send failed: " .. tostring(send_error)
    return out
  end
  local ok, data = socket:receive_bytes(opts.read_bytes or 4096)
  socket:close()
  if not ok then
    out.kind = "silent"
    out.summary = string.format("no answer to a %d byte ClientHello within %dms: a TLS listener "
      .. "that intends to answer would have replied with a handshake or an alert, so the peer is "
      .. "either a plaintext protocol or a filtered path", #hello, timeout)
    out.error = tostring(data)
    return out
  end
  local parsed = M.parse_reply(data)
  for key, value in pairs(parsed) do out[key] = value end
  out.hello_answered = true
  return out
end

-- A plaintext protocol on the same port has its own fingerprint. Recognising
-- the first bytes turns "there was an answer" into "the answer was Kafka", which
-- is what a listener audit has to distinguish.
M.PLAINTEXT_MARKERS = {
  { marker = "\0\0", kind = "length-prefixed binary protocol",
    note = "a four byte length followed by a correlation id: the shape of the protocol this script audits" },
  { marker = "HTTP/1.", kind = "HTTP", note = "plaintext HTTP on the audit port" },
  { marker = "AMQP", kind = "AMQP", note = "an AMQP protocol header" },
  { marker = "SSH-", kind = "SSH", note = "an SSH banner" },
  { marker = "-ERR", kind = "Redis", note = "a Redis error reply" },
  { marker = "+OK", kind = "Redis", note = "a Redis status reply" },
  { marker = "220 ", kind = "SMTP", note = "an SMTP greeting" },
  { marker = "RFB ", kind = "VNC", note = "a VNC server banner" },
  { marker = "PONG", kind = "memcached", note = "a memcached reply" },
}

function M.classify_plaintext(data)
  if not data or #data == 0 then return nil end
  for _, entry in ipairs(M.PLAINTEXT_MARKERS) do
    if string.sub(data, 1, #entry.marker) == entry.marker then
      return entry
    end
  end
  if #data >= 8 then
    -- A length-prefixed frame whose length matches reality is the strongest
    -- plaintext evidence there is.
    local declared = string.byte(data, 1) * 16777216 + string.byte(data, 2) * 65536
      + string.byte(data, 3) * 256 + string.byte(data, 4)
    if declared == #data - 4 then
      return { marker = string.sub(data, 1, 4), kind = "length-prefixed binary protocol",
        note = string.format("a %d byte frame whose prefix matches its length", declared) }
    end
  end
  return { marker = string.sub(data, 1, 4), kind = "unrecognised",
    note = "no known plaintext greeting; the bytes are quoted for review" }
end

return M
