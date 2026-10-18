local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Audits the size and type of the host key an SSH server presents during the
key exchange, flagging small RSA moduli (1024-bit and 1536-bit) that are
within reach of well-resourced factoring attacks, and reporting the full
key identity for change tracking.

Why it matters
- The host key is the root of trust for the entire SSH session: a broken
  host key means a broken session, every time.
- 1024-bit RSA was already treated as deprecated by NIST in 2013 and is
  considered factorable by nation-state actors; 2048-bit is the current
  minimum for RSA, 3072-bit the recommended target.
- Host keys are rarely rotated, so a small key generated years ago stays in
  place indefinitely unless someone measures it.

What the script does
1. Opens a TCP connection, reads the banner and completes the KEXINIT
   exchange.
2. Reads the host key presented by the server during the exchange
   (KEXDH_REPLY), parsing the key type and the public key blob
   (RSA modulus length, ECDSA point, Ed25519 raw key).
3. Classifies the key size:
   - RSA below 2048 bits => MEDIUM finding (factorable horizon).
   - RSA 2048 bits => acceptable minimum (informational).
   - RSA 3072 bits or above / ed25519 / ecdsa nistp256+ => strong.
4. Reports the key type, bit strength, the deprecation note from the audit
   table and the raw type string for change tracking.
5. When the server does not present a host key before the userauth phase,
   reports that the key could not be observed pre-authentication.

Pre-authentication only: banner, KEXINIT and host key read; no credentials,
no channels.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"defensive", "safe"}

portrule = shortport.port_or_service(
  22,
  "ssh",
  "tcp"
)

local SCRIPT_NAME = "ssh-hostkey-size-audit"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  maxrequests = 12,
  timeout = 8,
  retries = 1,
  delay = 0.3,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
  { key = "retries", minimum = 0, maximum = 5, integer = true },
  { key = "delay", minimum = 0 },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

local RSA_MIN_BITS = 2048
local RSA_TARGET_BITS = 3072
local HOSTKEY_CVSS = "5.9"

local SSH_CVSS = {
  hostkey_small = HOSTKEY_CVSS,
}

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local function trim(value)
  if type(value) ~= "string" then
    return value
  end
  value = string.gsub(value, "^%s+", "")
  value = string.gsub(value, "%s+$", "")
  return value
end

local function lower(value)
  if type(value) ~= "string" then
    return ""
  end
  return string.lower(trim(value))
end

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function ends_with(value, suffix)
  if #suffix > #value then
    return false
  end
  return string.sub(value, -#suffix) == suffix
end

local function contains(value, needle)
  return string.find(value or "", needle, 1, true) ~= nil
end

local function split(value, separator)
  local parts = {}
  if type(value) ~= "string" or #value == 0 then
    return parts
  end
  for chunk in string.gmatch(value, "([^" .. separator .. "]+)") do
    table.insert(parts, trim(chunk))
  end
  return parts
end

local function list_contains(list, needle)
  for _, item in ipairs(list or {}) do
    if item == needle then
      return true
    end
  end
  return false
end

local function table_size(tbl)
  local count = 0
  for _ in pairs(tbl or {}) do
    count = count + 1
  end
  return count
end

local function sorted_keys(tbl)
  local keys = {}
  for key in pairs(tbl or {}) do
    table.insert(keys, key)
  end
  table.sort(keys)
  return keys
end

local function unique_append(list, seen, value)
  if seen[value] then
    return false
  end
  seen[value] = true
  table.insert(list, value)
  return true
end

local function clamp(value, minimum, maximum)
  if value < minimum then
    return minimum
  end
  if value > maximum then
    return maximum
  end
  return value
end

local function byte_hex(value, count)
  local out = {}
  for i = 1, math.min(count or 16, #(value or "")) do
    table.insert(out, string.format("%02x", string.byte(value, i)))
  end
  return table.concat(out, " ")
end

local function truncate(value, limit)
  if type(value) ~= "string" then
    return tostring(value)
  end
  if #value <= limit then
    return value
  end
  return string.sub(value, 1, limit) .. "..."
end

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #(value or "") do
    hash = (hash ~ string.byte(value, i)) & 0xFFFFFFFF
    hash = (hash * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

local function entropy_bits(value)
  if type(value) ~= "string" or #value == 0 then
    return 0
  end
  local counts = {}
  for i = 1, #value do
    local char = string.sub(value, i, i)
    counts[char] = (counts[char] or 0) + 1
  end
  local length = #value
  local entropy = 0
  for _, count in pairs(counts) do
    local probability = count / length
    entropy = entropy - probability * (math.log(probability) / math.log(2))
  end
  return entropy
end

local function random_token(length, uppercase)
  local alphabet = uppercase and "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    or "abcdefghijklmnopqrstuvwxyz0123456789"
  local out = {}
  for _ = 1, length do
    local index = math.random(1, #alphabet)
    table.insert(out, string.sub(alphabet, index, index))
  end
  return table.concat(out)
end

local function seed_random(port)
  math.randomseed((os.time() * 65537) + ((port and port.number) or 0)
    + ((stdnse.clock_ms and stdnse.clock_ms()) or 0))
end

local state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }

local function reset_state()
  state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }
end

local function budget_exhausted(args)
  return state.requests >= args.maxrequests
end

local function sleep(seconds)
  if seconds and seconds > 0 then
    stdnse.sleep(seconds)
  end
end

local function read_args()
  local args = {}
  for key, value in pairs(DEFAULT_ARGS) do
    args[key] = value
  end

  for _, spec in ipairs(NUMERIC_ARGS) do
    local raw = stdnse.get_script_args(SCRIPT_NAME .. "." .. spec.key)
    local value = tonumber(raw)
    if value and value >= spec.minimum and (not spec.maximum or value <= spec.maximum) then
      if spec.integer then
        args[spec.key] = math.floor(value)
      else
        args[spec.key] = value
      end
    end
  end

  for _, key in ipairs(BOOLEAN_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if value ~= nil then
      args[key] = not (value == false or value == "false" or value == "no" or value == "0")
    end
  end

  for _, key in ipairs(STRING_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if type(value) == "string" and #trim(value) > 0 then
      args[key] = trim(value)
    elseif type(value) == "table" and #value > 0 then
      args[key] = trim(tostring(value[1]))
    end
  end

  local raw_list = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if raw_list and #tostring(raw_list) > 0 then
    local list = {}
    for candidate in string.gmatch(tostring(raw_list), "[^,]+") do
      local normalized = trim(candidate)
      if #normalized > 0 then
        if not starts_with(normalized, "/") then
          normalized = "/" .. normalized
        end
        table.insert(list, normalized)
      end
    end
    if #list > 0 then
      args.paths = list
    end
  end

  return args
end

local SSH_MSG = {
  KEXINIT = 20,
  NEWKEYS = 21,
  SERVICE_REQUEST = 5,
  SERVICE_ACCEPT = 6,
  USERAUTH_REQUEST = 50,
  USERAUTH_FAILURE = 51,
  USERAUTH_SUCCESS = 52,
  USERAUTH_PK_OK = 60,
  GLOBAL_REQUEST = 80,
  REQUEST_SUCCESS = 81,
  REQUEST_FAILURE = 82,
  CHANNEL_OPEN = 90,
  CHANNEL_OPEN_CONFIRMATION = 91,
  CHANNEL_OPEN_FAILURE = 92,
  CHANNEL_REQUEST = 98,
  CHANNEL_SUCCESS = 99,
  CHANNEL_FAILURE = 100,
}

local SSH_CIPHERS_WEAK = {
  ["3des-cbc"] = "broken key size, CBC mode",
  ["3des-counter"] = "broken key size",
  ["arcfour"] = "broken stream cipher",
  ["arcfour128"] = "broken stream cipher",
  ["arcfour256"] = "broken stream cipher",
  ["blowfish-cbc"] = "64-bit block CBC (birthday attacks)",
  ["cast128-cbc"] = "64-bit block CBC (birthday attacks)",
  ["idea-cbc"] = "patented 64-bit block cipher",
  ["twofish-cbc"] = "64-bit block CBC",
  ["serpent-cbc"] = "64-bit block CBC",
  ["aes128-cbc"] = "CBC mode (ETM recommended)",
  ["aes192-cbc"] = "CBC mode (ETM recommended)",
  ["aes256-cbc"] = "CBC mode (ETM recommended)",
}

local SSH_CIPHERS_MODERN = {
  ["aes128-ctr"] = true,
  ["aes192-ctr"] = true,
  ["aes256-ctr"] = true,
  ["aes128-gcm@openssh.com"] = true,
  ["aes256-gcm@openssh.com"] = true,
  ["chacha20-poly1305@openssh.com"] = true,
}

local SSH_KEX_WEAK = {
  ["diffie-hellman-group1-sha1"] = "1024-bit DH, SHA-1 (Logjam)",
  ["diffie-hellman-group14-sha1"] = "SHA-1 (upgrade to -sha256)",
  ["diffie-hellman-group-exchange-sha1"] = "SHA-1",
}

local SSH_KEX_MODERN = {
  ["curve25519-sha256"] = true,
  ["curve25519-sha256@libssh.org"] = true,
  ["diffie-hellman-group14-sha256"] = true,
  ["diffie-hellman-group16-sha512"] = true,
  ["diffie-hellman-group18-sha512"] = true,
  ["diffie-hellman-group-exchange-sha256"] = true,
  ["ecdh-sha2-nistp256"] = true,
  ["ecdh-sha2-nistp384"] = true,
  ["ecdh-sha2-nistp521"] = true,
}

local SSH_MACS_WEAK = {
  ["hmac-md5"] = "MD5-based",
  ["hmac-md5-96"] = "MD5-based truncated",
  ["hmac-ripemd160"] = "RIPEMD-160 collision era",
  ["hmac-sha1-96"] = "truncated SHA-1",
  ["umac-64@openssh.com"] = "64-bit tag",
  ["hmac-sha1"] = "SHA-1 (upgrade to sha2)",
}

local SSH_MACS_MODERN = {
  ["hmac-sha2-256"] = true,
  ["hmac-sha2-512"] = true,
  ["umac-128@openssh.com"] = true,
  ["hmac-sha2-256-etm@openssh.com"] = true,
  ["hmac-sha2-512-etm@openssh.com"] = true,
  ["umac-128-etm@openssh.com"] = true,
}

local SSH_HOSTKEY_TYPES_DEPRECATION = {
  ["ssh-dss"] = "deprecated (1024-bit DSA, broken for new deployments)",
  ["ssh-rsa"] = "acceptable only with RSA >= 2048 bits",
}

local function ssh_split_namelist(text)
  local list = {}
  for name in string.gmatch(tostring(text or ""), "([^,]+)") do
    if #name > 0 then
      list[#list + 1] = name
    end
  end
  if #list == 0 and #tostring(text or "") > 0 then
    list[#list + 1] = text
  end
  return list
end

local function ssh_encode_string(value)
  local data = tostring(value or "")
  local len = #data
  return string.char(
    math.floor(len / 16777216) % 256,
    math.floor(len / 65536) % 256,
    math.floor(len / 256) % 256,
    len % 256
  ) .. data
end

local function ssh_read_string(data, position)
  if position + 4 > #data then
    return nil, "truncated string length"
  end
  local len = string.byte(data, position) * 16777216
    + string.byte(data, position + 1) * 65536
    + string.byte(data, position + 2) * 256
    + string.byte(data, position + 3)
  if position + 3 + len > #data then
    return nil, "truncated string payload"
  end
  return string.sub(data, position + 4, position + 3 + len), position + 4 + len
end

local function ssh_parse_identification(raw)
  local line = tostring(raw or "")
  line = line:match("^(.-)[\r\n]*$") or line
  line = line:gsub("^%s+", "")
  local protocol_version = "unknown"
  local proto_field
  local rest = ""
  if line:match("^SSH%-") then
    proto_field = line:match("^SSH%-([%d%.]+)")
    if proto_field == "2.0" then
      protocol_version = "SSH-2.0"
    elseif proto_field == "1.99" or proto_field == "1.5" then
      protocol_version = "SSH-1 (legacy compatibility identifier)"
    else
      protocol_version = "unknown (" .. tostring(proto_field) .. ")"
    end
    rest = line:match("^SSH%-[%d%.]+%-?(.*)$") or ""
    rest = rest:gsub("^%s+", "")
  end
  local vendor
  local version
  if rest:match("^OpenSSH[_ ]") then
    vendor = "OpenSSH"
    version = rest:match("OpenSSH[_ ]([%d%.%w]+)")
  elseif rest:match("^libssh%-%d") then
    vendor = "libssh"
    version = rest:match("libssh%-([%d%.]+)")
  elseif rest:match("^Dropbear") then
    vendor = "Dropbear"
    version = rest:match("Dropbear[_ ]?([%d%.]*)")
  elseif rest:match("^libcrypt") then
    vendor = "libcrypt"
    version = rest:match("libcrypt%-?([%d%.]*)")
  elseif rest:match("^ssh%-") then
    vendor = "ssh2"
    version = rest:match("ssh%-?2%-?([%d%.]*)")
  elseif #rest > 0 then
    vendor = rest:match("^(%S+)")
    version = rest:match("%-([%d%.%w%-]*)$")
  end
  return {
    raw = line,
    proto_field = proto_field,
    protocol_version = protocol_version,
    software = rest,
    vendor = vendor,
    version = version,
  }
end

local function ssh_build_identification()
  return "SSH-2.0-nmap-audit_1.0"
end

local SSH_CLIENT_KEX = {
  kex = "curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
  host_key = "ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
  cipher_c2s = "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com",
  cipher_s2c = "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com",
  mac_c2s = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256",
  mac_s2c = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256",
  comp_c2s = "none,zlib@openssh.com",
  comp_s2c = "none,zlib@openssh.com",
  lang_c2s = "",
  lang_s2c = "",
}

local function ssh_frame_packet(payload)
  local pad_len = 8 - (#payload % 8)
  if pad_len < 4 then
    pad_len = pad_len + 8
  end
  local packet_len = 1 + #payload + pad_len
  local padding = ""
  for i = 1, pad_len do
    padding = padding .. string.char(math.random(1, 255))
  end
  return string.char(
    math.floor(packet_len / 16777216) % 256,
    math.floor(packet_len / 65536) % 256,
    math.floor(packet_len / 256) % 256,
    packet_len % 256
  ) .. string.char(pad_len) .. payload .. padding
end

local function ssh_build_kexinit_packet()
  local cookie = ""
  for _ = 1, 16 do
    cookie = cookie .. string.char(math.random(0, 255))
  end
  local body = cookie
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.kex)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.host_key)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.cipher_c2s)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.cipher_s2c)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.mac_c2s)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.mac_s2c)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.comp_c2s)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.comp_s2c)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.lang_c2s)
  body = body .. ssh_encode_string(SSH_CLIENT_KEX.lang_s2c)
  local payload = string.char(SSH_MSG.KEXINIT) .. body
  return ssh_frame_packet(payload)
end

local function ssh_parse_kexinit(body)
  if #body < 1 + 16 then
    return nil, "truncated KEXINIT"
  end
  local pos = 18
  local fields = {
    "kex_algorithms",
    "server_host_key_algorithms",
    "ciphers_client_to_server",
    "ciphers_server_to_client",
    "macs_client_to_server",
    "macs_server_to_client",
    "compressions_client_to_server",
    "compressions_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
  }
  local info = { cookie = string.sub(body, 2, 17) }
  for _, name in ipairs(fields) do
    local value, p2 = ssh_read_string(body, pos)
    if value == nil then
      info[name] = ""
      break
    end
    info[name] = value
    pos = p2
  end
  return info
end

local function ssh_classify_algorithm(algorithm, kind)
  if kind == "cipher" then
    if SSH_CIPHERS_WEAK[algorithm] then
      return { status = "weak", note = SSH_CIPHERS_WEAK[algorithm] }
    end
    if SSH_CIPHERS_MODERN[algorithm] then
      return { status = "modern", note = "recommended" }
    end
  elseif kind == "kex" then
    if SSH_KEX_WEAK[algorithm] then
      return { status = "weak", note = SSH_KEX_WEAK[algorithm] }
    end
    if SSH_KEX_MODERN[algorithm] then
      return { status = "modern", note = "recommended" }
    end
  elseif kind == "mac" then
    if SSH_MACS_WEAK[algorithm] then
      return { status = "weak", note = SSH_MACS_WEAK[algorithm] }
    end
    if SSH_MACS_MODERN[algorithm] then
      return { status = "modern", note = "recommended" }
    end
  elseif kind == "hostkey" then
    if SSH_HOSTKEY_TYPES_DEPRECATION[algorithm] then
      return { status = "deprecated", note = SSH_HOSTKEY_TYPES_DEPRECATION[algorithm] }
    end
    if algorithm == "ssh-ed25519" then
      return { status = "modern", note = "recommended" }
    end
    if algorithm:match("^ecdsa-sha2-nistp") then
      return { status = "modern", note = "acceptable" }
    end
    if algorithm:match("^rsa-sha2-") then
      return { status = "modern", note = "recommended for RSA" }
    end
  end
  return { status = "unknown", note = "not in audit tables" }
end

local function ssh_namelist_report(namelist, kind, limit)
  limit = limit or 40
  local list = ssh_split_namelist(namelist)
  local rows = {}
  local weak = {}
  for i, name in ipairs(list) do
    if i > limit then
      break
    end
    local cls = ssh_classify_algorithm(name, kind)
    if cls.status == "weak" or cls.status == "deprecated" then
      weak[#weak + 1] = name .. " (" .. cls.note .. ")"
    end
    rows[#rows + 1] = { name = name, status = cls.status, note = cls.note }
  end
  return { list = rows, weak = weak, total = #list }
end

local function ssh_parse_hostkey(blob)
  local pos = 1
  local keytype, p2 = ssh_read_string(blob, pos)
  if keytype == nil then
    return nil, "not a valid host key blob"
  end
  pos = p2
  local result = { type = keytype, bits = nil, public_data = nil }
  if keytype == "ssh-rsa" or keytype:match("^rsa%-sha2%-") then
    local e, p3 = ssh_read_string(blob, pos)
    if e == nil then
      return nil, "truncated RSA e"
    end
    pos = p3
    local n, p4 = ssh_read_string(blob, pos)
    if n == nil then
      return nil, "truncated RSA n"
    end
    pos = p4
    result.bits = #n * 8
    result.public_data = n
  elseif keytype:match("^ecdsa-sha2-nistp") then
    local curve, p3 = ssh_read_string(blob, pos)
    if curve == nil then
      return nil, "truncated curve"
    end
    pos = p3
    local point, p4 = ssh_read_string(blob, pos)
    if point == nil then
      return nil, "truncated point"
    end
    result.bits = #point * 8 - 8
    result.public_data = point
  elseif keytype == "ssh-ed25519" then
    local raw, p3 = ssh_read_string(blob, pos)
    if raw == nil then
      return nil, "truncated key"
    end
    result.bits = #raw * 8
    result.public_data = raw
  end
  return result
end

local SSH_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function ssh_mod32(v)
  return v % 4294967296
end

local function ssh_bit_and(a, b)
  local r = 0
  local p = 1
  for _ = 0, 31 do
    if a % 2 == 1 and b % 2 == 1 then
      r = r + p
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function ssh_bit_or(a, b)
  local r = 0
  local p = 1
  for _ = 0, 31 do
    if a % 2 == 1 or b % 2 == 1 then
      r = r + p
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function ssh_bit_xor(a, b)
  local r = 0
  local p = 1
  for _ = 0, 31 do
    if (a % 2) + (b % 2) == 1 then
      r = r + p
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function ssh_bit_not32(a)
  return 4294967295 - (a % 4294967296)
end

local function ssh_shl32(x, n)
  return (x * (2 ^ n)) % 4294967296
end

local function ssh_shr32(x, n)
  return math.floor(x / (2 ^ n)) % 4294967296
end

local function ssh_rotr32(x, n)
  return (ssh_shl32(x, 32 - n) + ssh_shr32(x, n)) % 4294967296
end

local function ssh_rotl32(x, n)
  return (ssh_shl32(x, n) + ssh_shr32(x, 32 - n)) % 4294967296
end

local MD5_T = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

local function ssh_md5(data)
  local len = #data
  local padded_len = math.floor((len + 8) / 64 + 1) * 64
  local padded = data .. string.char(0x80)
  padded = padded .. string.rep(string.char(0), padded_len - #padded - 8)
  local bit_len = len * 8
  local le = ""
  for i = 0, 7 do
    le = le .. string.char(math.floor(bit_len / (256 ^ i)) % 256)
  end
  padded = padded .. le
  local a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  local round_shifts = { { 7, 12, 17, 22 }, { 5, 9, 14, 20 }, { 4, 11, 16, 23 }, { 6, 10, 15, 21 } }
  for chunk_start = 1, padded_len, 64 do
    local M = {}
    for i = 0, 15 do
      local o = chunk_start + i * 4
      M[i + 1] = ssh_mod32(string.byte(padded, o)
        + string.byte(padded, o + 1) * 256
        + string.byte(padded, o + 2) * 65536
        + string.byte(padded, o + 3) * 16777216)
    end
    local A, B, C, D = a0, b0, c0, d0
    for i = 1, 64 do
      local f
      local g
      if i <= 16 then
        f = ssh_bit_or(ssh_bit_and(B, C), ssh_bit_and(ssh_bit_not32(B), D))
        g = i - 1
      elseif i <= 32 then
        f = ssh_bit_or(ssh_bit_and(D, B), ssh_bit_and(ssh_bit_not32(D), C))
        g = (5 * (i - 1) + 1) % 16
      elseif i <= 48 then
        f = ssh_mod32(ssh_mod32(ssh_bit_xor(ssh_bit_xor(B, C), D)))
        g = (3 * (i - 1) + 5) % 16
      else
        f = ssh_bit_xor(C, ssh_bit_or(B, ssh_bit_not32(D)))
        g = (7 * (i - 1)) % 16
      end
      f = ssh_mod32(f + A + MD5_T[i] + M[g + 1])
      A = D
      D = C
      C = B
      B = ssh_mod32(B + ssh_rotl32(f, round_shifts[math.floor((i - 1) / 16) + 1][(i - 1) % 4 + 1]))
    end
    a0 = ssh_mod32(a0 + A)
    b0 = ssh_mod32(b0 + B)
    c0 = ssh_mod32(c0 + C)
    d0 = ssh_mod32(d0 + D)
  end
  local out = ""
  for _, v in ipairs({ a0, b0, c0, d0 }) do
    for i = 0, 3 do
      out = out .. string.char(math.floor(v / (256 ^ i)) % 256)
    end
  end
  return out
end

local SHA256_K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function ssh_sha256(data)
  local len = #data
  local padded = data .. string.char(0x80)
  while #padded % 64 ~= 56 do
    padded = padded .. string.char(0)
  end
  local bit_len = len * 8
  for i = 7, 0, -1 do
    padded = padded .. string.char(math.floor(bit_len / (256 ^ i)) % 256)
  end
  local H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  for chunk_start = 1, #padded, 64 do
    local w = {}
    for i = 0, 15 do
      local o = chunk_start + i * 4
      w[i + 1] = ssh_mod32(string.byte(padded, o) * 16777216
        + string.byte(padded, o + 1) * 65536
        + string.byte(padded, o + 2) * 256
        + string.byte(padded, o + 3))
    end
    for i = 17, 64 do
      local s0 = ssh_mod32(ssh_bit_xor(ssh_bit_xor(ssh_rotr32(w[i - 15], 7), ssh_rotr32(w[i - 15], 18)), ssh_shr32(w[i - 15], 3)))
      local s1 = ssh_mod32(ssh_bit_xor(ssh_bit_xor(ssh_rotr32(w[i - 2], 17), ssh_rotr32(w[i - 2], 19)), ssh_shr32(w[i - 2], 10)))
      w[i] = ssh_mod32(w[i - 16] + s0 + w[i - 7] + s1)
    end
    local a, b, c, d = H[1], H[2], H[3], H[4]
    local e, f, g, h = H[5], H[6], H[7], H[8]
    for i = 1, 64 do
      local S1 = ssh_mod32(ssh_bit_xor(ssh_bit_xor(ssh_rotr32(e, 6), ssh_rotr32(e, 11)), ssh_rotr32(e, 25)))
      local ch = ssh_mod32(ssh_bit_or(ssh_bit_and(e, f), ssh_bit_and(ssh_bit_not32(e), g)))
      local t1 = ssh_mod32(h + S1 + ch + SHA256_K[i] + w[i])
      local S0 = ssh_mod32(ssh_bit_xor(ssh_bit_xor(ssh_rotr32(a, 2), ssh_rotr32(a, 13)), ssh_rotr32(a, 22)))
      local maj = ssh_mod32(ssh_bit_or(ssh_bit_or(ssh_bit_and(a, b), ssh_bit_and(a, c)), ssh_bit_and(b, c)))
      local t2 = ssh_mod32(S0 + maj)
      h = g
      g = f
      f = e
      e = ssh_mod32(d + t1)
      d = c
      c = b
      b = a
      a = ssh_mod32(t1 + t2)
    end
    H[1] = ssh_mod32(H[1] + a)
    H[2] = ssh_mod32(H[2] + b)
    H[3] = ssh_mod32(H[3] + c)
    H[4] = ssh_mod32(H[4] + d)
    H[5] = ssh_mod32(H[5] + e)
    H[6] = ssh_mod32(H[6] + f)
    H[7] = ssh_mod32(H[7] + g)
    H[8] = ssh_mod32(H[8] + h)
  end
  local out = ""
  for _, v in ipairs(H) do
    for i = 3, 0, -1 do
      out = out .. string.char(math.floor(v / (256 ^ i)) % 256)
    end
  end
  return out
end

local function ssh_base64(data)
  local out = {}
  for i = 1, #data, 3 do
    local b1 = data:byte(i)
    local b2 = data:byte(i + 1)
    local b3 = data:byte(i + 2)
    local v1 = math.floor(b1 / 4)
    local v2 = (b1 % 4) * 16 + (b2 and math.floor(b2 / 16) or 0)
    out[#out + 1] = SSH_B64_ALPHABET:sub(v1 + 1, v1 + 1)
    out[#out + 1] = SSH_B64_ALPHABET:sub(v2 + 1, v2 + 1)
    if b2 then
      local v3 = (b2 % 16) * 4 + (b3 and math.floor(b3 / 64) or 0)
      out[#out + 1] = SSH_B64_ALPHABET:sub(v3 + 1, v3 + 1)
      if b3 then
        out[#out + 1] = SSH_B64_ALPHABET:sub((b3 % 64) + 1, (b3 % 64) + 1)
      else
        out[#out + 1] = "="
      end
    else
      out[#out + 1] = "="
      out[#out + 1] = "="
    end
  end
  return table.concat(out)
end

local function ssh_md5_fingerprint(data)
  local digest = ssh_md5(data)
  local parts = {}
  for i = 1, #digest do
    parts[#parts + 1] = string.format("%02x", digest:byte(i))
  end
  return table.concat(parts, ":")
end

local function ssh_sha256_fingerprint(data)
  return "SHA256:" .. ssh_base64(ssh_sha256(data))
end

local SSH_CVE_TABLE = {
  {
    id = "CVE-2024-6387",
    name = "regreSSHion (pre-auth signal handler race)",
    vendor = "OpenSSH",
    vulnerable_from = "8.5",
    vulnerable_to = "9.7",
    fixed_in = "9.8",
    note = "pre-authentication RCE via SIGALRM race in the privileged child process; affects OpenSSH 8.5 through 9.7",
  },
  {
    id = "CVE-2023-48795",
    name = "Terrapin (prefix truncation of SSH encryption/MAC)",
    vendor = "OpenSSH",
    cipher_gate = "chacha20-poly1305@openssh.com",
    note = "protocol prefix-truncation attack; exposure increases when chacha20-poly1305 is offered and EtM is not enforced",
  },
  {
    id = "CVE-2018-10933",
    name = "libssh publickey authentication bypass",
    vendor = "libssh",
    vulnerable_from = "0.0.1",
    vulnerable_to = "0.8.2",
    fixed_in = "0.8.3",
    note = "empty publickey challenge allows bypass of authentication on libssh < 0.8.3",
  },
}

local function ssh_version_compare(a, b)
  local pa = {}
  for digit in string.gmatch(tostring(a or ""), "%d+") do
    pa[#pa + 1] = tonumber(digit)
  end
  local pb = {}
  for digit in string.gmatch(tostring(b or ""), "%d+") do
    pb[#pb + 1] = tonumber(digit)
  end
  for i = 1, math.max(#pa, #pb) do
    local va = pa[i] or 0
    local vb = pb[i] or 0
    if va ~= vb then
      return va < vb and -1 or 1
    end
  end
  return 0
end

local function ssh_check_cve(vendor, version, kex_info)
  local results = {}
  for _, cve in ipairs(SSH_CVE_TABLE) do
    local entry = { id = cve.id, name = cve.name, status = "not applicable", detail = "" }
    if cve.vendor == "OpenSSH" and vendor == "OpenSSH" and version then
      if cve.cipher_gate then
        local offers_chacha = kex_info
          and (kex_info.ciphers_client_to_server:find(cve.cipher_gate, 1, true) ~= nil)
        if offers_chacha then
          entry.status = "exposed"
          entry.detail = cve.note
        else
          entry.status = "not exposed (chacha20-poly1305 not offered)"
        end
      else
        local in_range = ssh_version_compare(version, cve.vulnerable_from) >= 0
          and ssh_version_compare(version, cve.fixed_in) < 0
        if in_range then
          entry.status = "vulnerable"
          entry.detail = cve.note
        else
          entry.status = "not in vulnerable range"
        end
      end
    elseif cve.vendor == "libssh" and vendor == "libssh" and version then
      local in_range = ssh_version_compare(version, cve.vulnerable_from) >= 0
        and ssh_version_compare(version, cve.fixed_in) < 0
      if in_range then
        entry.status = "vulnerable"
        entry.detail = cve.note
      else
        entry.status = "not in vulnerable range"
      end
    end
    results[#results + 1] = entry
  end
  return results
end

local function ssh_methods_split(methods)
  return ssh_split_namelist(methods)
end

local function ssh_parse_userauth_failure(body)
  local pos = 2
  local username, p2 = ssh_read_string(body, pos)
  if username == nil then
    return nil, "truncated username"
  end
  pos = p2
  local methods, p3 = ssh_read_string(body, pos)
  if methods == nil then
    return nil, "truncated methods"
  end
  return { username = username, methods = methods }
end

local function ssh_parse_service(body)
  local service, p2 = ssh_read_string(body, 2)
  return { service = service }
end

local function ssh_session_new(host, port, args)
  return {
    host = host,
    port = port,
    args = args,
    sock = nil,
    connected = false,
    closed = false,
    ident_raw = nil,
    ident = nil,
    kex = nil,
    hostkey = nil,
    hostkey_blob = nil,
    auth_methods = nil,
    authenticated = false,
    auth_user = nil,
    auth_attempts = 0,
    dropped_by_server = false,
    channel_local_id = 0,
    channel_remote_id = nil,
    channel_open = false,
    channel_requests = {},
    service_requests = {},
    extra_packets = {},
    keyboard_info = nil,
    errors = 0,
  }
end

local function ssh_socket_open(sess, ssl)
  local sock = nmap.new_socket()
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local proto = ssl and "ssl" or "tcp"
  local ok, err = sock:connect(sess.host, sess.port, proto)
  if not ok then
    sock:close()
    return nil, "TCP connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  return sock
end

local function ssh_send(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function ssh_read_exact(sess, count)
  if not sess.sock then
    return nil, "no socket"
  end
  local attempts = 0
  while attempts < 3 do
    attempts = attempts + 1
    local ok, data, err = sess.sock:receive_bytes(count)
    if ok and data and #data >= count then
      return data
    end
    if ok and data and #data > 0 then
      local attempts2 = 0
      while #data < count and attempts2 < 5 do
        attempts2 = attempts2 + 1
        local ok2, more, err2 = sess.sock:receive_bytes(count - #data)
        if ok2 and more and #more > 0 then
          data = data .. more
        else
          break
        end
      end
      if #data >= count then
        return data
      end
      if #data > 0 then
        sess.errors = sess.errors + 1
        return nil, "truncated read (" .. #data .. "/" .. count .. ")"
      end
      sess.errors = sess.errors + 1
    end
  end
  return nil, "read timeout"
end

local function ssh_read_ident_line(sess)
  local ok, line, err = sess.sock:receive("*n")
  if not ok or not line or #line == 0 then
    if err and err ~= "" then
      return nil, "identification read failed: " .. tostring(err)
    end
    return nil, "no identification string received"
  end
  sess.ident_raw = line
  sess.ident = ssh_parse_identification(line)
  return sess.ident
end

local function ssh_read_packet(sess)
  local hdr, err = ssh_read_exact(sess, 4)
  if not hdr then
    return nil, err
  end
  local plen = hdr:byte(1) * 16777216
    + hdr:byte(2) * 65536
    + hdr:byte(3) * 256
    + hdr:byte(4)
  if plen < 5 or plen > 4096 then
    sess.dropped_by_server = true
    return nil, "malformed packet length " .. tostring(plen)
  end
  local body, e2 = ssh_read_exact(sess, plen)
  if not body then
    return nil, e2
  end
  local padlen = body:byte(1)
  if padlen < 4 or 1 + padlen > plen then
    return nil, "malformed packet padding " .. tostring(padlen)
  end
  local payload = string.sub(body, 2, plen - padlen)
  local mtype = payload:byte(1)
  return { type = mtype, payload = payload }
end

local function ssh_write_packet(sess, payload)
  local framed = ssh_frame_packet(payload)
  return ssh_send(sess, framed)
end

local function ssh_kexinit_exchange(sess)
  local kexinit_frame = ssh_build_kexinit_packet()
  local ok, err = ssh_send(sess, kexinit_frame)
  if not ok then
    return nil, "KEXINIT send failed: " .. tostring(err)
  end
  for _ = 1, 8 do
    local packet, e2 = ssh_read_packet(sess)
    if not packet then
      return nil, "KEXINIT exchange read failed: " .. tostring(e2)
    end
    if packet.type == SSH_MSG.KEXINIT then
      local info, e3 = ssh_parse_kexinit(packet.payload)
      if not info then
        return nil, "KEXINIT parse failed: " .. tostring(e3)
      end
      sess.kex = info
      return sess.kex
    end
    if packet.type ~= SSH_MSG.NEWKEYS and packet.type ~= SSH_MSG.SERVICE_REQUEST
      and packet.type ~= SSH_MSG.SERVICE_ACCEPT then
      sess.extra_packets[#sess.extra_packets + 1] = packet.type
    end
  end
  return nil, "no KEXINIT received from server"
end

local function ssh_read_hostkey(sess, max_packets)
  for _ = 1, (max_packets or 6) do
    local packet, e2 = ssh_read_packet(sess)
    if not packet then
      return nil, e2
    end
    if packet.type == 32 then
      local blob, e3 = ssh_read_string(packet.payload, 2)
      if not blob then
        return nil, "hostkey blob parse failed: " .. tostring(e3)
      end
      sess.hostkey_blob = blob
      local info, e4 = ssh_parse_hostkey(blob)
      if not info then
        return nil, "hostkey decode failed: " .. tostring(e4)
      end
      sess.hostkey = info
      return sess.hostkey
    end
    if packet.type == SSH_MSG.USERAUTH_REQUEST or packet.type >= 50 then
      return nil, "server did not present a host key before userauth"
    end
    sess.extra_packets[#sess.extra_packets + 1] = packet.type
  end
  return nil, "no host key presented"
end

local function ssh_build_userauth_request(service, user, method, password)
  local payload = string.char(SSH_MSG.USERAUTH_REQUEST)
    .. ssh_encode_string(service or "ssh-connection")
    .. ssh_encode_string(user)
    .. ssh_encode_string(method)
  if method == "password" then
    payload = payload .. string.char(1) .. ssh_encode_string(password or "")
  elseif method == "keyboard-interactive" then
    payload = payload
      .. ssh_encode_string("")
      .. ssh_encode_string("")
  elseif method == "publickey" then
    payload = payload
      .. string.char(0)
      .. ssh_encode_string("")
      .. ssh_encode_string("")
  end
  return payload
end

local function ssh_read_userauth_response(sess)
  for _ = 1, 4 do
    local packet, e2 = ssh_read_packet(sess)
    if not packet then
      sess.dropped_by_server = true
      return nil, "connection closed by server during authentication"
    end
    if packet.type == SSH_MSG.USERAUTH_SUCCESS then
      sess.authenticated = true
      return { result = "success" }
    end
    if packet.type == SSH_MSG.USERAUTH_FAILURE then
      local info, e3 = ssh_parse_userauth_failure(packet.payload)
      if info then
        sess.auth_methods = info.methods
        return { result = "failure", methods = info.methods, username = info.username }
      end
      return { result = "failure", methods = "" }
    end
    if packet.type == 53 then
      local pos = 2
      local username, p2 = ssh_read_string(packet.payload, pos)
      if username == nil then
        return { result = "info-request" }
      end
      pos = p2
      local instructions, p3 = ssh_read_string(packet.payload, pos)
      if instructions == nil then
        return { result = "info-request" }
      end
      pos = p3
      if pos + 4 > #packet.payload then
        return { result = "info-request" }
      end
      local prompt_count = packet.payload:byte(pos) * 16777216
        + packet.payload:byte(pos + 1) * 65536
        + packet.payload:byte(pos + 2) * 256
        + packet.payload:byte(pos + 3)
      pos = pos + 4
      local prompts = {}
      for i = 1, prompt_count do
        local text, p4 = ssh_read_string(packet.payload, pos)
        if text == nil then
          break
        end
        pos = p4
        prompts[#prompts + 1] = { text = text, echo = false }
      end
      for i = 1, prompt_count do
        if pos <= #packet.payload then
          local flag = packet.payload:byte(pos)
          pos = pos + 1
          if prompts[i] then
            prompts[i].echo = (flag == 1)
          end
        end
      end
      sess.keyboard_info = { username = username, instructions = instructions, prompts = prompts }
      return { result = "info-request", username = username, instructions = instructions, prompts = prompts }
    end
    sess.extra_packets[#sess.extra_packets + 1] = packet.type
  end
  return nil, "no userauth response received"
end

local function ssh_userauth_request(sess, service, user, method, password)
  sess.auth_attempts = sess.auth_attempts + 1
  local payload = ssh_build_userauth_request(service, user, method, password)
  local ok, err = ssh_write_packet(sess, payload)
  if not ok then
    return nil, "USERAUTH send failed: " .. tostring(err)
  end
  return ssh_read_userauth_response(sess)
end

local function ssh_channel_open(sess, channel_type)
  local channel_type_name = channel_type or "session"
  local payload = string.char(SSH_MSG.CHANNEL_OPEN)
    .. ssh_encode_string(channel_type_name)
    .. string.char(0, 0, 0, sess.channel_local_id)
    .. ssh_encode_string("")
    .. string.char(0, 2, 0, 0)
    .. string.char(0, 0, 8, 0)
  local ok, err = ssh_write_packet(sess, payload)
  if not ok then
    return nil, "CHANNEL_OPEN send failed: " .. tostring(err)
  end
  for _ = 1, 4 do
    local packet, e2 = ssh_read_packet(sess)
    if not packet then
      sess.dropped_by_server = true
      return nil, "connection closed by server during channel setup"
    end
    if packet.type == SSH_MSG.CHANNEL_OPEN_CONFIRMATION then
      local pos = 2
      if pos + 8 > #packet.payload then
        sess.channel_open = true
        return { ok = true, remote_id = 0 }
      end
      local lid = packet.payload:byte(pos) * 16777216
        + packet.payload:byte(pos + 1) * 65536
        + packet.payload:byte(pos + 2) * 256
        + packet.payload:byte(pos + 3)
      local rid = packet.payload:byte(pos + 4) * 16777216
        + packet.payload:byte(pos + 5) * 65536
        + packet.payload:byte(pos + 6) * 256
        + packet.payload:byte(pos + 7)
      sess.channel_open = true
      sess.channel_remote_id = rid
      return { ok = true, local_id = lid, remote_id = rid }
    end
    if packet.type == SSH_MSG.CHANNEL_OPEN_FAILURE then
      local pos = 2
      if pos + 8 > #packet.payload then
        return { ok = false, reason = "unknown" }
      end
      local reason = packet.payload:byte(pos + 8)
      local reasons = {
        [1] = "administratively prohibited",
        [2] = "connect failed",
        [3] = "unknown channel type",
        [4] = "resource shortage",
      }
      local lang, p2 = ssh_read_string(packet.payload, pos + 9)
      return { ok = false, reason = reasons[reason] or ("code " .. tostring(reason)), lang = lang }
    end
    sess.extra_packets[#sess.extra_packets + 1] = packet.type
  end
  return nil, "no channel open response"
end

local function ssh_channel_request(sess, channel_id, request_type, want_reply)
  local want = (want_reply == false) and 0 or 1
  local payload = string.char(SSH_MSG.CHANNEL_REQUEST)
    .. string.char(0, 0, 0, channel_id or sess.channel_local_id)
    .. ssh_encode_string(request_type)
    .. string.char(want)
  local ok, err = ssh_write_packet(sess, payload)
  if not ok then
    return nil, "CHANNEL_REQUEST send failed: " .. tostring(err)
  end
  if want == 0 then
    return { ok = nil }
  end
  for _ = 1, 3 do
    local packet, e2 = ssh_read_packet(sess)
    if not packet then
      sess.dropped_by_server = true
      return nil, "connection closed by server during channel request"
    end
    if packet.type == SSH_MSG.CHANNEL_SUCCESS then
      sess.channel_requests[request_type] = "success"
      return { ok = true }
    end
    if packet.type == SSH_MSG.CHANNEL_FAILURE then
      sess.channel_requests[request_type] = "failure"
      return { ok = false }
    end
    sess.extra_packets[#sess.extra_packets + 1] = packet.type
  end
  return nil, "no channel request response"
end

local function ssh_service_request(sess, service)
  local payload = string.char(SSH_MSG.SERVICE_REQUEST) .. ssh_encode_string(service)
  local ok, err = ssh_write_packet(sess, payload)
  if not ok then
    return nil, "SERVICE_REQUEST send failed: " .. tostring(err)
  end
  for _ = 1, 3 do
    local packet, e2 = ssh_read_packet(sess)
    if not packet then
      sess.dropped_by_server = true
      return nil, "connection closed by server during service request"
    end
    if packet.type == SSH_MSG.SERVICE_ACCEPT then
      sess.service_requests[service] = "accepted"
      return { ok = true, service = service }
    end
    if packet.type == 7 then
      sess.service_requests[service] = "rejected"
      return { ok = false, service = service }
    end
    sess.extra_packets[#sess.extra_packets + 1] = packet.type
  end
  return nil, "no service request response"
end

local function ssh_close_session(sess)
  if sess and sess.sock and not sess.closed then
    sess.closed = true
    pcall(function()
      sess.sock:close()
    end)
  end
end

local function ssh_session_summary(sess)
  local summary = stdnse.output_table()
  summary["Connection"] = "established to port " .. tostring(sess.port)
  if sess.ident then
    summary["Server identification"] = sess.ident_raw or ""
    summary["Detected software"] = tostring(sess.ident.vendor or "unknown")
    if sess.ident.version then
      summary["Detected version"] = sess.ident.version
    end
  end
  if sess.auth_methods then
    summary["Authentication methods offered"] = sess.auth_methods
  end
  summary["Authentication attempts"] = tostring(sess.auth_attempts)
  if sess.dropped_by_server then
    summary["Server behavior"] = "server closed the connection during probing"
  end
  return summary
end

local function ssh_session_open(host, port, args)
  local sess = ssh_session_new(host, port, args)
  local sock, err = ssh_socket_open(sess)
  if not sock then
    return nil, err
  end
  local ident, e2 = ssh_read_ident_line(sess)
  if not ident then
    ssh_close_session(sess)
    return nil, e2
  end
  local kex, e3 = ssh_kexinit_exchange(sess)
  if not kex then
    ssh_close_session(sess)
    return sess, "kexinit exchange failed: " .. tostring(e3)
  end
  return sess
end

local function ssh_probe_preauth(host, port, args)
  local sess, err = ssh_session_open(host, port, args)
  if not sess then
    return nil, err
  end
  local hostkey, e2 = ssh_read_hostkey(sess, 6)
  if hostkey then
    sess.hostkey = hostkey
  end
  if sess.ident and sess.ident.vendor then
    sess.cve_results = ssh_check_cve(sess.ident.vendor, sess.ident.version, sess.kex)
  end
  return sess
end

local function ssh_probe_authed(host, port, args)
  local sess, err = ssh_session_open(host, port, args)
  if not sess then
    return nil, err
  end
  local none_result, e2 = ssh_userauth_request(sess, "ssh-connection", "audit", "none")
  if none_result and none_result.methods then
    sess.auth_methods = none_result.methods
  end
  if none_result and none_result.result == "success" then
    return sess
  end
  local pw_result, e3 = ssh_userauth_request(sess, "ssh-connection", "audit", "password", args.test_password or "AuditPass123")
  if pw_result and pw_result.result == "success" then
    return sess
  end
  return sess
end

local function ssh_probe_channel(host, port, args)
  local sess, err = ssh_probe_authed(host, port, args)
  if not sess then
    return nil, err
  end
  if sess.authenticated then
    local open_result, e2 = ssh_channel_open(sess, "session")
    if open_result and open_result.ok then
      local req, e3 = ssh_channel_request(sess, open_result.local_id or 0, "agent-foreground-openssh", true)
      if req then
        sess.agent_forwarding = req.ok
      end
    end
  end
  return sess
end

local findings = {}

local function add_finding(severity, detail, extra)
  local entry = {
    severity = severity,
    weight = SEVERITY[severity] or SEVERITY.INFO,
    detail = detail,
    path = extra and extra.path,
    subject = extra and extra.subject,
    confidence = extra and extra.confidence or "high",
    evidence = extra and extra.evidence,
  }
  if entry.confidence == "low" then
    entry.weight = math.max(0, math.floor(entry.weight / 2))
  end
  table.insert(findings, entry)
  return entry
end

local function reset_findings()
  findings = {}
end

local function dedupe_findings()
  local unique = {}
  local index = {}
  local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  for _, finding in ipairs(findings) do
    local key = tostring(finding.subject or "-") .. "|" .. finding.severity .. "|" .. finding.detail
    if not index[key] then
      index[key] = {
        severity = finding.severity,
        weight = finding.weight,
        subject = finding.subject,
        detail = finding.detail,
        confidence = finding.confidence,
        paths = {},
        evidence = {},
      }
      table.insert(unique, index[key])
    end
    local entry = index[key]
    if finding.path then
      local seen_path = false
      for _, existing in ipairs(entry.paths) do
        if existing == finding.path then
          seen_path = true
        end
      end
      if not seen_path then
        table.insert(entry.paths, finding.path)
      end
    end
    if finding.evidence then
      local sample = truncate(tostring(finding.evidence), 120)
      local seen_evidence = false
      for _, existing in ipairs(entry.evidence) do
        if existing == sample then
          seen_evidence = true
        end
      end
      if not seen_evidence and #entry.evidence < 4 then
        table.insert(entry.evidence, sample)
      end
    end
    counts[finding.severity] = (counts[finding.severity] or 0) + 1
  end

  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  table.sort(unique, function(a, b)
    local first = order[a.severity] or 9
    local second = order[b.severity] or 9
    if first ~= second then
      return first < second
    end
    if a.weight ~= b.weight then
      return a.weight > b.weight
    end
    return tostring(a.detail) < tostring(b.detail)
  end)

  return unique, counts
end

local function weighted_score(unique)
  local score = 0
  for _, finding in ipairs(unique) do
    local multiplier = 1
    local path_count = #(finding.paths or {})
    if path_count > 1 then
      multiplier = multiplier + math.min(path_count - 1, 5) * 0.1
    end
    score = score + (finding.weight or 0) * multiplier
  end
  return math.floor(score + 0.5)
end

local function render_findings(unique, include_info)
  local rendered = {}
  for _, finding in ipairs(unique) do
    if finding.severity ~= "INFO" or include_info then
      local line = string.format("[%s] %s", finding.severity, finding.detail)
      if finding.subject and finding.subject ~= "-" then
        line = line .. " (" .. tostring(finding.subject) .. ")"
      end
      if finding.paths and #finding.paths > 0 then
        local shown = finding.paths
        if #shown > 3 then
          shown = { shown[1], shown[2], string.format("+%d more", #finding.paths - 2) }
        end
        line = line .. " [paths: " .. table.concat(shown, ", ") .. "]"
      end
      if finding.evidence and #finding.evidence > 0 then
        line = line .. " [evidence: " .. table.concat(finding.evidence, " | ") .. "]"
      end
      if finding.confidence == "low" then
        line = line .. " [low confidence]"
      end
      table.insert(rendered, line)
    end
  end
  return rendered
end

local function new_output(risk, status)
  local out = stdnse.output_table()
  out["Risk Level"] = risk
  out["Status"] = status
  return out
end

local function finish_output(out, unique, counts, extra_sections)
  local rendered = render_findings(unique, false)
  if #rendered == 0 then
    table.insert(rendered, "no weaknesses detected by this audit")
  end
  out["Findings"] = rendered
  out["Severity counts"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
    counts.CRITICAL or 0, counts.HIGH or 0, counts.MEDIUM or 0,
    counts.LOW or 0, counts.INFO or 0)
  out["Weighted score"] = tostring(weighted_score(unique))
  for _, section in ipairs(extra_sections or {}) do
    if section.value ~= nil then
      out[section.key] = section.value
    end
  end
  out["Requests issued"] = tostring(state.requests)
  if state.rate_limited > 0 then
    out["Rate limited responses"] = tostring(state.rate_limited)
  end
  if state.errors > 0 then
    out["Transport errors"] = tostring(state.errors)
  end
  return out
end

local function classify_key(hostkey)
  local type_name = hostkey.type or "unknown"
  local bits = hostkey.bits
  local verdict
  local note
  if type_name == "ssh-ed25519" then
    verdict = "strong"
    note = "curve25519-based, no factoring surface"
  elseif type_name:match("^ecdsa%-sha2%-nistp") then
    if bits and bits >= 256 then
      verdict = "strong"
      note = "ECDSA on a modern curve"
    else
      verdict = "acceptable"
      note = "ECDSA curve size at the minimum"
    end
  elseif type_name == "ssh-rsa" or type_name:match("^rsa%-sha2%-%d+") then
    if not bits then
      verdict = "unknown"
      note = "RSA key presented but modulus length could not be parsed"
    elseif bits < RSA_MIN_BITS then
      verdict = "weak"
      note = string.format("%d-bit RSA is below the %d-bit minimum; within factoring reach for well-resourced adversaries", bits, RSA_MIN_BITS)
    elseif bits < RSA_TARGET_BITS then
      verdict = "acceptable"
      note = string.format("%d-bit RSA meets the minimum but is below the %d-bit target", bits, RSA_TARGET_BITS)
    else
      verdict = "strong"
      note = string.format("%d-bit RSA meets the current target", bits)
    end
  else
    local dep = SSH_HOSTKEY_TYPES_DEPRECATION[type_name]
    if dep then
      verdict = "weak"
      note = "deprecated key type: " .. dep
    else
      verdict = "unknown"
      note = "key type not in the audit tables"
    end
  end
  return verdict, note
end

local function remediation_section(weak)
  local remediation = stdnse.output_table()
  if weak then
    remediation["1. Regenerate the Host Key"] = "Generate a new host key (rsa 3072 or ed25519) with ssh-keygen and replace the small one; notify users of the new fingerprint first."
    remediation["2. Prefer ed25519"] = "Modern clients (OpenSSH 6.5+) accept ssh-ed25519 host keys, which have no factoring surface at all."
    remediation["3. Track Fingerprint Changes"] = "Publish the new host key fingerprint (this collection's fingerprint script) and alert on unexpected changes."
  else
    remediation["1. Keep the Key Strong"] = "Re-run this audit after any host key rotation to confirm the replacement meets the size policy."
    remediation["2. Plan the Rotation"] = "Schedule a rotation to ed25519 or rsa3072 at the next maintenance window to stay ahead of the deprecation curve."
  end
  return { key = "Remediation", value = remediation }
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()

local sess, err = ssh_session_open(host, port, args)
local sections = {}

if not sess then
  local status_text = "INFORMATIONAL - host key audit incomplete: " .. tostring(err)
  add_finding("INFO", "Could not complete the key exchange phase", {
    subject = "host key",
    evidence = tostring(err),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections)
end

local keytab = stdnse.output_table()
local status_text
local verdict = "unobserved"
local note = "no host key presented before the userauth phase"

local hostkey, e1 = ssh_read_hostkey(sess, 6)
if hostkey then
  verdict, note = classify_key(hostkey)
  keytab["Key type"] = hostkey.type
  keytab["Key strength"] = hostkey.bits and (hostkey.bits .. " bits") or "not measurable for this key type"
  keytab["Classification"] = verdict
  keytab["Assessment note"] = note
  local dep = SSH_HOSTKEY_TYPES_DEPRECATION[hostkey.type]
  if dep then
    keytab["Deprecation note"] = dep
  end
else
  keytab["Key type"] = "not observed"
  keytab["Key strength"] = "n/a"
  keytab["Classification"] = "unobserved"
  keytab["Assessment note"] = tostring(e1 or note)
end
table.insert(sections, { key = "Host Key Audit", value = keytab })

if verdict == "weak" then
  status_text = "VULNERABLE - SSH host key is below the minimum size (" .. tostring(keytab["Key type"]) .. ", " .. tostring(keytab["Key strength"]) .. ")"
  add_finding("MEDIUM", "Server presents a small or deprecated host key", {
    subject = tostring(keytab["Key type"]),
    evidence = note,
    confidence = "high",
  })
elseif verdict == "acceptable" then
  status_text = "CAUTION - SSH host key meets the minimum but not the target (" .. tostring(keytab["Key strength"]) .. ")"
  add_finding("INFO", "Host key is at the acceptable minimum size", {
    subject = tostring(keytab["Key type"]),
    evidence = note,
    confidence = "high",
  })
elseif verdict == "strong" then
  status_text = "SECURE - SSH host key meets the current size target"
  add_finding("INFO", "Host key size is adequate", {
    subject = tostring(keytab["Key type"]),
    evidence = note,
    confidence = "high",
  })
else
  status_text = "INFORMATIONAL - host key could not be observed pre-authentication: " .. note
  add_finding("INFO", "No host key seen before the userauth phase", {
    subject = "key exchange",
    evidence = tostring(e1 or "server did not present a host key"),
    confidence = "low",
  })
end

table.insert(sections, remediation_section(verdict == "weak"))
local cvss_value = verdict == "weak" and (HOSTKEY_CVSS .. " (small host key exposure)") or "n/a - key size adequate or unobserved"
table.insert(sections, { key = "CVSS Score", value = cvss_value })

ssh_close_session(sess)
local unique, counts = dedupe_findings()
local out = new_output(RISK_LEVEL, status_text)
return finish_output(out, unique, counts, sections)

end
