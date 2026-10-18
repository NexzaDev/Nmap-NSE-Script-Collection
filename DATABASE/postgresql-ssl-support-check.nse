local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Sends a PostgreSQL SSLRequest to determine whether the server offers
to negotiate a TLS channel for the connection.

Why it matters
- PostgreSQL clients only encrypt credentials and queries when the
  server advertises TLS support and the client requests it (sslmode).
  A server that answers 'N' to the SSLRequest forces every client
  that is not hard-locked to sslmode=verify-full to fall back to a
  cleartext connection - usernames and passwords included.
- Many managed and on-prem PostgreSQL deployments leave ssl off
  because the certificates were never issued; the SSLRequest check is
  the fastest way to prove the cleartext exposure without completing
  a handshake.
- The result feeds directly into the audit narrative: combined with
  the trust-auth check it shows whether a default-configured server
  is simultaneously unencrypted and unauthenticated.

What the script does
1. Sends the 8-byte SSLRequest message (code 80877103), exactly what
   libpq sends before a StartupMessage.
2. Parses the single-byte server reply: 'S' (83) means the server
   is willing to negotiate TLS (INFO - the exposure depends on
   client sslmode policy); 'N' (78) means the server refuses TLS
   (MEDIUM - credentials will travel in cleartext unless clients
   are locked to verify-full, which a non-TLS server cannot satisfy
   anyway).
3. Records the raw reply byte for context and reports the expected
   client-side mitigation.
4. Emits MEDIUM for a TLS refusal and INFO for a TLS offer; a
   non-standard reply byte is reported as inconclusive with the raw
   value.

Exactly one 8-byte request is sent; no handshake is completed and no
credentials are involved.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5432, "postgresql")

local SCRIPT_NAME = "postgresql-ssl-support-check"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  maxrequests = 2,
  timeout = 10,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

local PG_SSL_CONTEXT = {
  offered = "clients using sslmode=disable or sslmode=prefer will connect in cleartext unless policy is set to sslmode=verify-full",
  refused = "no client can establish a TLS channel to this server; every connection is cleartext regardless of sslmode",
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

local function db_u8(n)
  return string.char(n % 256)
end

local function db_u16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function db_u16le(n)
  return string.char(n % 256, math.floor(n / 256) % 256)
end

local function db_u24(n)
  return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function db_u32(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256)
end

local function db_u32le(n)
  return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 16777216) % 256)
end

local function db_b8(b)
  return b:byte(1)
end

local function db_b16(b)
  return b:byte(1) * 256 + b:byte(2)
end

local function db_b16le(b)
  return b:byte(1) + b:byte(2) * 256
end

local function db_b24(b)
  return b:byte(1) * 65536 + b:byte(2) * 256 + b:byte(3)
end

local function db_b32(b)
  return b:byte(1) * 16777216 + b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
end

local function db_b32le(b)
  return b:byte(1) + b:byte(2) * 256 + b:byte(3) * 65536 + b:byte(4) * 16777216
end

local function db_u64be(n)
  local hi = math.floor(n / 4294967296)
  local lo = n - hi * 4294967296
  return db_u32(hi) .. db_u32(lo)
end

local function db_pack_double(value)
  if value == 0 then
    value = 0
  end
  local negative = 0
  if value < 0 then
    negative = 0x80000000
    value = -value
  end
  local exponent = 0
  local mantissa = value
  while mantissa >= 2 and exponent < 1023 do
    mantissa = mantissa / 2
    exponent = exponent + 1
  end
  while mantissa < 1 and exponent > -1022 do
    mantissa = mantissa * 2
    exponent = exponent - 1
  end
  local biased = exponent + 1023
  local frac = math.floor((mantissa - 1) * 4503599627370496 + 0.5)
  local hi = (negative + biased * 1048576 + math.floor(frac / 16777216)) % 4294967296
  local lo = frac % 16777216
  return db_u32(hi) .. db_u32(lo)
end

local function db_unpack_double(b)
  local hi = db_b32le(b:sub(5, 8))
  local lo = db_b32le(b)
  local sgn = math.floor(hi / 2147483648) == 0 and 1 or -1
  local exp_field = math.floor(hi / 1048576) % 2048
  local frac = (hi % 1048576) * 4294967296 + lo
  if exp_field == 2047 then
    if frac == 0 then
      if sgn == 1 then
        return 1 / 0
      end
      return -1 / 0
    end
    return 0 / 0
  end
  if exp_field == 0 then
    return sgn * (frac / 9007199254740992)
  end
  return sgn * ((1 + frac / 4503599627370496) * 2 ^ (exp_field - 1023))
end

local function db_cstr(value)
  return tostring(value) .. "\0"
end

local function db_read_cstr(data, pos)
  local endpos = string.find(data, "\0", pos, true)
  if not endpos then
    return nil, pos
  end
  return string.sub(data, pos, endpos - 1), endpos + 1
end

local RESP_SIMPLE = 43
local RESP_ERROR = 45
local RESP_INTEGER = 58
local RESP_BULK = 36
local RESP_ARRAY = 42

local function db_parse_resp(data)
  local pos = 1
  local ok, value, err = nil, nil, "no data"
  local function parse_value(position)
    if position > #data then
      return nil, nil, "truncated"
    end
    local t = data:byte(position)
    if t == RESP_SIMPLE or t == RESP_ERROR then
      local found = string.sub(data, position + 1):match("([^\r\n]*)\r\n")
      local npos = position + 1 + #found + 2
      if t == RESP_ERROR then
        return "error", found, nil, npos
      end
      return "string", found, nil, npos
    end
    if t == RESP_INTEGER then
      local num = string.match(data, "^:(-?%d*)\r\n", position)
      if num == nil then
        return nil, nil, "bad integer", position
      end
      local npos = position + 1 + #num + 2
      return "integer", tonumber(num), nil, npos
    end
    if t == RESP_BULK then
      local len_str = string.match(data, "^%$(-?%d+)\r\n", position)
      if len_str == nil then
        return nil, nil, "bad bulk", position
      end
      local npos = position + 1 + #len_str + 2
      local len = tonumber(len_str)
      if len < 0 then
        return "nil", nil, nil, npos
      end
      local bytes = string.sub(data, npos, npos + len - 1)
      npos = npos + len
      if string.sub(data, npos, npos + 1) == "\r\n" then
        npos = npos + 2
      end
      return "bulk", bytes, nil, npos
    end
    if t == RESP_ARRAY then
      local cnt_str = string.match(data, "^%*(-?%d+)\r\n", position)
      if cnt_str == nil then
        return nil, nil, "bad array", position
      end
      local npos = position + 1 + #cnt_str + 2
      local count = tonumber(cnt_str)
      if count < 0 then
        return "nil", nil, nil, npos
      end
      local items = {}
      for _ = 1, count do
        local kind, val, perr, newpos = parse_value(npos)
        if kind == nil then
          return nil, nil, perr or "bad array element", npos
        end
        items[#items + 1] = val
        npos = newpos
      end
      return "array", items, nil, npos
    end
    return nil, nil, "unknown type " .. tostring(t), position
  end
  ok, value, err, pos = parse_value(pos)
  return ok, value, err
end

local function db_resp_command(parts)
  local out = "*" .. #parts .. "\r\n"
  for _, p in ipairs(parts) do
    local s = tostring(p)
    out = out .. "$" .. #s .. "\r\n" .. s .. "\r\n"
  end
  return out
end

local function db_json_unescape(s)
  local out = {}
  local i = 1
  while i <= #s do
    local c = s:sub(i, i)
    if c == "\\" then
      local n = s:sub(i + 1, i + 1)
      if n == "n" then table.insert(out, "\n")
      elseif n == "t" then table.insert(out, "\t")
      elseif n == "r" then table.insert(out, "\r")
      elseif n == "b" then table.insert(out, "\b")
      elseif n == "f" then table.insert(out, "\f")
      elseif n == "\"" then table.insert(out, "\"")
      elseif n == "/" then table.insert(out, "/")
      elseif n == "\\" then table.insert(out, "\\")
      elseif n == "u" then
        local hex = s:sub(i + 2, i + 5)
        local code = tonumber(hex, 16)
        if code and code < 128 then
          table.insert(out, string.char(code))
        else
          table.insert(out, "?")
        end
        i = i + 4
      else
        table.insert(out, n)
      end
      i = i + 2
    else
      table.insert(out, c)
      i = i + 1
    end
  end
  return table.concat(out)
end

local function db_json_parse(text)
  local source = tostring(text or "")
  local len = #source
  local function skip_ws(p)
    local _, e = string.find(source, "^%s*", p)
    return e + 1
  end
  local parse_value
  local function parse_object(p)
    local obj = {}
    local keys = {}
    p = skip_ws(p)
    if source:sub(p, p) == "}" then
      return "object", obj, p + 1
    end
    while p <= len do
      local k = string.match(source, "^\"([^\"]*)\"", p)
      if k == nil then
        break
      end
      p = skip_ws(p + 2 + #k)
      if source:sub(p, p) ~= ":" then
        break
      end
      p = p + 1
      local _, val, newp = parse_value(p)
      if newp == nil then
        break
      end
      obj[k] = val
      keys[#keys + 1] = k
      p = skip_ws(newp)
      local sep = source:sub(p, p)
      if sep == "," then
        p = p + 1
      elseif sep == "}" then
        p = p + 1
        break
      else
        break
      end
    end
    return "object", obj, p
  end
  local function parse_array(p)
    local arr = {}
    p = skip_ws(p)
    if source:sub(p, p) == "]" then
      return "array", arr, p + 1
    end
    while p <= len do
      local _, val, newp = parse_value(p)
      if newp == nil then
        break
      end
      arr[#arr + 1] = val
      p = skip_ws(newp)
      local sep = source:sub(p, p)
      if sep == "," then
        p = p + 1
      elseif sep == "]" then
        p = p + 1
        break
      else
        break
      end
    end
    return "array", arr, p
  end
  parse_value = function(p)
    p = skip_ws(p)
    if p > len then
      return nil, nil, p
    end
    local c = source:sub(p, p)
    if c == "{" then
      return parse_object(p + 1)
    end
    if c == "[" then
      return parse_array(p + 1)
    end
    if c == "\"" then
      local raw = string.match(source, "^\"([^\"]*)\"", p)
      if raw == nil then
        return nil, nil, p
      end
      return "string", db_json_unescape(raw), p + 2 + #raw
    end
    if c == "t" and source:sub(p, p + 3) == "true" then
      return "boolean", true, p + 4
    end
    if c == "f" and source:sub(p, p + 4) == "false" then
      return "boolean", false, p + 5
    end
    if c == "n" and source:sub(p, p + 3) == "null" then
      return "nil", nil, p + 4
    end
    local num = string.match(source, "^(-?%d+%.?%d*[eE]?[+-]?%d*)", p)
    if num then
      return "number", tonumber(num), p + #num
    end
    return nil, nil, p
  end
  local _, value, _ = parse_value(1)
  return value
end

local MYSQL_CAPS = {
  [0x0001] = "CLIENT_LONG_PASSWORD",
  [0x0002] = "CLIENT_FOUND_ROWS",
  [0x0004] = "CLIENT_LONG_FLAG",
  [0x0008] = "CLIENT_CONNECT_WITH_DB",
  [0x0010] = "CLIENT_NO_SCHEMA",
  [0x0020] = "CLIENT_COMPRESS",
  [0x0040] = "CLIENT_ODBC",
  [0x0080] = "CLIENT_LOCAL_FILES",
  [0x0100] = "CLIENT_IGNORE_SPACE",
  [0x0200] = "CLIENT_PROTOCOL_41",
  [0x0400] = "CLIENT_INTERACTIVE",
  [0x0800] = "CLIENT_SSL",
  [0x1000] = "CLIENT_IGNORE_SIGPIPE",
  [0x2000] = "CLIENT_TRANSACTIONS",
  [0x4000] = "CLIENT_RESERVED",
  [0x8000] = "CLIENT_SECURE_CONNECTION",
  [0x00010000] = "CLIENT_MULTI_STATEMENTS",
  [0x00020000] = "CLIENT_MULTI_RESULTS",
  [0x00100000] = "CLIENT_PLUGIN_AUTH",
  [0x00200000] = "CLIENT_CONNECT_ATTRS",
  [0x00400000] = "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
}

local function db_mysql_cap_names(caps)
  local names = {}
  for bit, name in pairs(MYSQL_CAPS) do
    if (math.floor(caps / bit) % 2) == 1 then
      names[#names + 1] = name
    end
  end
  table.sort(names)
  return names
end

local function db_mysql_cap_set(caps, bit)
  return (math.floor(caps / bit) % 2) == 1
end

local function db_mysql_packet(payload, seq)
  local len = #payload
  return db_u24(len) .. db_u8(seq or 0) .. payload
end

local function db_mysql_handshake_bytes(version, thread_id, auth_part1, caps, charset, status, plugin, auth_part2)
  local caps_low = caps % 65536
  local caps_high = math.floor(caps / 65536) % 65536
  local out = db_u8(10) .. db_cstr(version)
  out = out .. db_u32le(thread_id or 0)
  out = out .. (auth_part1 or string.rep("\0", 8))
  out = out .. db_u8(0)
  out = out .. db_u16le(caps_low)
  out = out .. db_u8(charset or 0x21)
  out = out .. db_u16le(status or 0x0002)
  out = out .. db_u16le(caps_high)
  local auth_len = 21
  if auth_part2 == nil or auth_part2 == "" then
    auth_len = 0
  end
  out = out .. db_u8(auth_len)
  out = out .. string.rep("\0", 10)
  if auth_part2 ~= nil and auth_part2 ~= "" then
    out = out .. auth_part2
    if #auth_part2 < 13 then
      out = out .. string.rep("\0", 13 - #auth_part2)
    end
  end
  out = out .. db_cstr(plugin or "mysql_native_password")
  return out
end

local function db_parse_mysql_handshake(payload)
  local info = {}
  local pos = 1
  local proto = payload:byte(pos)
  if proto == nil then
    return nil
  end
  pos = pos + 1
  local version, newpos = db_read_cstr(payload, pos)
  if version == nil then
    return nil
  end
  info.version = version
  pos = newpos
  if #payload < pos + 29 then
    return info
  end
  info.thread_id = db_b32le(payload:sub(pos, pos + 3))
  pos = pos + 4
  local auth1 = payload:sub(pos, pos + 7)
  pos = pos + 8
  pos = pos + 1
  local caps_low = db_b16le(payload:sub(pos, pos + 1))
  pos = pos + 2
  info.charset = payload:byte(pos)
  pos = pos + 1
  info.status = db_b16le(payload:sub(pos, pos + 1))
  pos = pos + 2
  local caps_high = db_b16le(payload:sub(pos, pos + 1))
  pos = pos + 2
  local caps = caps_low + caps_high * 65536
  info.caps = caps
  info.cap_names = db_mysql_cap_names(caps)
  info.auth_len = payload:byte(pos)
  pos = pos + 1
  pos = pos + 10
  if db_mysql_cap_set(caps, 0x8000) and #payload >= pos + 13 then
    info.auth_part2 = payload:sub(pos, pos + 12)
    pos = pos + 13
  end
  if db_mysql_cap_set(caps, 0x00080000) and pos <= #payload then
    local plugin, plugin_pos = db_read_cstr(payload, pos)
    info.plugin = plugin
  end
  info.ssl = db_mysql_cap_set(caps, 0x0800)
  return info
end

local function db_mysql_handshake_response41(user, auth_data, plugin, database)
  local caps = 0x00100000 + 0x00020000 + 0x00008000 + 0x00002000 + 0x00000200 + 0x00000100 + 0x00000001
  local out = db_u32le(caps)
  out = out .. db_u32le(16777215)
  out = out .. db_u8(0x21)
  out = out .. string.rep("\0", 23)
  local u = tostring(user)
  out = out .. db_u16le(#u) .. u
  out = out .. db_u8(#auth_data) .. auth_data
  if database ~= nil and database ~= "" then
    out = out .. db_cstr(database)
  end
  out = out .. db_cstr(plugin or "mysql_native_password")
  return out
end

local function db_parse_mysql_response(payload)
  local head = payload:byte(1)
  if head == nil then
    return { kind = "unknown" }
  end
  if head == 0 then
    local info = { kind = "ok" }
    local pos = 2
    if #payload >= pos + 1 then
      info.affected = db_b16le(payload:sub(pos, pos + 1))
    end
    pos = pos + 2
    if #payload >= pos + 1 then
      info.last_insert = db_b16le(payload:sub(pos, pos + 1))
    end
    pos = pos + 2
    if #payload >= pos + 1 then
      info.server_status = db_b16le(payload:sub(pos, pos + 1))
    end
    return info
  end
  if head == 0xff then
    local info = { kind = "error" }
    local pos = 2
    if #payload >= pos + 1 then
      info.errno = db_b16le(payload:sub(pos, pos + 1))
    end
    pos = pos + 2
    local marker = payload:sub(pos, pos)
    if marker == "#" and #payload >= pos + 5 then
      info.sqlstate = payload:sub(pos + 1, pos + 5)
      pos = pos + 6
    end
    if pos <= #payload then
      info.message = payload:sub(pos)
    end
    return info
  end
  return { kind = "unknown" }
end

local function db_pg_ssl_request()
  return db_u32(8) .. db_u32(80877103)
end

local function db_pg_startup(user, database)
  local body = db_u32(196608)
  body = body .. "user\0" .. tostring(user) .. "\0"
  body = body .. "database\0" .. tostring(database) .. "\0"
  return db_u32(4 + #body) .. body
end

local PG_AUTH = {
  [0] = "AuthenticationOk",
  [3] = "AuthenticationCleartextPassword",
  [5] = "AuthenticationMD5Password",
  [6] = "AuthenticationGSS",
  [7] = "AuthenticationSSPI",
  [8] = "AuthenticationGSSContinue",
  [9] = "AuthenticationSASL",
  [10] = "AuthenticationSASLContinue",
  [11] = "AuthenticationSASLFinal",
  [12] = "AuthenticationScramSHA256",
}

local function db_parse_pg_message(data)
  if #data == 1 then
    local b = data:byte(1)
    if b == 83 then
      return { kind = "ssl_supported" }
    end
    if b == 78 then
      return { kind = "ssl_rejected" }
    end
    return { kind = "unknown" }
  end
  local pos = 1
  while pos + 5 <= #data do
    local t = data:byte(pos)
    local len = db_b32(data:sub(pos + 1, pos + 4))
    if len < 4 or pos + len > #data then
      break
    end
    local payload = data:sub(pos + 5, pos + len)
    pos = pos + len + 1
    if t == nil then
      break
    end
    if t == 83 then
      return { kind = "ssl_supported" }
    end
    if t == 78 then
      return { kind = "ssl_rejected" }
    end
    if t == 82 and #payload >= 4 then
      local code = db_b32(payload:sub(1, 4))
      local info = { kind = "auth", code = code, name = PG_AUTH[code] or ("code_" .. code) }
      if code == 5 and #payload >= 8 then
        info.salt = payload:sub(5, 8)
      end
      if (code == 9 or code == 12) and #payload >= 9 then
        info.mechanisms = payload:sub(9):match("([^%z]*)")
      end
      return info
    end
    if t == 69 then
      local info = { kind = "error", fields = {} }
      local p = 1
      while p <= #payload do
        if payload:byte(p) == 0 then
          break
        end
        local field_type = payload:byte(p)
        p = p + 1
        local value, newp = db_read_cstr(payload, p)
        if value == nil then
          break
        end
        p = newp
        info.fields[#info.fields + 1] = { type = field_type, value = value }
      end
      for _, f in ipairs(info.fields) do
        if f.type == 83 then info.severity = f.value end
        if f.type == 67 then info.code = f.value end
        if f.type == 77 then info.message = f.value end
      end
      return info
    end
  end
  return { kind = "unknown" }
end

local BSON_TYPES = {
  [1] = "double",
  [2] = "string",
  [3] = "document",
  [4] = "array",
  [5] = "binary",
  [8] = "boolean",
  [10] = "utcdatetime",
  [11] = "null",
  [12] = "regex",
  [16] = "int32",
  [17] = "timestamp",
  [18] = "int64",
  [19] = "decimal128",
  [255] = "minkey",
  [254] = "maxkey",
}

local function db_bson_encode_value(doc)
  local kind = type(doc)
  if kind == "number" then
    if doc == math.floor(doc) and math.abs(doc) < 2147483648 then
      return db_u8(16) .. db_u32le(math.floor(doc))
    end
    return db_u8(1) .. db_pack_double(doc)
  end
  if kind == "string" then
    local data = doc .. "\0"
    return db_u8(2) .. db_u32le(#data) .. data
  end
  if kind == "boolean" then
    return db_u8(8) .. db_u8(doc and 1 or 0)
  end
  if kind == "table" then
    local is_array = true
    local count = 0
    for k in pairs(doc) do
      count = count + 1
      if type(k) ~= "number" then
        is_array = false
        break
      end
    end
    local type_byte = is_array and count > 0 and 4 or 3
    local inner = ""
    if is_array then
      for i = 1, count do
        local v = doc[i]
        if v ~= nil then
          inner = inner .. db_cstr(tostring(i)) .. db_bson_encode_value(v)
        end
      end
    else
      local keys = {}
      for k in pairs(doc) do
        keys[#keys + 1] = k
      end
      table.sort(keys)
      for _, k in ipairs(keys) do
        inner = inner .. db_cstr(k) .. db_bson_encode_value(doc[k])
      end
    end
    return db_u8(type_byte) .. db_u32le(5 + #inner) .. inner .. "\0"
  end
  return db_u8(11)
end

local function db_bson_encode(doc)
  local inner = ""
  local keys = {}
  for k in pairs(doc) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  for _, k in ipairs(keys) do
    inner = inner .. db_cstr(k) .. db_bson_encode_value(doc[k])
  end
  return db_u32le(5 + #inner) .. inner .. "\0"
end

local function db_bson_decode(data)
  if #data < 5 then
    return nil
  end
  local total = db_b32le(data:sub(1, 4))
  if total ~= #data then
    return nil
  end
  local doc = {}
  local pos = 5
  while pos < total do
    local t = data:byte(pos)
    if t == nil or t == 0 then
      break
    end
    pos = pos + 1
    local name, newpos = db_read_cstr(data, pos)
    if name == nil then
      return doc
    end
    pos = newpos
    local value, newpos2 = nil, pos
    if t == 1 then
      value = db_unpack_double(data:sub(pos, pos + 7))
      newpos2 = pos + 8
    elseif t == 2 then
      local slen = db_b32le(data:sub(pos, pos + 3))
      value = data:sub(pos + 4, pos + 3 + slen - 1)
      newpos2 = pos + 4 + slen
    elseif t == 8 then
      value = data:byte(pos) == 1
      newpos2 = pos + 1
    elseif t == 16 then
      value = db_b32le(data:sub(pos, pos + 3))
      newpos2 = pos + 4
    elseif t == 3 or t == 4 then
      local dlen = db_b32le(data:sub(pos, pos + 3))
      value = db_bson_decode(data:sub(pos, pos + dlen - 1))
      newpos2 = pos + dlen
    elseif t == 11 then
      value = nil
      newpos2 = pos
    elseif t == 10 then
      value = db_b32le(data:sub(pos, pos + 3))
      newpos2 = pos + 4
    else
      local skip = 0
      if t == 17 or t == 18 then
        skip = 8
      elseif t == 5 then
        local blen = db_b32le(data:sub(pos + 1, pos + 4))
        skip = 1 + 4 + blen
      elseif t == 12 then
        local endpos = string.find(data, "\0\0", pos, true)
        if endpos then
          skip = endpos - pos + 1
        end
      end
      if skip > 0 then
        newpos2 = pos + skip
      else
        break
      end
    end
    doc[name] = value
    pos = newpos2
  end
  return doc
end

local function db_opmsg(doc)
  local body = db_u8(0) .. db_u8(0) .. db_bson_encode(doc)
  local len = 16 + #body
  return db_u32(len) .. db_u32(1) .. db_u32(0) .. db_u32(2013) .. body
end

local function db_parse_mongo_reply(data)
  if #data < 16 then
    return nil, "short"
  end
  local len = db_b32(data:sub(1, 4))
  local opcode = db_b32(data:sub(13, 16))
  if len < 16 or len > #data then
    return nil, "bad length"
  end
  if opcode == 1 then
    local err = db_bson_decode(data:sub(17, 16 + len))
    if err then
      return nil, string.format("reply: code=%s err=%s",
        tostring(err.code), tostring(err.errmsg))
    end
    return nil, "reply error"
  end
  if opcode == 2013 then
    local body = data:sub(17, 16 + len)
    if #body < 2 then
      return nil, "bad op_msg"
    end
    local section = body:sub(2)
    local doc = db_bson_decode(section:sub(2))
    return doc, nil
  end
  return nil, ("opcode %d"):tostring(opcode)
end

local CASS_OPCODES = {
  [0] = "ERROR",
  [1] = "STARTUP",
  [2] = "READY",
  [3] = "AUTHENTICATE",
  [4] = "RESULT",
  [5] = "OPTIONS",
  [6] = "SUPPORTED",
  [7] = "QUERY",
  [8] = "EXECUTE",
  [9] = "PREPARE",
  [13] = "BATCH",
  [14] = "EVENT",
}

local CASS_ERRORS = {
  [0x0000] = "SERVER_ERROR",
  [0x0001] = "PROTOCOL_ERROR",
  [0x0002] = "BAD_CREDENTIALS",
  [0x0003] = "UNAVAILABLE",
  [0x0004] = "OVERLOADED",
  [0x0005] = "IS_BOOTSTRAPPING",
  [0x0006] = "TRUNCATED",
  [0x0007] = "CONFIG_ERROR",
  [0x1000] = "ALREADY_EXISTS",
  [0x1001] = "UNPREPARED",
}

local function db_cass_frame(version, flags, stream, opcode, body)
  if version >= 4 then
    return db_u8(version) .. db_u8(flags) .. db_u16(stream) .. db_u8(opcode)
      .. db_u32(#body) .. body
  end
  return db_u8(version) .. db_u8(flags) .. db_u16(stream) .. db_u8(opcode)
    .. db_u16(#body) .. body
end

local function db_cass_str(value)
  local s = tostring(value)
  return db_u16(#s) .. s
end

local function db_cass_startup_frame(cql_version, compression)
  local map = ""
  local n = 0
  map = map .. db_cass_str("CQL_VERSION") .. db_cass_str(cql_version)
  n = n + 1
  if compression ~= nil then
    map = map .. db_cass_str("COMPRESSION") .. db_cass_str(compression)
    n = n + 1
  end
  local body = db_u16(n) .. map
  return db_cass_frame(4, 0, 0, 1, body)
end

local function db_cass_query_frame(query, stream)
  local q = tostring(query)
  local body = db_u8(0) .. db_u16(#q) .. q .. db_u16(0) .. db_u16(0)
  return db_cass_frame(4, 0, stream or 1, 7, body)
end

local function db_cass_read_str(body, p)
  if p + 1 > #body then
    return nil, p
  end
  local slen = db_b16(body:sub(p, p + 1))
  local s = body:sub(p + 2, p + 1 + slen)
  return s, p + 2 + slen
end

local function db_parse_cass_frame(data)
  if #data < 8 then
    return nil
  end
  local version = data:byte(1) % 16
  local flags = data:byte(2)
  local stream = db_b16(data:sub(3, 4))
  local opcode = data:byte(5)
  local len
  local body
  if version >= 4 then
    if #data < 9 then
      return nil
    end
    len = db_b32(data:sub(6, 9))
    body = data:sub(10, 9 + len)
  else
    len = db_b16(data:sub(6, 7))
    body = data:sub(8, 7 + len)
  end
  local frame = {
    version = version,
    flags = flags,
    stream = stream,
    opcode = opcode,
    opcode_name = CASS_OPCODES[opcode] or ("0x" .. string.format("%02x", opcode)),
    body = body,
  }
  if opcode == 0 then
    if #body >= 4 then
      local code = db_b32(body:sub(1, 4))
      frame.error_code = code
      frame.error_name = CASS_ERRORS[code] or ("0x" .. string.format("%04x", code))
      local p = 5
      local msg, newp = db_cass_read_str(body, p)
      frame.error_message = msg
      p = newp
      if p + 1 <= #body then
        local numinfo = db_b16(body:sub(p, p + 1))
        p = p + 2
        frame.error_info = {}
        for _ = 1, numinfo do
          local k, p2 = db_cass_read_str(body, p)
          if k == nil then break end
          local v, p3 = db_cass_read_str(body, p2)
          if v == nil then break end
          frame.error_info[#frame.error_info + 1] = { k = k, v = v }
          p = p3
        end
      end
    end
  end
  if opcode == 3 and #body >= 2 then
    local alen = db_b16(body:sub(1, 2))
    frame.authenticator = body:sub(3, 2 + alen)
  end
  if opcode == 4 then
    frame.result_kind = body:byte(1)
    if frame.result_kind == 1 and #body >= 5 then
      local rows = {}
      local meta_len = db_b24(body:sub(2, 4))
      local p = 5 + meta_len
      if p + 1 <= #body then
        local count = db_b16(body:sub(p, p + 1))
        p = p + 2
        for i = 1, count do
          if p + 3 > #body then
            break
          end
          local vlen = db_b32(body:sub(p, p + 3))
          p = p + 4
          if vlen >= 0 then
            rows[i] = body:sub(p, p + vlen - 1)
            p = p + vlen
          end
        end
      end
      frame.rows = rows
    end
  end
  return frame
end

local TDS_PRELOGIN_VERSION = 0
local TDS_PRELOGIN_ENCRYPTION = 1
local TDS_PRELOGIN_INSTOPT = 2
local TDS_PRELOGIN_THREADID = 3
local TDS_PRELOGIN_LANGUAGE = 4
local TDS_PRELOGIN_DATABASE = 5

local TDS_ENCRYPTION = {
  [0] = "ENCRYPT_OFF",
  [1] = "ENCRYPT_ON",
  [2] = "ENCRYPT_NOT_SUP",
  [3] = "ENCRYPT_REQ",
}

local function db_tds_prelogin(opts)
  opts = opts or {}
  local version = opts.version or { 15, 0, 4332, 0 }
  local version_bytes = db_u8(version[1]) .. db_u8(version[2])
    .. db_u8(math.floor(version[3] / 256) % 256) .. db_u8(version[3] % 256)
    .. db_u8(version[4] or 0)
  local parts = {}
  local part_version = db_u8(0) .. db_u16(#version_bytes) .. version_bytes
  local part_encryption = db_u8(1) .. db_u16(1) .. db_u8(opts.encryption or 0)
  parts[#parts + 1] = part_version
  parts[#parts + 1] = part_encryption
  local terminator = db_u8(255) .. db_u16(0)
  local body = table.concat(parts) .. terminator
  local header = db_u8(0x12) .. db_u8(1)
  header = header .. db_u16(8 + #body)
  header = header .. db_u16(0)
  header = header .. db_u16(1)
  header = header .. db_u16(0)
  return header .. body
end

local function db_parse_tds_packet(data)
  if #data < 8 then
    return nil
  end
  local info = {
    type = data:byte(1),
    status = data:byte(2),
    length = db_b16(data:sub(3, 4)),
    spid = db_b16(data:sub(5, 6)),
    packet_id = db_b16(data:sub(7, 8)),
    window = 0,
  }
  if #data >= 10 then
    info.window = db_b16(data:sub(9, 10))
  end
  info.body = data:sub(11, 8 + info.length)
  return info
end

local function db_parse_tds_prelogin(body)
  local info = {}
  local pos = 1
  while pos + 2 <= #body do
    local id = body:byte(pos)
    if id == 255 then
      break
    end
    local length = db_b16(body:sub(pos + 1, pos + 2))
    local value = body:sub(pos + 3, pos + 2 + length)
    pos = pos + 3 + length
    if id == TDS_PRELOGIN_VERSION and #value >= 5 then
      local build = value:byte(3) * 256 + value:byte(4)
      info.version = string.format("%d.%d.%d.%d",
        value:byte(1), value:byte(2), build, value:byte(5))
      info.version_bytes = value
    end
    if id == TDS_PRELOGIN_ENCRYPTION and #value >= 1 then
      info.encryption = value:byte(1)
      info.encryption_name = TDS_ENCRYPTION[value:byte(1)] or ("0x" .. string.format("%02x", value:byte(1)))
    end
    if id == TDS_PRELOGIN_INSTOPT and #value > 0 then
      info.instance = value:sub(2)
    end
    if id == TDS_PRELOGIN_THREADID and #value >= 4 then
      info.thread_id = db_b32(value)
    end
    if id == TDS_PRELOGIN_LANGUAGE and #value > 0 then
      info.language = value:match("([^%z]*)")
    end
    if id == TDS_PRELOGIN_DATABASE and #value > 0 then
      info.database = value:match("([^%z]*)")
    end
  end
  return info
end

local function db_connect(host, port, timeout)
  local sock, err = nmap.new_socket("tcp")
  if sock == nil then
    return nil, "no socket: " .. tostring(err)
  end
  sock:set_timeout(timeout or 10)
  local ok, cerr = sock:connect(host.ip, port)
  if not ok then
    return nil, cerr or "connect failed"
  end
  return sock, nil
end

local function db_read_exact(sock, n)
  local parts = {}
  local got = 0
  while got < n do
    local ok, chunk, rerr = sock:receive_bytes(n - got)
    if not ok or chunk == nil or #chunk == 0 then
      return table.concat(parts), rerr or "timeout"
    end
    parts[#parts + 1] = chunk
    got = got + #chunk
  end
  return table.concat(parts), nil
end

local function db_read_chunk(sock, maxbytes)
  local ok, chunk, err = sock:receive_bytes(maxbytes or 65536)
  if not ok or chunk == nil or #chunk == 0 then
    return nil, err or "timeout"
  end
  return chunk, nil
end

local function db_close(result)
  if result ~= nil and result.sock ~= nil then
    pcall(result.sock.close, result.sock)
  end
  return result
end

local function db_redis_roundtrip(sock, parts)
  local req = db_resp_command(parts)
  local ok, serr = sock:send(req)
  if not ok then
    return nil, serr
  end
  local data = nil
  local rerr = nil
  for _ = 1, 20 do
    local chunk, cerr = db_read_chunk(sock, 8192)
    if chunk == nil then
      rerr = cerr
      break
    end
    if data == nil then
      data = chunk
    else
      data = data .. chunk
    end
    local kind, value, perr = db_parse_resp(data)
    if kind ~= nil then
      if kind == "error" then
        return "error", value, nil
      end
      return kind, value, nil
    end
  end
  return nil, rerr or "timeout", nil
end

local function db_redis_ping(sock)
  return db_redis_roundtrip(sock, { "PING" })
end

local function db_redis_info(sock)
  local kind, value, err = db_redis_roundtrip(sock, { "INFO" })
  if kind == "error" then
    return nil, value
  end
  if kind ~= "bulk" and kind ~= "string" then
    return nil, err or ("unexpected reply " .. tostring(kind))
  end
  local fields = {}
  local sections = {}
  for line in string.gmatch(tostring(value), "([^\r\n]+)\r?\n") do
    if line == "" then
    elseif line:sub(1, 1) == "#" then
      local sec = line:sub(2):match("^%s*(.-)%s*$")
      sections[#sections + 1] = sec
    else
      local k, v = string.match(line, "^([^=:]+):(.*)$")
      if k then
        fields[k] = v
      end
    end
  end
  fields._sections = sections
  return fields, nil
end

local function db_redis_command_info(sock, names)
  local parts = { "COMMAND", "INFO" }
  for _, n in ipairs(names) do
    parts[#parts + 1] = n
  end
  local kind, value, err = db_redis_roundtrip(sock, parts)
  if kind == "error" then
    return nil, value
  end
  if kind ~= "array" then
    return nil, err or ("unexpected reply " .. tostring(kind))
  end
  local found = {}
  for _, entry in ipairs(value) do
    if type(entry) == "table" and entry[1] ~= nil then
      found[string.lower(tostring(entry[1]))] = true
    end
  end
  return found, nil
end

local function db_redis_set_get_probe(sock, key)
  local kind, v1 = db_redis_roundtrip(sock, { "SET", key, "nse-audit-probe" })
  if kind == "error" then
    return nil, v1
  end
  local k2, v2, e2 = db_redis_roundtrip(sock, { "GET", key })
  if k2 == "error" then
    return nil, v2
  end
  local k3, v3 = db_redis_roundtrip(sock, { "DEL", key })
  return {
    set_ok = (kind == "string" and v1 == "OK"),
    got_back = v2,
    deleted = (k3 == "integer") and v3 or nil,
  }, nil
end

local function db_memcached_command(sock, line)
  local ok, serr = sock:send(tostring(line) .. "\r\n")
  if not ok then
    return nil, serr
  end
  local data = nil
  for _ = 1, 30 do
    local chunk, cerr = db_read_chunk(sock, 16384)
    if chunk == nil then
      return nil, cerr
    end
    if data == nil then
      data = chunk
    else
      data = data .. chunk
    end
    if string.find(data, "END\r\n", 1, true) then
      break
    end
    if string.find(data, "VERSION ", 1, true) then
      break
    end
    if string.find(data, "ERROR", 1, true) then
      break
    end
  end
  return data, nil
end

local function db_memcached_stats(sock)
  local raw, err = db_memcached_command(sock, "stats")
  if raw == nil then
    return nil, err
  end
  local stats = {}
  for line in string.gmatch(raw, "([^\r\n]+)\r?\n") do
    local k, v = string.match(line, "^STAT%s+(%S+)%s+(%S+)$")
    if k then
      stats[k] = tonumber(v) or v
    end
  end
  return stats, nil
end

local function db_memcached_version(sock)
  local raw, err = db_memcached_command(sock, "version")
  if raw == nil then
    return nil, err
  end
  return string.match(raw, "^VERSION%s+(%S+)"), nil
end

local function db_mysql_read_packet(sock)
  local header, herr = db_read_exact(sock, 4)
  if #header < 4 then
    return nil, herr or "short header"
  end
  local len = db_b24(header)
  local seq = header:byte(4)
  local payload, perr = db_read_exact(sock, len)
  if #payload < len then
    return nil, perr or "short payload"
  end
  return { length = len, seq = seq, payload = payload }, nil
end

local function db_mysql_handshake(sock)
  local packet, err = db_mysql_read_packet(sock)
  if packet == nil then
    return nil, err
  end
  local info = db_parse_mysql_handshake(packet.payload)
  if info == nil then
    return nil, "unparseable handshake"
  end
  info.raw = packet.payload
  return info, nil
end

local function db_mysql_login(sock, handshake, user, password)
  local response = db_mysql_handshake_response41(user, tostring(password or ""),
    handshake.plugin or "mysql_native_password", nil)
  local pkt = db_mysql_packet(response, 1)
  local ok, serr = sock:send(pkt)
  if not ok then
    return nil, serr
  end
  local reply, rerr = db_mysql_read_packet(sock)
  if reply == nil then
    return nil, rerr
  end
  return db_parse_mysql_response(reply.payload), nil
end

local function db_pg_roundtrip(sock, bytes)
  local ok, serr = sock:send(bytes)
  if not ok then
    return nil, serr
  end
  local data, rerr = db_read_chunk(sock, 8192)
  if data == nil then
    return nil, rerr
  end
  return db_parse_pg_message(data), nil
end

local function db_pg_ssl_check(sock)
  return db_pg_roundtrip(sock, db_pg_ssl_request())
end

local function db_pg_startup_check(sock, user, database)
  return db_pg_roundtrip(sock, db_pg_startup(user, database))
end

local function db_mongo_command(sock, doc)
  local ok, serr = sock:send(db_opmsg(doc))
  if not ok then
    return nil, serr
  end
  local header, herr = db_read_exact(sock, 16)
  if #header < 16 then
    return nil, herr or "short header"
  end
  local len = db_b32(header:sub(1, 4))
  if len < 16 then
    return nil, "bad length"
  end
  local rest, rerr = db_read_exact(sock, len - 16)
  if #rest < len - 16 then
    return nil, rerr or "short message"
  end
  return db_parse_mongo_reply(header .. rest)
end

local function db_mongo_hello(sock)
  local doc, err = db_mongo_command(sock, {
    hello = 1,
    ["$db"] = "admin",
  })
  return doc, err
end

local function db_mongo_ping(sock)
  local doc, err = db_mongo_command(sock, {
    ping = 1,
    ["$db"] = "admin",
  })
  return doc, err
end

local function db_cass_roundtrip(sock, frame)
  local ok, serr = sock:send(frame)
  if not ok then
    return nil, serr
  end
  local header, herr = db_read_exact(sock, 9)
  if #header < 9 then
    return nil, herr or "short header"
  end
  local len = db_b32(header:sub(6, 9))
  local body, berr = db_read_exact(sock, len)
  if #body < len then
    return nil, berr or "short body"
  end
  return db_parse_cass_frame(header .. body), nil
end

local function db_cass_startup(sock, cql_version)
  return db_cass_roundtrip(sock, db_cass_startup_frame(cql_version or "3.4.5", nil))
end

local function db_cass_query(sock, query, stream)
  return db_cass_roundtrip(sock, db_cass_query_frame(query, stream or 1))
end

local function db_mssql_prelogin(sock)
  local ok, serr = sock:send(db_tds_prelogin({ encryption = 0 }))
  if not ok then
    return nil, serr
  end
  local data, rerr = db_read_chunk(sock, 4096)
  if data == nil then
    return nil, rerr
  end
  local packet = db_parse_tds_packet(data)
  if packet == nil then
    return nil, "unparseable TDS packet"
  end
  local info = db_parse_tds_prelogin(packet.body)
  info.packet = packet
  return info, nil
end

local function db_parse_http_response(raw)
  local head, body = string.match(raw or "", "^(.-)\r\n\r\n(.*)$")
  if not head then
    head, body = string.match(raw or "", "^(.-)\n\n(.*)$")
  end
  if not head then
    return { status = 0, header = {}, body = raw or "", raw = raw or "" }
  end
  local response = { header = {}, body = body, raw = raw }
  local first = true
  for line in string.gmatch(head, "([^\r\n]*)") do
    if first then
      response["status-line"] = line
      response.status = tonumber(string.match(line, "^HTTP/[%d%.]+%s+(%d+)")) or 0
      first = false
    elseif #line > 2 then
      local name, value = string.match(line, "^([^:]+):%s*(.*)$")
      if name then
        response.header[string.lower(name)] = value
      end
    end
  end
  return response
end

local function db_http_exchange(sock, method, path, host, extra_headers, body)
  local req = tostring(method) .. " " .. path .. " HTTP/1.1\r\n"
  req = req .. "Host: " .. tostring(host) .. "\r\n"
  req = req .. "User-Agent: nmap-nse-audit/1.0\r\n"
  req = req .. "Accept: */*\r\n"
  if extra_headers ~= nil then
    for _, h in ipairs(extra_headers) do
      req = req .. h .. "\r\n"
    end
  end
  if body ~= nil then
    req = req .. "Content-Length: " .. #tostring(body) .. "\r\n"
  end
  req = req .. "Connection: close\r\n\r\n" .. tostring(body or "")
  local ok, serr = sock:send(req)
  if not ok then
    return nil, serr
  end
  local data = ""
  for _ = 1, 64 do
    local chunk, cerr = db_read_chunk(sock, 16384)
    if chunk == nil then
      if data == "" then
        return nil, cerr
      end
      break
    end
    data = data .. chunk
    if string.find(data, "\r\n\r\n", 1, true) then
      break
    end
  end
  return db_parse_http_response(data), nil
end

local function db_http_get(host, port, path, args)
  local sock, cerr = db_connect(host, port, args and args.timeout)
  if sock == nil then
    return nil, cerr
  end
  local name = host.name or host.ip or "target"
  local resp, rerr = db_http_exchange(sock, "GET", path, name, nil, nil)
  pcall(sock.close, sock)
  return resp, rerr
end

local function db_http_post(host, port, path, body, content_type, args)
  local sock, cerr = db_connect(host, port, args and args.timeout)
  if sock == nil then
    return nil, cerr
  end
  local name = host.name or host.ip or "target"
  local headers = { "Content-Type: " .. (content_type or "application/octet-stream") }
  local resp, rerr = db_http_exchange(sock, "POST", path, name, headers, body)
  pcall(sock.close, sock)
  return resp, rerr
end

local function db_classify_pg_auth(msg)
  if msg == nil then
    return "unknown"
  end
  if msg.kind == "ssl_supported" then
    return "ssl_supported"
  end
  if msg.kind == "ssl_rejected" then
    return "ssl_rejected"
  end
  if msg.kind == "auth" then
    if msg.code == 0 then
      return "trust"
    end
    if msg.code == 3 then
      return "cleartext"
    end
    if msg.code == 5 then
      return "md5"
    end
    if msg.code == 9 or msg.code == 12 then
      return "sasl"
    end
    return "auth_code_" .. tostring(msg.code)
  end
  if msg.kind == "error" then
    return "error"
  end
  return "unknown"
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

local function classify_reply(msg)
  if msg == nil then
    return "no_response", nil
  end
  if msg.kind == "ssl_supported" then
    return "offered", 83
  end
  if msg.kind == "ssl_rejected" then
    return "refused", 78
  end
  if msg.kind == "auth" then
    return "auth_first", nil
  end
  if msg.kind == "error" then
    return "error", nil
  end
  return "unknown", nil
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local out = new_output(RISK_LEVEL, "AUDITED - PostgreSQL SSLRequest probed for TLS offer.")
  local sections = {}
  local notes = {}
  local port_number = port and (port.number or port.port) or 5432

  local sock, cerr = db_connect(host, port_number, args.timeout)
  if sock == nil then
    add_finding("INFO",
      "could not open a connection to the PostgreSQL port: " .. tostring(cerr),
      { subject = "conn-failed", evidence = tostring(cerr) })
    table.insert(sections, { key = "probe_notes", value = notes })
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end

  state.requests = state.requests + 1
  local msg, merr = db_pg_ssl_check(sock)
  pcall(sock.close, sock)

  local cls, raw = classify_reply(msg)
  table.insert(sections, { key = "sslreply_class", value = cls })
  if raw ~= nil then
    table.insert(sections, { key = "raw_reply_byte", value = string.format("0x%02x", raw) })
  end

  if cls == "offered" then
    add_finding("INFO",
      "PostgreSQL answered the SSLRequest with 'S': a TLS channel can be negotiated; the real exposure now depends on client sslmode policy and certificate trust",
      { subject = "ssl-offered", evidence = "SSLRequest -> 'S' (0x53)" })
    table.insert(sections, { key = "context", value = PG_SSL_CONTEXT.offered })
    table.insert(sections, { key = "recommended_action", value = "issue server certificates, enable ssl=on, and pin clients to sslmode=verify-ca/verify-full with a trusted root; pair this check with the trust-auth script to confirm the credential path." })
  elseif cls == "refused" then
    add_finding("MEDIUM",
      "PostgreSQL answered the SSLRequest with 'N': the server will not negotiate TLS, so every connection - including the password exchange - is cleartext on the wire",
      { subject = "ssl-refused", evidence = "SSLRequest -> 'N' (0x4e)" })
    table.insert(sections, { key = "context", value = PG_SSL_CONTEXT.refused })
    table.insert(sections, { key = "recommended_action", value = "generate server certificates (openssl or the CA of choice), set ssl=on in postgresql.conf, and restart; verify with psql 'SHOW ssl' and re-run this script." })
  elseif cls == "auth_first" then
    add_finding("INFO",
      "the server replied with an authentication message instead of an SSL reply; the TLS posture should be re-checked on the primary protocol path",
      { subject = "unexpected-auth", evidence = "SSLRequest -> AuthenticationRequest", confidence = "medium" })
  elseif cls == "error" then
    add_finding("INFO",
      "the server returned an error to the SSLRequest; the TLS offer could not be determined",
      { subject = "ssl-error", evidence = "SSLRequest -> ErrorResponse", confidence = "medium" })
  else
    add_finding("INFO",
      "no usable reply was received to the SSLRequest (" .. tostring(merr) .. "); the port may not be PostgreSQL",
      { subject = "ssl-no-reply", evidence = tostring(merr), confidence = "low" })
  end

  table.insert(sections, { key = "probe_notes", value = notes })
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)

end
